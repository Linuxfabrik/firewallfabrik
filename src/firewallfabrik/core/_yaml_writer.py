# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""YAML writer for serializing the database object graph to a single YAML file."""

import logging
import os
import pathlib

import sqlalchemy
import yaml

from . import objects
from ._util import ENUM_FIELDS, escape_obj_name
from .options._metadata import HOST_OPTIONS, INTERFACE_OPTIONS, RULE_OPTIONS

logger = logging.getLogger(__name__)


class _QuotedValueDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _quoted_str(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")


_QuotedValueDumper.add_representer(str, _quoted_str)

_orig_represent_mapping = yaml.SafeDumper.represent_mapping


def _represent_mapping(self, tag, mapping, flow_style=None):
    node = _orig_represent_mapping(self, tag, mapping, flow_style)
    for key_node, _ in node.value:
        if key_node.tag == 'tag:yaml.org,2002:str':
            key_node.style = None
    return node


_QuotedValueDumper.represent_mapping = _represent_mapping

# Fields to always skip when serializing (FK columns, internal fields).
_SKIP_ALWAYS = frozenset(
    {
        'id',
        'library_id',
        'group_id',
        'interface_id',
        'device_id',
        'rule_set_id',
        'parent_group_id',
        'parent_interface_id',
        'database_id',
    }
)


def _is_default(value):
    """Return True if value is a default that should be omitted."""
    if value is None:
        return True
    if isinstance(value, str) and value == '':
        return True
    if isinstance(value, bool) and value is False:
        return True
    if isinstance(value, int | float) and not isinstance(value, bool) and value == 0:
        return True
    if isinstance(value, dict) and not value:
        return True
    return bool(isinstance(value, set | list) and not value)


def _serialize_obj(obj, extra_skip=frozenset(), skip_opt_columns=False):
    """Serialize an ORM object to a dict, omitting defaults and skipped fields.

    Handles enum remapping and set→sorted list conversion.
    If skip_opt_columns is True, skips all opt_* columns (they are serialized
    separately as an options dict).
    """
    skip = _SKIP_ALWAYS | extra_skip
    result = {}
    mapper = sqlalchemy.inspect(type(obj))

    for col in mapper.columns:
        key = col.key
        if key in skip:
            continue

        # Skip opt_* columns when requested
        if skip_opt_columns and key.startswith('opt_'):
            continue

        value = getattr(obj, key)

        # Enum remapping
        if key in ENUM_FIELDS:
            yaml_key, enum_cls = ENUM_FIELDS[key]
            if value is not None:
                try:
                    result[yaml_key] = enum_cls(value).name
                except ValueError:
                    result[yaml_key] = value
            continue

        if _is_default(value):
            continue

        # set -> sorted list
        if isinstance(value, set):
            result[key] = sorted(value)
        else:
            result[key] = value

    return result


class YamlWriter:
    """Serializes the database object graph to a single YAML file."""

    def __init__(self):
        self._ref_index = {}

    def write(self, session, database_id, output_path):
        output_path = pathlib.Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        db = session.get(objects.FWObjectDatabase, database_id)
        if db is None:
            raise ValueError(f'Database {database_id} not found')

        libraries = session.scalars(
            sqlalchemy.select(objects.Library).where(
                objects.Library.database_id == database_id
            ),
        ).all()

        # Build the global ref-path index via tree walk
        self._build_ref_index(session, libraries)

        # Build a single combined document
        doc = self._serialize_database(db)
        doc['libraries'] = sorted(
            [self._serialize_library(session, lib) for lib in libraries],
            key=lambda lib: lib['name'],
        )
        self._write_yaml(output_path, doc)

    def _build_ref_index(self, session, libraries):
        """Build UUID -> full tree-path mapping for all objects."""
        self._ref_index = {}
        seen_paths = {}

        for lib in libraries:
            lib_path = f'Library:{escape_obj_name(lib.name)}'

            # Orphan addresses (group_id IS NULL)
            for addr in session.scalars(
                sqlalchemy.select(objects.Address).where(
                    objects.Address.library_id == lib.id,
                    objects.Address.group_id.is_(None),
                ),
            ).all():
                self._register_ref(
                    seen_paths,
                    f'{lib_path}/{addr.type}:{escape_obj_name(addr.name)}',
                    addr.id,
                )

            # Orphan services
            for svc in session.scalars(
                sqlalchemy.select(objects.Service).where(
                    objects.Service.library_id == lib.id,
                    objects.Service.group_id.is_(None),
                ),
            ).all():
                self._register_ref(
                    seen_paths,
                    f'{lib_path}/{svc.type}:{escape_obj_name(svc.name)}',
                    svc.id,
                )

            # Orphan intervals
            for itv in session.scalars(
                sqlalchemy.select(objects.Interval).where(
                    objects.Interval.library_id == lib.id,
                    objects.Interval.group_id.is_(None),
                ),
            ).all():
                self._register_ref(
                    seen_paths,
                    f'{lib_path}/Interval:{escape_obj_name(itv.name)}',
                    itv.id,
                )

            # Root groups
            for grp in session.scalars(
                sqlalchemy.select(objects.Group).where(
                    objects.Group.library_id == lib.id,
                    objects.Group.parent_group_id.is_(None),
                ),
            ).all():
                self._walk_group(session, seen_paths, grp, lib_path)

            # Orphan devices
            for dev in session.scalars(
                sqlalchemy.select(objects.Host).where(
                    objects.Host.library_id == lib.id,
                    objects.Host.group_id.is_(None),
                ),
            ).all():
                self._walk_device(session, seen_paths, dev, lib_path)

            # Standalone interfaces (no device)
            for iface in session.scalars(
                sqlalchemy.select(objects.Interface).where(
                    objects.Interface.library_id == lib.id,
                    objects.Interface.device_id.is_(None),
                ),
            ).all():
                self._walk_interface(seen_paths, iface, lib_path)

    def _walk_group(self, session, seen_paths, grp, parent_path):
        """Walk a group and its children, registering ref-paths."""
        grp_path = f'{parent_path}/{grp.type}:{escape_obj_name(grp.name)}'
        self._register_ref(seen_paths, grp_path, grp.id)

        # Child addresses
        for addr in session.scalars(
            sqlalchemy.select(objects.Address).where(
                objects.Address.group_id == grp.id,
            ),
        ).all():
            self._register_ref(
                seen_paths,
                f'{grp_path}/{addr.type}:{escape_obj_name(addr.name)}',
                addr.id,
            )

        # Child services
        for svc in session.scalars(
            sqlalchemy.select(objects.Service).where(
                objects.Service.group_id == grp.id,
            ),
        ).all():
            self._register_ref(
                seen_paths,
                f'{grp_path}/{svc.type}:{escape_obj_name(svc.name)}',
                svc.id,
            )

        # Child intervals
        for itv in session.scalars(
            sqlalchemy.select(objects.Interval).where(
                objects.Interval.group_id == grp.id,
            ),
        ).all():
            self._register_ref(
                seen_paths,
                f'{grp_path}/Interval:{escape_obj_name(itv.name)}',
                itv.id,
            )

        # Child devices
        for dev in session.scalars(
            sqlalchemy.select(objects.Host).where(
                objects.Host.group_id == grp.id,
            ),
        ).all():
            self._walk_device(session, seen_paths, dev, grp_path)

        # Child groups
        for child in session.scalars(
            sqlalchemy.select(objects.Group).where(
                objects.Group.parent_group_id == grp.id,
            ),
        ).all():
            self._walk_group(session, seen_paths, child, grp_path)

    def _walk_device(self, session, seen_paths, dev, parent_path):
        """Walk a device and its interfaces, registering ref-paths."""
        dev_path = f'{parent_path}/{dev.type}:{escape_obj_name(dev.name)}'
        self._register_ref(seen_paths, dev_path, dev.id)

        top_ifaces = [i for i in dev.interfaces if i.parent_interface_id is None]
        for iface in sorted(top_ifaces, key=lambda i: i.name):
            self._walk_interface(seen_paths, iface, dev_path)

    def _walk_interface(self, seen_paths, iface, parent_path):
        """Walk an interface and its sub-interfaces, registering ref-paths."""
        iface_path = f'{parent_path}/Interface:{escape_obj_name(iface.name)}'
        self._register_ref(seen_paths, iface_path, iface.id)
        for addr in sorted(iface.addresses, key=lambda a: a.name):
            self._register_ref(
                seen_paths,
                f'{iface_path}/{addr.type}:{escape_obj_name(addr.name)}',
                addr.id,
            )
        for sub in sorted(iface.sub_interfaces, key=lambda i: i.name):
            self._walk_interface(seen_paths, sub, iface_path)

    def _register_ref(self, seen_paths, path, obj_id):
        """Register a full tree-path -> UUID mapping, with #N fallback for collisions."""
        if path not in seen_paths:
            seen_paths[path] = obj_id
            self._ref_index[obj_id] = path
        else:
            n = 2
            while f'{path}#{n}' in seen_paths:
                n += 1
            if n == 2:
                first_id = seen_paths[path]
                self._ref_index[first_id] = f'{path}#1'
                seen_paths[f'{path}#1'] = first_id
            seen_paths[f'{path}#{n}'] = obj_id
            self._ref_index[obj_id] = f'{path}#{n}'

    def _ref_path(self, target_id):
        """Resolve a UUID to a full tree-path ref string."""
        ref = self._ref_index.get(target_id)
        if ref is None:
            logger.warning('No ref-path for UUID %s', target_id)
            return str(target_id)
        return ref

    def _serialize_database(self, db):
        d = {}
        if db.name:
            d['name'] = db.name
        if db.comment:
            d['comment'] = db.comment
        if db.last_modified:
            d['last_modified'] = db.last_modified
        if db.data_file:
            d['data_file'] = db.data_file
        if db.predictable_id_tracker:
            d['predictable_id_tracker'] = db.predictable_id_tracker
        if db.data:
            d['data'] = db.data
        return d

    def _serialize_library(self, session, lib):
        d = {'name': lib.name}
        if lib.comment:
            d['comment'] = lib.comment
        if lib.ro:
            d['ro'] = True
        if lib.data:
            d['data'] = lib.data

        children = []

        # Orphan addresses (group_id IS NULL)
        for a in session.scalars(
            sqlalchemy.select(objects.Address).where(
                objects.Address.library_id == lib.id,
                objects.Address.group_id.is_(None),
            ),
        ).all():
            children.append(self._serialize_address(a))

        # Orphan services
        for s in session.scalars(
            sqlalchemy.select(objects.Service).where(
                objects.Service.library_id == lib.id,
                objects.Service.group_id.is_(None),
            ),
        ).all():
            children.append(_serialize_obj(s))

        # Orphan intervals (Interval has no STI type column)
        for i in session.scalars(
            sqlalchemy.select(objects.Interval).where(
                objects.Interval.library_id == lib.id,
                objects.Interval.group_id.is_(None),
            ),
        ).all():
            d_itv = _serialize_obj(i)
            d_itv.setdefault('type', 'Interval')
            children.append(d_itv)

        # Root groups
        for g in session.scalars(
            sqlalchemy.select(objects.Group).where(
                objects.Group.library_id == lib.id,
                objects.Group.parent_group_id.is_(None),
            ),
        ).all():
            children.append(self._serialize_group(session, g))

        # Orphan devices
        for dev in session.scalars(
            sqlalchemy.select(objects.Host).where(
                objects.Host.library_id == lib.id,
                objects.Host.group_id.is_(None),
            ),
        ).all():
            children.append(self._serialize_device(session, dev))

        # Standalone interfaces (no device)
        for iface in session.scalars(
            sqlalchemy.select(objects.Interface).where(
                objects.Interface.library_id == lib.id,
                objects.Interface.device_id.is_(None),
            ),
        ).all():
            d_iface = self._serialize_interface(iface)
            d_iface.setdefault('type', 'Interface')
            children.append(d_iface)

        if children:
            d['children'] = sorted(children, key=lambda c: c.get('name', ''))

        return d

    def _serialize_address(self, addr):
        return _serialize_obj(addr)

    def _serialize_group(self, session, grp):
        d = _serialize_obj(grp, extra_skip=frozenset({'ro'}))
        if grp.ro:
            d['ro'] = True

        children = []

        # Child addresses
        for a in session.scalars(
            sqlalchemy.select(objects.Address).where(
                objects.Address.group_id == grp.id,
            ),
        ).all():
            children.append(self._serialize_address(a))

        # Child services
        for s in session.scalars(
            sqlalchemy.select(objects.Service).where(
                objects.Service.group_id == grp.id,
            ),
        ).all():
            children.append(_serialize_obj(s))

        # Child intervals (Interval has no STI type column)
        for i in session.scalars(
            sqlalchemy.select(objects.Interval).where(
                objects.Interval.group_id == grp.id,
            ),
        ).all():
            d_itv = _serialize_obj(i)
            d_itv.setdefault('type', 'Interval')
            children.append(d_itv)

        # Child devices
        for dev in session.scalars(
            sqlalchemy.select(objects.Host).where(
                objects.Host.group_id == grp.id,
            ),
        ).all():
            children.append(self._serialize_device(session, dev))

        # Child groups
        for child in session.scalars(
            sqlalchemy.select(objects.Group).where(
                objects.Group.parent_group_id == grp.id,
            ),
        ).all():
            children.append(self._serialize_group(session, child))

        if children:
            d['children'] = sorted(children, key=lambda c: c.get('name', ''))

        # Members from group_membership (cross-references only)
        rows = session.execute(
            sqlalchemy.select(objects.group_membership.c.member_id).where(
                objects.group_membership.c.group_id == grp.id,
            ),
        ).fetchall()
        if rows:
            d['members'] = sorted(self._ref_path(row[0]) for row in rows)

        return d

    def _serialize_device(self, session, dev):
        d = _serialize_obj(
            dev,
            extra_skip=frozenset({'id_mapping_for_duplicate'}),
            skip_opt_columns=True,
        )
        if dev.ro:
            d['ro'] = True
        if dev.id_mapping_for_duplicate:
            d['id_mapping_for_duplicate'] = dev.id_mapping_for_duplicate

        # Build options dict from typed columns (sorted for stable output)
        # Include value if it differs from the column default (None or otherwise)
        opts = {}
        for _, meta in HOST_OPTIONS.items():
            value = getattr(dev, meta.column_name)
            if value != meta.default:
                opts[meta.yaml_key] = value
        if opts:
            d['options'] = dict(sorted(opts.items()))

        # Interfaces (top-level only; sub-interfaces are nested within)
        top_ifaces = [i for i in dev.interfaces if i.parent_interface_id is None]
        if top_ifaces:
            d['interfaces'] = [
                self._serialize_interface(iface)
                for iface in sorted(top_ifaces, key=lambda i: i.name)
            ]

        # Rule sets
        if dev.rule_sets:
            d['rule_sets'] = [
                self._serialize_ruleset(session, rs)
                for rs in sorted(dev.rule_sets, key=lambda rs: rs.name)
            ]

        return d

    def _serialize_interface(self, iface):
        d = _serialize_obj(iface, skip_opt_columns=True)

        # Build options dict from typed columns (sorted for stable output)
        opts = {}
        for _, meta in INTERFACE_OPTIONS.items():
            value = getattr(iface, meta.column_name)
            if value != meta.default:
                opts[meta.yaml_key] = value
        if opts:
            d['options'] = dict(sorted(opts.items()))

        # Interface addresses
        if iface.addresses:
            d['addresses'] = [
                self._serialize_address(a)
                for a in sorted(iface.addresses, key=lambda a: a.name)
            ]

        # Sub-interfaces
        if iface.sub_interfaces:
            d['interfaces'] = [
                self._serialize_interface(sub)
                for sub in sorted(iface.sub_interfaces, key=lambda i: i.name)
            ]

        return d

    def _serialize_ruleset(self, session, rs):
        d = _serialize_obj(rs)

        # Rules (ordered by position)
        rules = session.scalars(
            sqlalchemy.select(objects.Rule)
            .where(
                objects.Rule.rule_set_id == rs.id,
            )
            .order_by(objects.Rule.position),
        ).all()
        if rules:
            d['rules'] = [self._serialize_rule(session, rule) for rule in rules]

        return d

    def _serialize_rule(self, session, rule):
        d = _serialize_obj(
            rule,
            extra_skip=frozenset({'sorted_dst_ids', 'negations'}),
            skip_opt_columns=True,
        )

        # Build options dict from typed columns (sorted for stable output)
        opts = {}
        for _, meta in RULE_OPTIONS.items():
            value = getattr(rule, meta.column_name)
            if value != meta.default:
                opts[meta.yaml_key] = value
        if opts:
            d['options'] = dict(sorted(opts.items()))

        # Negations — only include slots that are True
        if rule.negations:
            active_negs = {k: v for k, v in rule.negations.items() if v}
            if active_negs:
                d['negations'] = active_negs

        # Rule elements grouped by slot
        rows = session.execute(
            sqlalchemy.select(
                objects.rule_elements.c.slot,
                objects.rule_elements.c.target_id,
            ).where(
                objects.rule_elements.c.rule_id == rule.id,
            ),
        ).fetchall()

        if rows:
            slots = {}
            for slot, target_id in rows:
                ref = self._ref_path(target_id)
                slots.setdefault(slot, []).append(ref)
            for slot in slots:
                slots[slot].sort()
            d.update(slots)

        return d

    @staticmethod
    def _write_yaml(path, data):
        """Write the provided data as YAML atomically to the file."""
        path = pathlib.Path(path)
        tmp_path = path.with_suffix(path.suffix + '.tmp')
        with pathlib.Path.open(tmp_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                data,
                f,
                Dumper=_QuotedValueDumper,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
            f.flush()
            os.fsync(f.fileno())
        tmp_path.replace(path)
