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
import pathlib

import sqlalchemy
import yaml

from . import objects
from ._util import ENUM_FIELDS, escape_obj_name

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


def _serialize_obj(obj, extra_skip=frozenset()):
    """Serialize an ORM object to a dict, omitting defaults and skipped fields.

    Handles enum remapping and set→sorted list conversion.
    """
    skip = _SKIP_ALWAYS | extra_skip
    result = {}
    mapper = sqlalchemy.inspect(type(obj))

    for col in mapper.columns:
        key = col.key
        if key in skip:
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
        self._lib_name_by_id = {}

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

        # Build lib name lookup
        self._lib_name_by_id = {lib.id: lib.name for lib in libraries}

        # Build the global ref-path index
        self._build_ref_index(session, libraries)

        # Build a single combined document
        doc = self._serialize_database(db)
        doc['libraries'] = sorted(
            [self._serialize_library(session, lib) for lib in libraries],
            key=lambda lib: lib['name'],
        )
        self._write_yaml(output_path, doc)

    def _build_ref_index(self, session, libraries):
        """Build UUID -> ref-path mapping for all objects."""
        self._ref_index = {}
        self._uuid_to_lib = {}

        # Track (library_id, type, name) to detect duplicates
        seen = {}

        for lib in libraries:
            lib_id = lib.id
            lib_name = lib.name

            # Addresses (library-level)
            for addr in session.scalars(
                sqlalchemy.select(objects.Address).where(
                    objects.Address.library_id == lib_id
                ),
            ).all():
                self._register_ref(
                    seen, lib_id, lib_name, addr.type, addr.name, addr.id
                )
                self._uuid_to_lib[addr.id] = lib_id

            # Interface addresses
            for iface in session.scalars(
                sqlalchemy.select(objects.Interface)
                .join(objects.Host)
                .where(objects.Host.library_id == lib_id),
            ).all():
                for addr in iface.addresses:
                    self._register_ref(
                        seen, lib_id, lib_name, addr.type, addr.name, addr.id
                    )
                    self._uuid_to_lib[addr.id] = lib_id

            # Services
            for svc in session.scalars(
                sqlalchemy.select(objects.Service).where(
                    objects.Service.library_id == lib_id
                ),
            ).all():
                self._register_ref(seen, lib_id, lib_name, svc.type, svc.name, svc.id)
                self._uuid_to_lib[svc.id] = lib_id

            # Intervals
            for itv in session.scalars(
                sqlalchemy.select(objects.Interval).where(
                    objects.Interval.library_id == lib_id
                ),
            ).all():
                self._register_ref(seen, lib_id, lib_name, 'Interval', itv.name, itv.id)
                self._uuid_to_lib[itv.id] = lib_id

            # Groups (all, including nested)
            for grp in session.scalars(
                sqlalchemy.select(objects.Group).where(
                    objects.Group.library_id == lib_id
                ),
            ).all():
                self._register_ref(seen, lib_id, lib_name, grp.type, grp.name, grp.id)
                self._uuid_to_lib[grp.id] = lib_id

            # Devices
            for dev in session.scalars(
                sqlalchemy.select(objects.Host).where(
                    objects.Host.library_id == lib_id
                ),
            ).all():
                self._register_ref(seen, lib_id, lib_name, dev.type, dev.name, dev.id)
                self._uuid_to_lib[dev.id] = lib_id

            # Interfaces
            for iface in session.scalars(
                sqlalchemy.select(objects.Interface)
                .join(objects.Host)
                .where(objects.Host.library_id == lib_id),
            ).all():
                self._register_ref(
                    seen,
                    lib_id,
                    lib_name,
                    'Interface',
                    iface.name,
                    iface.id,
                )
                self._uuid_to_lib[iface.id] = lib_id

    def _register_ref(self, seen, lib_id, lib_name, type_name, obj_name, obj_id):
        """Register a ref-path for an object, handling duplicates with #N."""
        obj_name_escaped = escape_obj_name(obj_name)
        key = (lib_id, type_name, obj_name_escaped)
        count = seen.get(key, 0)
        seen[key] = count + 1

        if count == 0:
            ref = f'{type_name}/{obj_name_escaped}'
        else:
            ref = f'{type_name}/{obj_name_escaped}#{count + 1}'
            # Rename the first entry when the second occurrence appears
            if count == 1:
                for uid, existing_ref in self._ref_index.items():
                    if existing_ref == f'{type_name}/{obj_name_escaped}':
                        self._ref_index[uid] = f'{type_name}/{obj_name_escaped}#1'
                        break

        self._ref_index[obj_id] = ref

    def _ref_path(self, target_id, context_lib_id):
        """Resolve a UUID to a ref-path string, with a cross-library prefix if needed."""
        ref = self._ref_index.get(target_id)
        if ref is None:
            logger.warning('No ref-path for UUID %s', target_id)
            return str(target_id)

        target_lib = self._uuid_to_lib.get(target_id)
        if target_lib is not None and target_lib != context_lib_id:
            lib_name = self._lib_name_by_id.get(target_lib, '?')
            return f'{lib_name}/{ref}'
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
            children.append(self._serialize_group(session, g, lib.id))

        # Orphan devices
        for dev in session.scalars(
            sqlalchemy.select(objects.Host).where(
                objects.Host.library_id == lib.id,
                objects.Host.group_id.is_(None),
            ),
        ).all():
            children.append(self._serialize_device(session, dev, lib.id))

        if children:
            d['children'] = sorted(children, key=lambda c: c.get('name', ''))

        return d

    def _serialize_address(self, addr):
        return _serialize_obj(addr)

    def _serialize_group(self, session, grp, lib_id):
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
            children.append(self._serialize_device(session, dev, lib_id))

        # Child groups
        for child in session.scalars(
            sqlalchemy.select(objects.Group).where(
                objects.Group.parent_group_id == grp.id,
            ),
        ).all():
            children.append(self._serialize_group(session, child, lib_id))

        if children:
            d['children'] = sorted(children, key=lambda c: c.get('name', ''))

        # Members from group_membership (cross-references only)
        rows = session.execute(
            sqlalchemy.select(objects.group_membership.c.member_id).where(
                objects.group_membership.c.group_id == grp.id,
            ),
        ).fetchall()
        if rows:
            d['members'] = sorted(self._ref_path(row[0], lib_id) for row in rows)

        return d

    def _serialize_device(self, session, dev, lib_id):
        d = _serialize_obj(
            dev,
            extra_skip=frozenset({'id_mapping_for_duplicate'}),
        )
        if dev.ro:
            d['ro'] = True
        if dev.id_mapping_for_duplicate:
            d['id_mapping_for_duplicate'] = dev.id_mapping_for_duplicate

        # Interfaces
        if dev.interfaces:
            d['interfaces'] = [
                self._serialize_interface(session, iface, lib_id)
                for iface in sorted(dev.interfaces, key=lambda i: i.name)
            ]

        # Rule sets
        if dev.rule_sets:
            d['rule_sets'] = [
                self._serialize_ruleset(session, rs, lib_id)
                for rs in sorted(dev.rule_sets, key=lambda rs: rs.name)
            ]

        return d

    def _serialize_interface(self, session, iface, lib_id):
        d = _serialize_obj(iface)

        # Interface addresses
        if iface.addresses:
            d['addresses'] = [
                self._serialize_address(a)
                for a in sorted(iface.addresses, key=lambda a: a.name)
            ]

        return d

    def _serialize_ruleset(self, session, rs, lib_id):
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
            d['rules'] = [self._serialize_rule(session, rule, lib_id) for rule in rules]

        return d

    def _serialize_rule(self, session, rule, lib_id):
        d = _serialize_obj(rule, extra_skip=frozenset({'sorted_dst_ids', 'negations'}))

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
                ref = self._ref_path(target_id, lib_id)
                slots.setdefault(slot, []).append(ref)
            for slot in slots:
                slots[slot].sort()
            d.update(slots)

        return d

    @staticmethod
    def _write_yaml(path, data):
        with pathlib.Path.open(path, 'w', encoding='utf-8') as f:
            yaml.dump(
                data,
                f,
                Dumper=_QuotedValueDumper,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
