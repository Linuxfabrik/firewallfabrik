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

"""YAML reader for loading a single YAML file back into the database model."""

import logging
import pathlib
import uuid

import yaml

from . import objects
from ._util import (
    ADDRESS_CLASSES,
    DEVICE_CLASSES,
    GROUP_CLASSES,
    RULE_CLASSES,
    RULESET_CLASSES,
    SERVICE_CLASSES,
    SLOT_VALUES,
    ParseResult,
    escape_obj_name,
)

logger = logging.getLogger(__name__)

# Reverse enum maps: yaml key -> (orm column, enum class)
_ENUM_REVERSE = {
    'PolicyRule': {
        'action': ('policy_action', objects.PolicyAction),
        'direction': ('policy_direction', objects.Direction),
    },
    'NATRule': {
        'action': ('nat_action', objects.NATAction),
        'rule_type': ('nat_rule_type', objects.NATRuleType),
    },
    'RoutingRule': {
        'rule_type': ('routing_rule_type', objects.RoutingRuleType),
    },
}

# YAML reader needs base classes in addition to concrete subclasses.
_ADDRESS_CLASSES = {**ADDRESS_CLASSES, 'Address': objects.Address}

_SERVICE_CLASSES = {
    **SERVICE_CLASSES,
    'Service': objects.Service,
    'TCPUDPService': objects.TCPUDPService,
}

_GROUP_CLASSES = {**GROUP_CLASSES, 'Group': objects.Group}
_DEVICE_CLASSES = DEVICE_CLASSES
_RULESET_CLASSES = {**RULESET_CLASSES, 'RuleSet': objects.RuleSet}
_RULE_CLASSES = {**RULE_CLASSES, 'Rule': objects.Rule}


def _coerce_bools(d):
    """Coerce string booleans in a dict to Python bools.

    YAML normally handles this, but quoted values like ``"true"`` remain
    strings. This keeps behaviour consistent with the XML reader.
    """
    if not isinstance(d, dict):
        return d
    coerced = {}
    for k, v in d.items():
        if isinstance(v, str):
            low = v.lower()
            if low == 'true':
                coerced[k] = True
                continue
            if low == 'false':
                coerced[k] = False
                continue
        coerced[k] = v
    return coerced


class YamlReader:
    """Parses a single YAML file into a ParseResult compatible with DatabaseManager.load()."""

    def __init__(self):
        self._ref_index = {}  # full tree-path -> UUID
        self._memberships = []
        self._rule_element_rows = []
        self._deferred_memberships = []
        self._deferred_rule_elements = []

    def parse(self, input_path):
        input_path = pathlib.Path(input_path)

        self._ref_index.clear()
        self._memberships.clear()
        self._rule_element_rows.clear()
        self._deferred_memberships.clear()
        self._deferred_rule_elements.clear()

        # Phase 1: Load YAML file
        with pathlib.Path.open(input_path, encoding='utf-8') as f:
            db_data = yaml.safe_load(f)

        # Phase 2: Create objects
        db = objects.FWObjectDatabase()
        db.id = uuid.uuid4()
        db.name = db_data.get('name', '')
        db.comment = db_data.get('comment', '')
        db.last_modified = db_data.get('last_modified', 0.0)
        db.data_file = db_data.get('data_file', '')
        db.predictable_id_tracker = db_data.get('predictable_id_tracker', 0)
        db.data = db_data.get('data', {})

        for lib_data in db_data.get('libraries', []):
            self._parse_library(lib_data, db)

        # Phase 3: Resolve references
        self._resolve_deferred()

        return ParseResult(
            database=db,
            memberships=self._memberships[:],
            rule_element_rows=self._rule_element_rows[:],
        )

    def _register_ref(self, path, obj_id):
        """Register a full tree-path -> UUID mapping."""
        if path not in self._ref_index:
            self._ref_index[path] = obj_id
            return path
        # #N fallback for same-path collisions
        n = 2
        while f'{path}#{n}' in self._ref_index:
            n += 1
        if n == 2:
            self._ref_index[f'{path}#1'] = self._ref_index[path]
        self._ref_index[f'{path}#{n}'] = obj_id
        return f'{path}#{n}'

    def _resolve_ref_path(self, ref_path):
        """Resolve a full tree-path to UUID via direct lookup."""
        return self._ref_index.get(ref_path)

    def _resolve_deferred(self):
        for group_id, ref_path in self._deferred_memberships:
            target_id = self._resolve_ref_path(ref_path)
            if target_id is None:
                logger.warning('Unresolved group member ref: %s', ref_path)
                continue
            self._memberships.append(
                {
                    'group_id': group_id,
                    'member_id': target_id,
                }
            )

        for rule_id, slot, ref_path in self._deferred_rule_elements:
            target_id = self._resolve_ref_path(ref_path)
            if target_id is None:
                logger.warning('Unresolved rule element ref: %s', ref_path)
                continue
            self._rule_element_rows.append(
                {
                    'rule_id': rule_id,
                    'slot': slot,
                    'target_id': target_id,
                }
            )

    def _dispatch_child(self, data, library, parent_path, parent_group=None):
        """Route a child dict by its ``type`` to the correct parse method."""
        type_name = data.get('type', '')
        if type_name in _GROUP_CLASSES:
            self._parse_group(data, library, parent_path, parent_group=parent_group)
        elif type_name in _ADDRESS_CLASSES:
            addr = self._parse_address(data, parent_path, library=library)
            if parent_group is not None:
                addr.group = parent_group
        elif type_name in _SERVICE_CLASSES:
            svc = self._parse_service(data, library, parent_path)
            if parent_group is not None:
                svc.group = parent_group
        elif type_name == 'Interval':
            itv = self._parse_interval(data, library, parent_path)
            if parent_group is not None:
                itv.group = parent_group
        elif type_name in _DEVICE_CLASSES:
            dev = self._parse_device(data, library, parent_path)
            if parent_group is not None:
                dev.group = parent_group
        elif type_name == 'Interface':
            self._parse_interface(data, library, None, parent_path)
        else:
            logger.warning('Unknown child type: %s', type_name)

    def _parse_library(self, lib_data, db):
        lib = objects.Library()
        lib.id = uuid.uuid4()
        lib.name = lib_data.get('name', '')
        lib.comment = lib_data.get('comment', '')
        lib.ro = lib_data.get('ro', False)
        lib.data = lib_data.get('data', {})
        lib.database = db

        lib_path = f'Library:{escape_obj_name(lib.name)}'

        for child_data in lib_data.get('children', []):
            self._dispatch_child(child_data, lib, lib_path)

        return lib

    def _parse_address(self, data, parent_path, library=None, interface=None):
        type_name = data.get('type', 'Address')
        cls = _ADDRESS_CLASSES.get(type_name, objects.Address)
        addr = cls()
        addr.id = uuid.uuid4()
        addr.name = data.get('name', '')
        addr.comment = data.get('comment', '')
        addr.keywords = set(data.get('keywords', []))
        addr.data = data.get('data', {})

        # Type-specific fields
        if 'inet_addr_mask' in data:
            addr.inet_addr_mask = data['inet_addr_mask']
        if 'start_address' in data:
            addr.start_address = data['start_address']
        if 'end_address' in data:
            addr.end_address = data['end_address']
        if 'subst_type_name' in data:
            addr.subst_type_name = data['subst_type_name']
        if 'source_name' in data:
            addr.source_name = data['source_name']
        if 'run_time' in data:
            addr.run_time = data['run_time']

        if interface is not None:
            addr.interface = interface
        elif library is not None:
            addr.library = library

        self._register_ref(
            f'{parent_path}/{type_name}:{escape_obj_name(addr.name)}',
            addr.id,
        )
        return addr

    def _parse_service(self, data, library, parent_path):
        type_name = data.get('type', 'Service')
        cls = _SERVICE_CLASSES.get(type_name, objects.Service)
        svc = cls()
        svc.id = uuid.uuid4()
        svc.name = data.get('name', '')
        svc.comment = data.get('comment', '')
        svc.keywords = set(data.get('keywords', []))
        svc.data = data.get('data', {})
        svc.library = library

        # Type-specific fields
        for field in (
            'src_range_start',
            'src_range_end',
            'dst_range_start',
            'dst_range_end',
        ):
            if field in data:
                setattr(svc, field, data[field])

        if 'tcp_flags' in data:
            svc.tcp_flags = data['tcp_flags']
        if 'tcp_flags_masks' in data:
            svc.tcp_flags_masks = data['tcp_flags_masks']
        if 'named_protocols' in data:
            svc.named_protocols = data['named_protocols']
        if 'codes' in data:
            svc.codes = data['codes']
        if 'protocol' in data:
            svc.protocol = data['protocol']
        if 'custom_address_family' in data:
            svc.custom_address_family = data['custom_address_family']
        if 'userid' in data:
            svc.userid = data['userid']

        self._register_ref(
            f'{parent_path}/{type_name}:{escape_obj_name(svc.name)}',
            svc.id,
        )
        return svc

    def _parse_interval(self, data, library, parent_path):
        itv = objects.Interval()
        itv.id = uuid.uuid4()
        itv.name = data.get('name', '')
        itv.comment = data.get('comment', '')
        itv.keywords = set(data.get('keywords', []))
        itv.data = data.get('data', {})
        itv.library = library

        self._register_ref(
            f'{parent_path}/Interval:{escape_obj_name(itv.name)}',
            itv.id,
        )
        return itv

    def _parse_group(self, data, library, parent_path, parent_group=None):
        type_name = data.get('type', 'ObjectGroup')
        cls = _GROUP_CLASSES.get(type_name, objects.ObjectGroup)
        grp = cls()
        grp.id = uuid.uuid4()
        grp.name = data.get('name', '')
        grp.comment = data.get('comment', '')
        grp.ro = data.get('ro', False)
        grp.keywords = set(data.get('keywords', []))
        grp.data = data.get('data', {})
        grp.options = _coerce_bools(data.get('options', {}))
        grp.library = library

        if parent_group is not None:
            grp.parent_group = parent_group

        grp_path = f'{parent_path}/{type_name}:{escape_obj_name(grp.name)}'
        self._register_ref(grp_path, grp.id)

        # Children (mixed types: objects + subgroups)
        for child_data in data.get('children', []):
            self._dispatch_child(child_data, library, grp_path, parent_group=grp)

        # Deferred member references (cross-references only)
        for ref_path in data.get('members', []):
            self._deferred_memberships.append((grp.id, ref_path))

        return grp

    def _parse_device(self, data, library, parent_path):
        type_name = data.get('type', 'Host')
        cls = _DEVICE_CLASSES.get(type_name, objects.Host)
        dev = cls()
        dev.id = uuid.uuid4()
        dev.name = data.get('name', '')
        dev.comment = data.get('comment', '')
        dev.ro = data.get('ro', False)
        dev.keywords = set(data.get('keywords', []))
        dev.data = data.get('data', {})
        dev.options = _coerce_bools(data.get('options', {}))
        dev.management = data.get('management', {})
        dev.library = library

        if 'id_mapping_for_duplicate' in data:
            dev.id_mapping_for_duplicate = data['id_mapping_for_duplicate']

        dev_path = f'{parent_path}/{type_name}:{escape_obj_name(dev.name)}'
        self._register_ref(dev_path, dev.id)

        # Interfaces
        for iface_data in data.get('interfaces', []):
            self._parse_interface(iface_data, None, dev, dev_path)

        # Rule sets
        for rs_data in data.get('rule_sets', []):
            self._parse_ruleset(rs_data, dev)

        return dev

    def _parse_interface(
        self, data, library, device, parent_path, parent_interface=None
    ):
        iface = objects.Interface()
        iface.id = uuid.uuid4()
        iface.name = data.get('name', '')
        iface.comment = data.get('comment', '')
        iface.keywords = set(data.get('keywords', []))
        iface.data = data.get('data', {})
        iface.options = _coerce_bools(data.get('options', {}))
        iface.bcast_bits = data.get('bcast_bits', 0)
        iface.ostatus = data.get('ostatus', False)
        iface.snmp_type = data.get('snmp_type', 0)
        iface.library = library
        iface.device = device

        if parent_interface is not None:
            iface.parent_interface = parent_interface

        iface_path = f'{parent_path}/Interface:{escape_obj_name(iface.name)}'
        self._register_ref(iface_path, iface.id)

        # Interface addresses
        for addr_data in data.get('addresses', []):
            self._parse_address(addr_data, iface_path, interface=iface)

        # Sub-interfaces
        for sub_data in data.get('interfaces', []):
            self._parse_interface(
                sub_data, library, device, iface_path, parent_interface=iface
            )

        return iface

    def _parse_ruleset(self, data, device):
        type_name = data.get('type', 'Policy')
        cls = _RULESET_CLASSES.get(type_name, objects.Policy)
        rs = cls()
        rs.id = uuid.uuid4()
        rs.name = data.get('name', '')
        rs.comment = data.get('comment', '')
        rs.options = _coerce_bools(data.get('options', {}))
        rs.ipv4 = data.get('ipv4', False)
        rs.ipv6 = data.get('ipv6', False)
        rs.top = data.get('top', False)
        rs.device = device

        # Rules
        for rule_data in data.get('rules', []):
            self._parse_rule(rule_data, rs, type_name)

        return rs

    def _parse_rule(self, data, rule_set, rs_type):
        type_name = data.get('type', 'PolicyRule')
        cls = _RULE_CLASSES.get(type_name, objects.PolicyRule)
        rule = cls()
        rule.id = uuid.uuid4()
        rule.name = data.get('name', '')
        rule.comment = data.get('comment', '')
        rule.label = data.get('label', '')
        rule.rule_unique_id = data.get('rule_unique_id', '')
        rule.compiler_message = data.get('compiler_message', '')
        rule.position = data.get('position', 0)
        rule.fallback = data.get('fallback', False)
        rule.hidden = data.get('hidden', False)
        rule.options = _coerce_bools(data.get('options', {}))
        rule.negations = data.get('negations', {})
        rule.rule_set = rule_set

        # Enum fields
        enum_map = _ENUM_REVERSE.get(type_name, {})
        for yaml_key, (orm_col, enum_cls) in enum_map.items():
            value = data.get(yaml_key)
            if value is not None:
                if isinstance(value, str):
                    # Look up by name
                    try:
                        setattr(rule, orm_col, enum_cls[value].value)
                    except KeyError:
                        logger.warning('Unknown enum value %s for %s', value, yaml_key)
                        setattr(rule, orm_col, int(value))
                else:
                    setattr(rule, orm_col, value)

        # Rule elements (slot references)
        for slot_name in SLOT_VALUES:
            refs = data.get(slot_name)
            if refs:
                for ref_path in refs:
                    self._deferred_rule_elements.append(
                        (rule.id, slot_name, ref_path),
                    )

        return rule
