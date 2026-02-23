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

"""Constants and pure functions for the object tree."""

import uuid

import sqlalchemy

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    Interval,
    IntervalGroup,
    Library,
    ObjectGroup,
    RuleSet,
    Service,
    ServiceGroup,
)
from firewallfabrik.gui.platform_settings import HOST_OS

# Map ORM type discriminator strings to QRC icon aliases.
ICON_MAP = {
    'AddressRange': ':/Icons/AddressRange/icon-tree',
    'AddressTable': ':/Icons/AddressTable/icon-tree',
    'AttachedNetworks': ':/Icons/AttachedNetworks/icon-tree',
    'Cluster': ':/Icons/Cluster/icon-tree',
    'CustomService': ':/Icons/CustomService/icon-tree',
    'DNSName': ':/Icons/DNSName/icon-tree',
    'DynamicGroup': ':/Icons/DynamicGroup/icon-tree',
    'FailoverClusterGroup': ':/Icons/FailoverClusterGroup/icon-tree',
    'Firewall': ':/Icons/Firewall/icon-tree',
    'Host': ':/Icons/Host/icon-tree',
    'ICMP6Service': ':/Icons/ICMP6Service/icon-tree',
    'ICMPService': ':/Icons/ICMPService/icon-tree',
    'Interface': ':/Icons/Interface/icon-tree',
    'Interval': ':/Icons/Interval/icon-tree',
    'IntervalGroup': ':/Icons/IntervalGroup/icon-tree',
    'IPService': ':/Icons/IPService/icon-tree',
    'IPv4': ':/Icons/IPv4/icon-tree',
    'IPv6': ':/Icons/IPv6/icon-tree',
    'Library': ':/Icons/Library/icon-tree',
    'NAT': ':/Icons/NAT/icon-tree',
    'Network': ':/Icons/Network/icon-tree',
    'NetworkIPv6': ':/Icons/NetworkIPv6/icon-tree',
    'ObjectGroup': ':/Icons/ObjectGroup/icon-tree',
    'PhysAddress': ':/Icons/PhysAddress/icon-tree',
    'Policy': ':/Icons/Policy/icon-tree',
    'Routing': ':/Icons/Routing/icon-tree',
    'ServiceGroup': ':/Icons/ServiceGroup/icon-tree',
    'StateSyncClusterGroup': ':/Icons/StateSyncClusterGroup/icon-tree',
    'TCPService': ':/Icons/TCPService/icon-tree',
    'TagService': ':/Icons/TagService/icon-tree',
    'UDPService': ':/Icons/UDPService/icon-tree',
    'UserService': ':/Icons/UserService/icon-tree',
}

CATEGORY_ICON = ':/Icons/SystemGroup/icon-tree'
LOCK_ICON = ':/Icons/lock'

# Maps object type discriminators to their standard two-level group path
# inside a library.  Mirrors fwbuilder's ``systemGroupPaths`` map
# (FWBTree.cpp:125-152).
SYSTEM_GROUP_PATHS = {
    'AddressRange': 'Objects/Address Ranges',
    'AddressTable': 'Objects/Address Tables',
    'Cluster': 'Clusters',
    'CustomService': 'Services/Custom',
    'DNSName': 'Objects/DNS Names',
    'DynamicGroup': 'Objects/Groups',
    'Firewall': 'Firewalls',
    'Host': 'Objects/Hosts',
    'ICMP6Service': 'Services/ICMP',
    'ICMPService': 'Services/ICMP',
    'IPService': 'Services/IP',
    'IPv4': 'Objects/Addresses',
    'IPv6': 'Objects/Addresses',
    'Interval': 'Time',
    'Network': 'Objects/Networks',
    'NetworkIPv6': 'Objects/Networks',
    'ObjectGroup': 'Objects/Groups',
    'ServiceGroup': 'Services/Groups',
    'TCPService': 'Services/TCP',
    'TagService': 'Services/TagServices',
    'UDPService': 'Services/UDP',
    'UserService': 'Services/Users',
}

# Full folder structure created for every new library.  Mirrors
# fwbuilder's ``FWBTree::createNewLibrary()`` (FWBTree.cpp:513-601).
# Each entry is ``(group_type, name, children | None)``.
LIBRARY_FOLDER_STRUCTURE = [
    ('ObjectGroup', 'Clusters', None),
    ('ObjectGroup', 'Firewalls', None),
    (
        'ObjectGroup',
        'Objects',
        [
            ('ObjectGroup', 'Address Ranges'),
            ('ObjectGroup', 'Address Tables'),
            ('ObjectGroup', 'Addresses'),
            ('ObjectGroup', 'DNS Names'),
            ('ObjectGroup', 'Groups'),
            ('ObjectGroup', 'Hosts'),
            ('ObjectGroup', 'Networks'),
        ],
    ),
    (
        'ServiceGroup',
        'Services',
        [
            ('ServiceGroup', 'Custom'),
            ('ServiceGroup', 'Groups'),
            ('ServiceGroup', 'ICMP'),
            ('ServiceGroup', 'IP'),
            ('ServiceGroup', 'TCP'),
            ('ServiceGroup', 'TagServices'),
            ('ServiceGroup', 'UDP'),
            ('ServiceGroup', 'Users'),
        ],
    ),
    ('IntervalGroup', 'Time', None),
]

GROUP_TYPE_CLS = {
    'IntervalGroup': IntervalGroup,
    'ObjectGroup': ObjectGroup,
    'ServiceGroup': ServiceGroup,
}

# Map type discriminator strings to their SQLAlchemy base model class.
MODEL_MAP = {
    'AddressRange': Address,
    'AddressTable': Group,
    'AttachedNetworks': Group,
    'Cluster': Host,
    'CustomService': Service,
    'DNSName': Group,
    'DynamicGroup': Group,
    'FailoverClusterGroup': Group,
    'Firewall': Host,
    'Host': Host,
    'ICMP6Service': Service,
    'ICMPService': Service,
    'IPService': Service,
    'IPv4': Address,
    'IPv6': Address,
    'Interface': Interface,
    'Interval': Interval,
    'IntervalGroup': Group,
    'Library': Library,
    'NAT': RuleSet,
    'Network': Address,
    'NetworkIPv6': Address,
    'ObjectGroup': Group,
    'PhysAddress': Address,
    'Policy': RuleSet,
    'Routing': RuleSet,
    'ServiceGroup': Group,
    'StateSyncClusterGroup': Group,
    'TCPService': Service,
    'TagService': Service,
    'UDPService': Service,
    'UserService': Service,
}

# Rule set types that can be opened via double-click.
RULE_SET_TYPES = frozenset({'NAT', 'Policy', 'Routing'})

# Types that cannot be dragged (structural / container items).
NON_DRAGGABLE_TYPES = frozenset({'Library', 'NAT', 'Policy', 'Routing'})

# Types for which "Duplicate ..." is not offered (structural / internal).
NO_DUPLICATE_TYPES = frozenset(
    {
        'AttachedNetworks',
        'Interface',
        'Library',
        'NAT',
        'PhysAddress',
        'Policy',
        'Routing',
    }
)

# Types for which "Move" is not offered.
NO_MOVE_TYPES = frozenset(
    {
        'AttachedNetworks',
        'Interface',
        'Library',
        'NAT',
        'PhysAddress',
        'Policy',
        'Routing',
    }
)

# Types that cannot be copied / cut.
NO_COPY_TYPES = frozenset(
    {
        'AttachedNetworks',
        'Library',
        'NAT',
        'Policy',
        'Routing',
    }
)

# Types that cannot be deleted.
NO_DELETE_TYPES = frozenset({'AttachedNetworks'})

# System folder names that match fwbuilder's ``deleteMenuState`` map
# (FWBTree.cpp:344-364).  These structural groups cannot be deleted.
SYSTEM_ROOT_FOLDERS = frozenset(
    {'Clusters', 'Firewalls', 'Objects', 'Services', 'Time'}
)
SYSTEM_SUB_FOLDERS = {
    'Objects': frozenset(
        {
            'Address Ranges',
            'Address Tables',
            'Addresses',
            'DNS Names',
            'Groups',
            'Hosts',
            'Networks',
        }
    ),
    'Services': frozenset(
        {
            'Custom',
            'Groups',
            'ICMP',
            'IP',
            'TCP',
            'TagServices',
            'UDP',
            'Users',
        }
    ),
}

# Service object types used to detect group type for "Group" action.
SERVICE_OBJ_TYPES = frozenset(
    {
        'CustomService',
        'ICMP6Service',
        'ICMPService',
        'IPService',
        'ServiceGroup',
        'TCPService',
        'TagService',
        'UDPService',
        'UserService',
    }
)

# New object types offered for device context (sorted alphabetically).
NEW_TYPES_FOR_PARENT = {
    'Cluster': [
        ('Interface', 'Interface'),
        ('NAT', 'NAT Rule Set'),
        ('Policy', 'Policy Rule Set'),
        ('Routing', 'Routing Rule Set'),
        ('StateSyncClusterGroup', 'State Sync Group'),
    ],
    'Firewall': [
        ('Interface', 'Interface'),
        ('NAT', 'NAT Rule Set'),
        ('Policy', 'Policy Rule Set'),
        ('Routing', 'Routing Rule Set'),
    ],
    'Host': [
        ('Interface', 'Interface'),
    ],
}

# New object types offered based on the data.folder of the clicked item
# (or its siblings).  Matches fwbuilder's addSubfolderActions() order.
NEW_TYPES_FOR_FOLDER = {
    'Address Ranges': [
        ('AddressRange', 'Address Range'),
    ],
    'Address Tables': [
        ('AddressTable', 'Address Table'),
    ],
    'Addresses': [
        ('IPv4', 'Address'),
        ('IPv6', 'Address IPv6'),
    ],
    'Clusters': [
        ('Cluster', 'Cluster'),
    ],
    'Custom': [
        ('CustomService', 'Custom Service'),
    ],
    'DNS Names': [
        ('DNSName', 'DNS Name'),
    ],
    'Firewalls': [
        ('Firewall', 'Firewall'),
    ],
    'Groups': [
        ('DynamicGroup', 'Dynamic Group'),
        ('ObjectGroup', 'Object Group'),
        ('ServiceGroup', 'Service Group'),
    ],
    'Hosts': [
        ('Host', 'Host'),
    ],
    'ICMP': [
        ('ICMP6Service', 'ICMP6 Service'),
        ('ICMPService', 'ICMP Service'),
    ],
    'IP': [
        ('IPService', 'IP Service'),
    ],
    'Networks': [
        ('Network', 'Network'),
        ('NetworkIPv6', 'Network IPv6'),
    ],
    'TCP': [
        ('TCPService', 'TCP Service'),
    ],
    'TagServices': [
        ('TagService', 'Tag Service'),
    ],
    'Time': [
        ('Interval', 'Time Interval'),
    ],
    'UDP': [
        ('UDPService', 'UDP Service'),
    ],
    'Users': [
        ('UserService', 'User Service'),
    ],
}

# Context menu "New [Type]" entries for real group nodes, keyed by
# ``(group_type, group_name)``.  This disambiguates folders with the
# same name under different parents (e.g. "Groups" under Objects vs.
# under Services) and provides correct entries for top-level groups.
# Mirrors fwbuilder's ``ObjectManipulator::addSubfolderActions()`` logic.
NEW_TYPES_FOR_GROUP_NODE = {
    ('IntervalGroup', 'Time'): [
        ('Interval', 'Time Interval'),
    ],
    ('ObjectGroup', 'Address Ranges'): [
        ('AddressRange', 'Address Range'),
    ],
    ('ObjectGroup', 'Address Tables'): [
        ('AddressTable', 'Address Table'),
    ],
    ('ObjectGroup', 'Addresses'): [
        ('IPv4', 'Address'),
        ('IPv6', 'Address IPv6'),
    ],
    ('ObjectGroup', 'Clusters'): [
        ('Cluster', 'Cluster'),
    ],
    ('ObjectGroup', 'DNS Names'): [
        ('DNSName', 'DNS Name'),
    ],
    ('ObjectGroup', 'Firewalls'): [
        ('Firewall', 'Firewall'),
    ],
    ('ObjectGroup', 'Groups'): [
        ('DynamicGroup', 'Dynamic Group'),
        ('ObjectGroup', 'Object Group'),
    ],
    ('ObjectGroup', 'Hosts'): [
        ('Host', 'Host'),
    ],
    ('ObjectGroup', 'Networks'): [
        ('Network', 'Network'),
        ('NetworkIPv6', 'Network IPv6'),
    ],
    ('ObjectGroup', 'Objects'): [
        ('AddressRange', 'Address Range'),
        ('AddressTable', 'Address Table'),
        ('DNSName', 'DNS Name'),
        ('DynamicGroup', 'Dynamic Group'),
        ('Host', 'Host'),
        ('IPv4', 'Address'),
        ('IPv6', 'Address IPv6'),
        ('Network', 'Network'),
        ('NetworkIPv6', 'Network IPv6'),
        ('ObjectGroup', 'Object Group'),
    ],
    ('ServiceGroup', 'Custom'): [
        ('CustomService', 'Custom Service'),
    ],
    ('ServiceGroup', 'Groups'): [
        ('ServiceGroup', 'Service Group'),
    ],
    ('ServiceGroup', 'ICMP'): [
        ('ICMP6Service', 'ICMP6 Service'),
        ('ICMPService', 'ICMP Service'),
    ],
    ('ServiceGroup', 'IP'): [
        ('IPService', 'IP Service'),
    ],
    ('ServiceGroup', 'Services'): [
        ('CustomService', 'Custom Service'),
        ('ICMP6Service', 'ICMP6 Service'),
        ('ICMPService', 'ICMP Service'),
        ('IPService', 'IP Service'),
        ('ServiceGroup', 'Service Group'),
        ('TCPService', 'TCP Service'),
        ('TagService', 'Tag Service'),
        ('UDPService', 'UDP Service'),
        ('UserService', 'User Service'),
    ],
    ('ServiceGroup', 'TCP'): [
        ('TCPService', 'TCP Service'),
    ],
    ('ServiceGroup', 'TagServices'): [
        ('TagService', 'Tag Service'),
    ],
    ('ServiceGroup', 'UDP'): [
        ('UDPService', 'UDP Service'),
    ],
    ('ServiceGroup', 'Users'): [
        ('UserService', 'User Service'),
    ],
}

# Types for which Compile / Install are offered in the context menu.
COMPILABLE_TYPES = frozenset({'Cluster', 'Firewall'})

# Types whose ORM model has an ``ro`` column (Host, Group, Library subtypes).
# These can be locked/unlocked via the context menu.
LOCKABLE_TYPES = frozenset(
    {
        'AddressTable',
        'AttachedNetworks',
        'Cluster',
        'DNSName',
        'DynamicGroup',
        'FailoverClusterGroup',
        'Firewall',
        'Host',
        'IntervalGroup',
        'Library',
        'ObjectGroup',
        'ServiceGroup',
        'StateSyncClusterGroup',
    }
)

# Types that DO get "New Subfolder" in their context menu.
# Matches fwbuilder's addSubfolderActions() exclusion list (lines 420-444):
# types NOT listed there get addSubfolder=true.
SUBFOLDER_TYPES = frozenset({'Interface', 'IntervalGroup', 'ObjectGroup'})


# ------------------------------------------------------------------
# Pure functions
# ------------------------------------------------------------------


def find_group_by_path(session, lib_id, path):
    """Resolve a ``"Level1/Level2"`` group path inside a library.

    Returns the deepest :class:`Group`, or *None* if any segment is
    missing (the caller should fall back to virtual ``data.folder``).
    """
    if not path:
        return None
    parts = path.split('/')
    parent_id = None
    group = None
    for part in parts:
        stmt = sqlalchemy.select(Group).where(
            Group.library_id == lib_id,
            Group.name == part,
        )
        if parent_id is None:
            stmt = stmt.where(Group.parent_group_id.is_(None))
        else:
            stmt = stmt.where(Group.parent_group_id == parent_id)
        group = session.scalars(stmt).first()
        if group is None:
            return None
        parent_id = group.id
    return group


def create_library_folder_structure(session, lib_id):
    """Create the standard folder hierarchy for a library.

    Mirrors fwbuilder's ``FWBTree::createNewLibrary()`` which creates
    ``Clusters``, ``Firewalls``, ``Objects`` (with sub-groups),
    ``Services`` (with sub-groups), and ``Time`` groups.
    """
    for group_type, name, children in LIBRARY_FOLDER_STRUCTURE:
        cls = GROUP_TYPE_CLS[group_type]
        parent = cls(
            id=uuid.uuid4(),
            type=group_type,
            library_id=lib_id,
            name=name,
        )
        session.add(parent)
        if children:
            session.flush()  # ensure parent.id is available
            for child_type, child_name in children:
                child_cls = GROUP_TYPE_CLS[child_type]
                session.add(
                    child_cls(
                        id=uuid.uuid4(),
                        type=child_type,
                        library_id=lib_id,
                        parent_group_id=parent.id,
                        name=child_name,
                    )
                )


def normalize_subfolders(raw):
    """Normalize a subfolders value to a list of strings.

    Handles both list format (Python-created) and comma-separated string
    format (from fwbuilder XML import).
    """
    if isinstance(raw, str):
        return [s.strip() for s in raw.split(',') if s.strip()]
    if isinstance(raw, list):
        return raw
    return []


def obj_sort_key(obj):
    """Sort key: (label, name), case-insensitive."""
    data = getattr(obj, 'data', None) or {}
    label = (data.get('label') or '').lower()
    return (label, obj.name.lower())


def obj_display_name(obj):
    """Return 'name (label)' when a label exists, else just 'name'."""
    data = getattr(obj, 'data', None) or {}
    label = data.get('label') or ''
    if label:
        return f'{obj.name} ({label})'
    return obj.name


def is_inactive(obj):
    """Return True if the object is marked inactive/disabled."""
    data = getattr(obj, 'data', None) or {}
    return data.get('inactive') in (True, 'True')


def needs_compile(obj):
    """Return True if the object has been modified since the last compile."""
    data = getattr(obj, 'data', None) or {}
    last_modified = int(data.get('lastModified', 0) or 0)
    last_compiled = int(data.get('lastCompiled', 0) or 0)
    return last_modified > last_compiled


def obj_tags(obj):
    """Return the tags (keywords) of *obj* as a set, or empty set."""
    return getattr(obj, 'keywords', None) or set()


def tags_to_str(tags):
    """Convert a tag set to a lowercased, space-joined string for filtering."""
    if not tags:
        return ''
    return ' '.join(t.lower() for t in sorted(tags))


def obj_brief_attrs(obj, under_interface=False):
    """Return a display-friendly attribute string for the tree's second column.

    Matches the format of fwbuilder's ``getObjectPropertiesBrief()``.
    The same string serves as visible column text **and** filter search text.
    """
    type_str = getattr(obj, 'type', type(obj).__name__)

    # -- Addresses --
    if type_str in ('IPv4', 'IPv6'):
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        addr = iam.get('address', '')
        if under_interface:
            mask = iam.get('netmask', '')
            return f'{addr}/{mask}' if addr else ''
        return addr or ''

    if type_str in ('Network', 'NetworkIPv6'):
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        addr = iam.get('address', '')
        mask = iam.get('netmask', '')
        return f'{addr}/{mask}' if addr else ''

    if type_str == 'AddressRange':
        start = (getattr(obj, 'start_address', None) or {}).get('address', '')
        end = (getattr(obj, 'end_address', None) or {}).get('address', '')
        if start or end:
            return f'{start} - {end}'
        return ''

    if type_str == 'PhysAddress':
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        return iam.get('address', '') or ''

    # -- Devices --
    if type_str in ('Cluster', 'Firewall'):
        data = getattr(obj, 'data', None) or {}
        platform = data.get('platform', '')
        version = data.get('version', '')
        host_os = data.get('host_OS', '')
        host_os = HOST_OS.get(host_os, host_os)
        if platform:
            return f'{platform}({version or "- any -"}) / {host_os}'
        return ''

    # -- Services --
    if type_str in ('TCPService', 'UDPService'):
        ss = getattr(obj, 'src_range_start', None) or 0
        se = getattr(obj, 'src_range_end', None) or 0
        ds = getattr(obj, 'dst_range_start', None) or 0
        de = getattr(obj, 'dst_range_end', None) or 0
        return f'{ss}:{se} / {ds}:{de}'

    if type_str in ('ICMP6Service', 'ICMPService'):
        codes = getattr(obj, 'codes', None) or {}
        icmp_type = codes.get('type', -1)
        code = codes.get('code', -1)
        return f'type: {icmp_type}  code: {code}'

    if type_str == 'IPService':
        named = getattr(obj, 'named_protocols', None) or {}
        protocol_num = named.get('protocol_num', '')
        if protocol_num:
            return f'protocol: {protocol_num}'
        return ''

    # -- Interface --
    if type_str == 'Interface':
        data = getattr(obj, 'data', None) or {}
        label = data.get('label', '')
        flags = []
        if getattr(obj, 'is_dynamic', lambda: False)():
            flags.append('dyn')
        if getattr(obj, 'is_unnumbered', lambda: False)():
            flags.append('unnum')
        if getattr(obj, 'is_bridge_port', lambda: False)():
            flags.append('bridge port')
        if getattr(obj, 'is_slave', lambda: False)():
            flags.append('slave')
        parts = [label] if label else []
        if flags:
            parts.append(','.join(flags))
        return ' '.join(parts)

    # -- Groups --
    if type_str in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
        count = 0
        for attr in ('addresses', 'child_groups', 'devices', 'intervals', 'services'):
            val = getattr(obj, attr, None)
            if val:
                count += len(val)
        return f'{count} objects'

    # -- Library --
    if type_str == 'Library':
        if getattr(obj, 'ro', False):
            return '(read only)'
        return ''

    return ''
