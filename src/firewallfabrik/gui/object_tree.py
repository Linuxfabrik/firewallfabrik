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

"""Object tree panel for the main window."""

import copy
import json
import uuid
from datetime import UTC, datetime

import sqlalchemy
from PySide6.QtCore import QMimeData, QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QDrag, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMenu,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    RuleSet,
    Service,
    group_membership,
    rule_elements,
)
from firewallfabrik.gui.policy_model import FWF_MIME_TYPE

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

_CATEGORY_ICON = ':/Icons/SystemGroup/icon-tree'
_LOCK_ICON = ':/Icons/lock'


def _obj_sort_key(obj):
    """Sort key: (label, name), case-insensitive."""
    data = getattr(obj, 'data', None) or {}
    label = (data.get('label') or '').lower()
    return (label, obj.name.lower())


def _obj_display_name(obj):
    """Return 'name (label)' when a label exists, else just 'name'."""
    data = getattr(obj, 'data', None) or {}
    label = data.get('label') or ''
    if label:
        return f'{obj.name} ({label})'
    return obj.name


def _is_inactive(obj):
    """Return True if the object is marked inactive/disabled."""
    data = getattr(obj, 'data', None) or {}
    return data.get('inactive') == 'True'


def _obj_tags(obj):
    """Return the tags (keywords) of *obj* as a set, or empty set."""
    return getattr(obj, 'keywords', None) or set()


def _tags_to_str(tags):
    """Convert a tag set to a lowercased, space-joined string for filtering."""
    if not tags:
        return ''
    return ' '.join(t.lower() for t in sorted(tags))


def _obj_brief_attrs(obj, under_interface=False):
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


def _get_library_name(obj):
    """Return the name of the library containing *obj*, or empty string."""
    type_str = getattr(obj, 'type', type(obj).__name__)
    if type_str == 'Library':
        return obj.name
    try:
        lib = getattr(obj, 'library', None)
        if lib is not None:
            return lib.name
        # Address → interface → device → library
        iface = getattr(obj, 'interface', None)
        if iface is not None:
            lib = getattr(iface, 'library', None)
            if lib is not None:
                return lib.name
            device = getattr(iface, 'device', None)
            if device is not None:
                lib = getattr(device, 'library', None)
                if lib is not None:
                    return lib.name
        # RuleSet → device → library
        device = getattr(obj, 'device', None)
        if device is not None:
            lib = getattr(device, 'library', None)
            if lib is not None:
                return lib.name
    except Exception:
        pass
    return ''


def _obj_tooltip(obj):
    """Return an HTML tooltip string for *obj*, matching fwbuilder's detailed format."""
    type_str = getattr(obj, 'type', type(obj).__name__)
    name = getattr(obj, 'name', '')
    lines = []

    # Library header (skip for Library objects themselves).
    if type_str != 'Library':
        lib_name = _get_library_name(obj)
        if lib_name:
            lines.append(f'<b>Library:</b> {lib_name}')

    lines.append(f'<b>Object Type:</b> {type_str}')
    lines.append(f'<b>Object Name:</b> {name}')

    # -- Addresses --
    if type_str in ('IPv4', 'IPv6') or type_str in ('Network', 'NetworkIPv6'):
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        addr = iam.get('address', '')
        mask = iam.get('netmask', '')
        if addr:
            lines.append(f'{addr}/{mask}' if mask else addr)

    elif type_str == 'AddressRange':
        start = (getattr(obj, 'start_address', None) or {}).get('address', '')
        end = (getattr(obj, 'end_address', None) or {}).get('address', '')
        if start or end:
            lines.append(f'{start} - {end}')

    elif type_str == 'PhysAddress':
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        mac = iam.get('address', '')
        if mac:
            lines.append(mac)

    # -- Devices --
    elif type_str in ('Cluster', 'Firewall'):
        data = getattr(obj, 'data', None) or {}
        platform = data.get('platform', '')
        version = data.get('version', '') or '- any -'
        host_os = data.get('host_OS', '')
        ts_modified = int(data.get('lastModified', 0) or 0)
        ts_compiled = int(data.get('lastCompiled', 0) or 0)
        ts_installed = int(data.get('lastInstalled', 0) or 0)
        # Bold the most recent timestamp, show '-' for zero.
        ts_vals = {
            'Modified': ts_modified,
            'Compiled': ts_compiled,
            'Installed': ts_installed,
        }
        ts_max = max(ts_vals.values())
        ts_rows = ''
        for label, ts in ts_vals.items():
            if ts:
                text = datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')
            else:
                text = '-'
            if ts and ts == ts_max:
                text = f'<b>{text}</b>'
            ts_rows += f'<tr><td>{label}:&nbsp;</td><td>{text}</td></tr>'
        lines.append(
            '<table cellspacing="0" cellpadding="0">'
            f'<tr><td>Platform:&nbsp;</td><td>{platform}</td></tr>'
            f'<tr><td>Version:&nbsp;</td><td>{version}</td></tr>'
            f'<tr><td>Host OS:&nbsp;</td><td>{host_os}</td></tr>'
            f'{ts_rows}'
            '</table>'
        )

    elif type_str == 'Host':
        # Show interfaces with their brief attributes.
        for iface in sorted(
            getattr(obj, 'interfaces', []), key=lambda o: o.name.lower()
        ):
            attrs = _obj_brief_attrs(iface)
            lines.append(f'{iface.name}: {attrs}')

    elif type_str == 'Interface':
        # Parent device.
        device = getattr(obj, 'device', None)
        if device is not None:
            lines.append(f'<b>Parent: </b>{device.name}')
        data = getattr(obj, 'data', None) or {}
        label = data.get('label', '')
        lines.append(f'<b>Label: </b>{label}')
        # IP addresses.
        for addr in getattr(obj, 'addresses', []):
            if getattr(addr, 'type', '') == 'PhysAddress':
                continue
            iam = getattr(addr, 'inet_addr_mask', None) or {}
            a = iam.get('address', '')
            if a:
                m = iam.get('netmask', '')
                lines.append(f'{a}/{m}' if m else a)
        # Interface type.
        options = getattr(obj, 'options', None) or {}
        intf_type = options.get('type', '')
        if intf_type:
            type_text = intf_type
            if intf_type == '8021q':
                vlan_id = options.get('vlan_id', '')
                if vlan_id:
                    type_text += f' VLAN ID={vlan_id}'
            lines.append(f'<b>Interface Type: </b>{type_text}')
        # MAC address.
        for addr in getattr(obj, 'addresses', []):
            if getattr(addr, 'type', '') == 'PhysAddress':
                iam = getattr(addr, 'inet_addr_mask', None) or {}
                mac = iam.get('address', '')
                if mac:
                    lines.append(f'MAC: {mac}')
        # Flags.
        flags = []
        if getattr(obj, 'is_dynamic', lambda: False)():
            flags.append('dyn')
        if getattr(obj, 'is_unnumbered', lambda: False)():
            flags.append('unnum')
        if getattr(obj, 'is_bridge_port', lambda: False)():
            flags.append('bridge port')
        if getattr(obj, 'is_slave', lambda: False)():
            flags.append('slave')
        if flags:
            lines.append(f'({" ".join(flags)})')

    # -- Services --
    elif type_str in ('TCPService', 'UDPService'):
        ss = getattr(obj, 'src_range_start', None) or 0
        se = getattr(obj, 'src_range_end', None) or 0
        ds = getattr(obj, 'dst_range_start', None) or 0
        de = getattr(obj, 'dst_range_end', None) or 0
        lines.append(
            '<table cellspacing="0" cellpadding="0">'
            f'<tr><td>source port range&nbsp;</td><td>{ss}:{se}</td></tr>'
            f'<tr><td>destination port range&nbsp;</td><td>{ds}:{de}</td></tr>'
            '</table>'
        )

    elif type_str in ('ICMP6Service', 'ICMPService'):
        codes = getattr(obj, 'codes', None) or {}
        icmp_type = codes.get('type', -1)
        code = codes.get('code', -1)
        lines.append(f'type: {icmp_type}  code: {code}')

    elif type_str == 'IPService':
        named = getattr(obj, 'named_protocols', None) or {}
        protocol_num = named.get('protocol_num', '')
        if protocol_num:
            lines.append(f'protocol {protocol_num}')

    # -- Groups --
    elif type_str in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
        members = []
        for attr in ('addresses', 'child_groups', 'devices', 'intervals', 'services'):
            val = getattr(obj, attr, None)
            if val:
                members.extend(val)
        count = len(members)
        lines.append(f'{count} objects')
        for m in sorted(members, key=lambda o: o.name.lower())[:20]:
            m_type = getattr(m, 'type', type(m).__name__)
            lines.append(f'{m_type}  <b>{m.name}</b>')
        if count > 20:
            lines.append('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;.&nbsp;.&nbsp;.')

    # -- Library --
    elif type_str == 'Library':
        if getattr(obj, 'ro', False):
            lines.append('Read-only')

    # -- Comment --
    comment = getattr(obj, 'comment', None) or ''
    if comment:
        if len(comment) > 200:
            comment = comment[:200] + '\u2026'
        comment = (
            comment.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        )
        lines.append(f'<br><i>{comment}</i>')

    return '<br>'.join(lines)


# Rule set types that can be opened via double-click.
_RULE_SET_TYPES = frozenset({'Policy', 'NAT', 'Routing'})

# Types that cannot be dragged (structural / container items).
_NON_DRAGGABLE_TYPES = frozenset(
    {
        'Library',
        'NAT',
        'Policy',
        'Routing',
    }
)


# Map type discriminator strings to their SQLAlchemy base model class.
_MODEL_MAP = {
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

# Types for which "Duplicate ..." is not offered (structural / internal).
_NO_DUPLICATE_TYPES = frozenset(
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
_NO_MOVE_TYPES = frozenset(
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
_NO_COPY_TYPES = frozenset(
    {
        'AttachedNetworks',
        'Library',
        'NAT',
        'Policy',
        'Routing',
    }
)

# Types that cannot be deleted.
_NO_DELETE_TYPES = frozenset(
    {
        'AttachedNetworks',
        'Library',
    }
)

# New object types offered for device context (fwbuilder order).
_NEW_TYPES_FOR_PARENT = {
    'Cluster': [
        ('Interface', 'Interface'),
        ('Policy', 'Policy Rule Set'),
        ('NAT', 'NAT Rule Set'),
        ('StateSyncClusterGroup', 'State Sync Group'),
    ],
    'Firewall': [
        ('Interface', 'Interface'),
        ('Policy', 'Policy Rule Set'),
        ('NAT', 'NAT Rule Set'),
    ],
    'Host': [
        ('Interface', 'Interface'),
    ],
}

# New object types offered based on the data.folder of the clicked item
# (or its siblings).  Matches fwbuilder's addSubfolderActions() order.
_NEW_TYPES_FOR_FOLDER = {
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
        ('ObjectGroup', 'Object Group'),
        ('DynamicGroup', 'Dynamic Group'),
    ],
    'Hosts': [
        ('Host', 'Host'),
    ],
    'ICMP': [
        ('ICMPService', 'ICMP Service'),
        ('ICMP6Service', 'ICMP6 Service'),
    ],
    'IP': [
        ('IPService', 'IP Service'),
    ],
    'Networks': [
        ('Network', 'Network'),
        ('NetworkIPv6', 'Network IPv6'),
    ],
    'Service Groups': [
        ('ServiceGroup', 'Service Group'),
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

# Types that do NOT get "New Subfolder" in their context menu.
# Matches fwbuilder's exclusion list in addSubfolderActions().
_NO_SUBFOLDER_TYPES = frozenset(
    {
        'AddressRange',
        'AddressTable',
        'AttachedNetworks',
        'Cluster',
        'CustomService',
        'DNSName',
        'DynamicGroup',
        'Firewall',
        'Host',
        'ICMP6Service',
        'ICMPService',
        'IPService',
        'IPv4',
        'IPv6',
        'Interval',
        'Network',
        'NetworkIPv6',
        'ServiceGroup',
        'TCPService',
        'TagService',
        'UDPService',
        'UserService',
    }
)

# Module-level clipboard shared across all ObjectTree instances.
_tree_clipboard: dict | None = None  # {'id': str, 'type': str, 'cut': bool}


class _DraggableTree(QTreeWidget):
    """QTreeWidget subclass that provides drag MIME data for object items."""

    def mimeTypes(self):
        return [FWF_MIME_TYPE]

    def mimeData(self, items):
        if not items:
            return None
        item = items[0]
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type or obj_type in _NON_DRAGGABLE_TYPES:
            return None
        payload = json.dumps(
            {
                'id': obj_id,
                'name': item.text(0),
                'type': obj_type,
            }
        ).encode()
        mime = QMimeData()
        mime.setData(FWF_MIME_TYPE, payload)
        return mime

    def startDrag(self, supported_actions):
        """Start a drag with the object's type icon as cursor pixmap."""
        items = self.selectedItems()
        mime = self.mimeData(items)
        if mime is None:
            return
        item = items[0]
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)

        drag = QDrag(self)
        drag.setMimeData(mime)

        icon_path = ICON_MAP.get(obj_type)
        if icon_path:
            drag.setPixmap(QIcon(icon_path).pixmap(25, 25))

        drag.exec(supported_actions)


class ObjectTree(QWidget):
    """Left-hand object tree panel with filter field and library selector."""

    rule_set_activated = Signal(str, str, str)
    """Emitted when a rule set node is double-clicked: (rule_set_id, firewall_name, rule_set_name)."""

    object_activated = Signal(str, str)
    """Emitted when a non-rule-set object is double-clicked: (obj_id, obj_type)."""

    tree_changed = Signal()
    """Emitted after a CRUD operation (e.g. duplicate) to trigger a tree refresh."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText('Filter... (Ctrl+F)')
        self._filter.setClearButtonEnabled(True)

        shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        shortcut.activated.connect(self._filter.setFocus)

        self._tree = _DraggableTree()
        self._tree.setHeaderLabels(['Object', 'Attribute'])
        self._tree.setDragEnabled(True)
        self._tree.setDragDropMode(QAbstractItemView.DragDropMode.DragOnly)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)

        self._db_manager = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._filter)
        layout.addWidget(self._tree)

        self._show_attrs = QSettings().value(
            'UI/ShowObjectsAttributesInTree', True, type=bool
        )
        self._tooltips_enabled = QSettings().value('UI/ObjTooltips', True, type=bool)
        self._applying_saved_width = False
        self._apply_column_setup()

        # One-time cleanup of stale keys from an earlier implementation.
        settings = QSettings()
        if settings.value('TreeState') is not None:
            settings.remove('TreeState')
            settings.sync()

        self._tree.header().sectionResized.connect(self._on_section_resized)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        self._filter.textChanged.connect(self._apply_filter)

    def populate(self, session, file_key=''):
        """Build the tree from all libraries in *session*.

        *file_key* identifies the loaded file (typically ``str(path)``).
        When set, the expand/collapse state is restored from QSettings
        if no in-memory state exists (i.e. first open of this file in
        the current session).
        """
        had_tree = self._tree.topLevelItemCount() > 0
        expanded = self._save_expanded_state()
        self._tree.clear()
        self._filter.clear()

        libraries = session.scalars(sqlalchemy.select(Library)).all()

        # Sort so "User" comes first, "Standard" last, others alphabetical.
        def _lib_order(lib):
            if lib.name == 'User':
                return (0, '')
            if lib.name == 'Standard':
                return (2, '')
            return (1, lib.name.lower())

        libraries.sort(key=_lib_order)

        self._building_device_ro = False
        self._building_lib_ro = False

        self._groups_with_members = set(
            session.scalars(
                sqlalchemy.select(group_membership.c.group_id).distinct(),
            ).all()
        )

        for lib in libraries:
            self._building_lib_ro = getattr(lib, 'ro', False)
            self._building_device_ro = False
            lib_item = self._make_item(
                lib.name,
                'Library',
                str(lib.id),
                attrs=_obj_brief_attrs(lib),
                effective_readonly=self._building_lib_ro,
                obj=lib,
                readonly=self._building_lib_ro,
            )
            self._tree.addTopLevelItem(lib_item)
            self._add_children(lib, lib_item)

        if had_tree:
            # In-memory state from a previous populate (e.g. undo/redo).
            self._restore_expanded_state(expanded)
        elif file_key:
            # Try QSettings for this file, otherwise use defaults.
            stored = self._load_tree_state(file_key)
            if stored is not None:
                self._restore_expanded_state(stored)
            else:
                self._apply_default_expand()
        else:
            self._apply_default_expand()

        # Defer column setup so Qt has finished layout/painting first;
        # otherwise ResizeToContents computes zero width for column 1.
        QTimer.singleShot(0, self._apply_column_setup)

    @staticmethod
    def _item_path(item):
        """Build a stable path key from *item* to the tree root.

        Uses display text at each level (e.g. ``User/Firewalls/fw1``),
        which is deterministic across file reloads unlike object UUIDs.
        """
        parts = []
        current = item
        while current:
            parts.append(current.text(0))
            current = current.parent()
        parts.reverse()
        return '/'.join(parts)

    def _save_expanded_state(self):
        """Collect path keys for all currently expanded tree items."""
        expanded = set()

        def _walk(item):
            if not item.isExpanded():
                return
            expanded.add(self._item_path(item))
            for i in range(item.childCount()):
                _walk(item.child(i))

        for i in range(self._tree.topLevelItemCount()):
            _walk(self._tree.topLevelItem(i))
        return expanded

    def _restore_expanded_state(self, expanded_ids):
        """Re-expand items whose path keys are in *expanded_ids*."""

        def _walk(item):
            item.setExpanded(self._item_path(item) in expanded_ids)
            for i in range(item.childCount()):
                _walk(item.child(i))

        for i in range(self._tree.topLevelItemCount()):
            _walk(self._tree.topLevelItem(i))

    def _apply_default_expand(self):
        """Collapse "Standard" library, expand everything else."""
        for i in range(self._tree.topLevelItemCount()):
            item = self._tree.topLevelItem(i)
            item.setExpanded(item.text(0) != 'Standard')

    def save_tree_state(self, file_key):
        """Persist current tree expand/collapse state to QSettings.

        *file_key* should be the same string passed to :meth:`populate`
        (typically ``str(file_path)``).
        """
        if not file_key or self._tree.topLevelItemCount() == 0:
            return
        expanded = self._save_expanded_state()
        settings = QSettings()
        all_states = self._read_all_tree_states(settings)
        all_states[file_key] = sorted(expanded)
        settings.setValue('UI/TreeExpandState', json.dumps(all_states))
        settings.sync()

    def _load_tree_state(self, file_key):
        """Load persisted expand state from QSettings, or *None*."""
        all_states = self._read_all_tree_states(QSettings())
        ids = all_states.get(file_key)
        if ids is not None:
            return set(ids)
        return None

    @staticmethod
    def _read_all_tree_states(settings):
        """Return the full ``{file_key: [ids]}`` dict from QSettings.

        Handles the QSettings INI-backend quirk where a quoted string
        containing commas may be returned as a list instead of a str.
        """
        raw = settings.value('UI/TreeExpandState')
        if raw is None:
            return {}
        # QSettings may split comma-containing strings into a list.
        if isinstance(raw, list):
            raw = ','.join(str(x) for x in raw)
        if not isinstance(raw, str) or not raw:
            return {}
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_show_attrs(self, show):
        """Toggle the attribute column visibility."""
        self._show_attrs = show
        self._apply_column_setup()

    def set_db_manager(self, db_manager):
        """Set the database manager for context menu operations."""
        self._db_manager = db_manager

    def set_tooltips_enabled(self, enabled):
        """Enable or disable tooltips on all existing tree items."""
        self._tooltips_enabled = enabled
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if not enabled:
                item.setToolTip(0, '')
                item.setToolTip(1, '')
            else:
                # Re-derive tooltip from stored data; only object items
                # (those with an id in UserRole) carry tooltips.
                tip = item.data(0, Qt.ItemDataRole.UserRole + 4) or ''
                if tip:
                    item.setToolTip(0, tip)
                    if self._show_attrs:
                        item.setToolTip(1, tip)

    def _apply_column_setup(self):
        """Apply the current column count / resize mode."""
        if self._show_attrs:
            self._tree.setColumnCount(2)
            self._tree.setHeaderHidden(False)
            header = self._tree.header()
            header.setStretchLastSection(True)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
            saved = QSettings().value('UI/ObjectTreeCol0Width', 0, type=int)
            if saved > 0:
                self._applying_saved_width = True
                header.resizeSection(0, saved)
                self._applying_saved_width = False
        else:
            self._tree.setColumnCount(1)
            self._tree.setHeaderHidden(True)

    def _on_section_resized(self, index, _old_size, new_size):
        """Persist column width when the user drags the header."""
        if index == 0 and not self._applying_saved_width:
            QSettings().setValue('UI/ObjectTreeCol0Width', new_size)

    # ------------------------------------------------------------------
    # Tree building helpers
    # ------------------------------------------------------------------

    def _add_children(self, lib, parent_item):
        """Add orphan objects and root groups from *lib* under *parent_item*."""
        children = [
            obj
            for obj in (
                list(lib.addresses)
                + list(lib.services)
                + list(lib.intervals)
                + list(lib.devices)
            )
            if obj.group_id is None
        ]
        children += [g for g in lib.groups if g.parent_group_id is None]
        children += [i for i in lib.interfaces if i.device_id is None]
        # Include user-created subfolders stored in lib.data.
        user_subfolders = (getattr(lib, 'data', None) or {}).get('subfolders', [])
        self._add_objects_with_folders(
            children,
            parent_item,
            extra_folders=user_subfolders,
        )

    def _add_object(self, obj, parent_item):
        """Create a tree item for *obj* and recurse into groups / devices."""
        type_str = getattr(obj, 'type', None) or type(obj).__name__
        obj_ro = getattr(obj, 'ro', False)
        effective_ro = self._building_lib_ro or obj_ro
        item = self._make_item(
            _obj_display_name(obj),
            type_str,
            str(obj.id),
            parent_item,
            attrs=_obj_brief_attrs(obj),
            effective_readonly=effective_ro,
            inactive=_is_inactive(obj),
            obj=obj,
            tags=_obj_tags(obj),
        )
        if isinstance(obj, Group):
            self._add_group_children(obj, item)
            if obj.id not in self._groups_with_members:
                item.setIcon(0, QIcon(_CATEGORY_ICON))
        elif isinstance(obj, Host):
            saved_device_ro = self._building_device_ro
            self._building_device_ro = obj_ro
            self._add_device_children(obj, item)
            self._building_device_ro = saved_device_ro

    def _add_group_children(self, group, parent_item):
        """Add child objects and sub-groups of *group*."""
        children = (
            list(group.addresses)
            + list(group.services)
            + list(group.intervals)
            + list(group.devices)
            + list(group.child_groups)
        )
        self._add_objects_with_folders(children, parent_item)

    def _add_objects_with_folders(self, objects, parent_item, *, extra_folders=None):
        """Add *objects* under *parent_item*, grouping by ``data.folder``."""
        sorted_objects = sorted(objects, key=_obj_sort_key)
        # Pre-create folder items (sorted) so they appear above ungrouped objects.
        folder_names = {self._get_folder_name(obj) for obj in sorted_objects} - {''}
        if extra_folders:
            folder_names |= set(extra_folders)
        folder_names = sorted(folder_names, key=str.casefold)
        folder_items = {
            name: self._make_category(name, parent_item) for name in folder_names
        }
        for obj in sorted_objects:
            folder_name = self._get_folder_name(obj)
            target = folder_items[folder_name] if folder_name else parent_item
            self._add_object(obj, target)

    @staticmethod
    def _get_folder_name(obj):
        """Return the folder name for *obj*, or empty string."""
        data = getattr(obj, 'data', None) or {}
        return data.get('folder', '')

    def _add_device_children(self, device, parent_item):
        """Add rule sets and interfaces of *device*."""
        effective_ro = self._building_lib_ro or self._building_device_ro
        for rs in sorted(device.rule_sets, key=_obj_sort_key):
            self._make_item(
                _obj_display_name(rs),
                rs.type,
                str(rs.id),
                parent_item,
                effective_readonly=effective_ro,
                inactive=_is_inactive(rs),
                obj=rs,
            )
        for iface in sorted(device.interfaces, key=lambda o: o.name.lower()):
            self._add_interface(iface, parent_item)

    def _add_interface(self, iface, parent_item):
        """Add an Interface node with its child addresses."""
        effective_ro = self._building_lib_ro or self._building_device_ro
        iface_item = self._make_item(
            _obj_display_name(iface),
            'Interface',
            str(iface.id),
            parent_item,
            attrs=_obj_brief_attrs(iface),
            effective_readonly=effective_ro,
            inactive=_is_inactive(iface),
            obj=iface,
            tags=_obj_tags(iface),
        )
        for addr in sorted(iface.addresses, key=_obj_sort_key):
            self._make_item(
                _obj_display_name(addr),
                addr.type,
                str(addr.id),
                iface_item,
                attrs=_obj_brief_attrs(addr, under_interface=True),
                effective_readonly=effective_ro,
                inactive=_is_inactive(addr),
                obj=addr,
                tags=_obj_tags(addr),
            )

    def _make_category(self, label, parent_item):
        """Create a non-selectable category folder item."""
        item = QTreeWidgetItem(parent_item, [label])
        item.setIcon(0, QIcon(_CATEGORY_ICON))
        return item

    def _make_item(
        self,
        name,
        type_str,
        obj_id,
        parent_item=None,
        *,
        attrs=None,
        effective_readonly=False,
        inactive=False,
        obj=None,
        readonly=False,
        tags=None,
    ):
        """Create a tree item storing id, type, tags, and attrs in user roles."""
        item = QTreeWidgetItem([name])
        item.setData(0, Qt.ItemDataRole.UserRole, obj_id)
        item.setData(0, Qt.ItemDataRole.UserRole + 1, type_str)
        item.setData(0, Qt.ItemDataRole.UserRole + 2, _tags_to_str(tags))
        item.setData(0, Qt.ItemDataRole.UserRole + 3, attrs or '')
        item.setData(0, Qt.ItemDataRole.UserRole + 5, effective_readonly)
        if attrs:
            item.setText(1, attrs)
        if readonly:
            item.setIcon(0, QIcon(_LOCK_ICON))
        else:
            icon_path = ICON_MAP.get(type_str)
            if icon_path:
                item.setIcon(0, QIcon(icon_path))
        if inactive:
            font = item.font(0)
            font.setStrikeOut(True)
            item.setFont(0, font)
        if obj is not None:
            tip = _obj_tooltip(obj)
            item.setData(0, Qt.ItemDataRole.UserRole + 4, tip)
            if self._tooltips_enabled:
                item.setToolTip(0, tip)
                if self._show_attrs:
                    item.setToolTip(1, tip)
        if parent_item is not None:
            parent_item.addChild(item)
        return item

    def update_item(self, obj):
        """Refresh the tree item for *obj* (name, attrs, tooltip, tags)."""
        obj_id = str(obj.id)
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) != obj_id:
                continue

            item.setText(0, _obj_display_name(obj))

            attrs = _obj_brief_attrs(obj)
            item.setData(0, Qt.ItemDataRole.UserRole + 3, attrs)
            item.setText(1, attrs)

            item.setData(0, Qt.ItemDataRole.UserRole + 2, _tags_to_str(_obj_tags(obj)))

            tip = _obj_tooltip(obj)
            item.setData(0, Qt.ItemDataRole.UserRole + 4, tip)
            if self._tooltips_enabled:
                item.setToolTip(0, tip)
                if self._show_attrs:
                    item.setToolTip(1, tip)
            else:
                item.setToolTip(0, '')
                item.setToolTip(1, '')
            return

    def focus_filter(self):
        """Set keyboard focus to the filter input field."""
        self._filter.setFocus()

    def select_object(self, obj_id):
        """Find, expand, scroll to, and select the item with *obj_id*.

        Returns True if the item was found, False otherwise.
        """
        obj_id_str = str(obj_id)
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) == obj_id_str:
                # Expand all ancestors so the item is visible.
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                self._tree.scrollToItem(item)
                self._tree.setCurrentItem(item)
                return True
        return False

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self, text):
        """Hide items whose name does not match *text* (case-insensitive).

        When an item matches, all its descendants are shown too so the
        user can interact with children (e.g. double-click a Policy
        child of a matched Firewall).
        """
        text = text.strip().lower()
        if not text:
            self._reset_visibility()
            return

        # First pass: determine direct match per item.
        matched = set()
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) is None:
                continue
            tags_str = item.data(0, Qt.ItemDataRole.UserRole + 2) or ''
            match = text in item.text(0).lower() or text in tags_str
            if self._show_attrs:
                attrs_str = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
                match = match or text in attrs_str.lower()
            if match:
                matched.add(id(item))

        # Second pass: hide non-matching items, show children of matches.
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) is None:
                continue
            if id(item) in matched or self._has_matched_ancestor(item, matched):
                item.setHidden(False)
            else:
                item.setHidden(True)

        # Ensure parents of visible items are also visible.
        it = QTreeWidgetItemIterator(
            self._tree,
            QTreeWidgetItemIterator.IteratorFlag.NotHidden,
        )
        while it.value():
            item = it.value()
            it += 1
            parent = item.parent()
            while parent:
                parent.setHidden(False)
                parent.setExpanded(True)
                parent = parent.parent()

    @staticmethod
    def _has_matched_ancestor(item, matched):
        """Return True if any ancestor of *item* is in *matched*."""
        parent = item.parent()
        while parent:
            if id(parent) in matched:
                return True
            parent = parent.parent()
        return False

    def _reset_visibility(self):
        """Restore all items to visible."""
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            it.value().setHidden(False)
            it += 1

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _on_double_click(self, item, _column):
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        type_str = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not type_str:
            return
        if type_str in _RULE_SET_TYPES:
            # The firewall is the parent of this rule set node.
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self.rule_set_activated.emit(obj_id, fw_name, item.text(0))
        else:
            self.object_activated.emit(obj_id, type_str)

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def _on_context_menu(self, pos):
        """Build and show the context menu for the right-clicked tree item."""
        item = self._tree.itemAt(pos)
        if item is None:
            return
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)

        # Category folder (no obj_id/obj_type): show only New items.
        if not obj_id or not obj_type:
            self._on_category_context_menu(item, pos)
            return

        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False

        menu = QMenu(self)

        # Edit / Inspect
        label = 'Inspect' if effective_ro else 'Edit'
        edit_action = menu.addAction(label)
        edit_action.triggered.connect(lambda: self._ctx_edit(item))

        # Duplicate ...
        if obj_type not in _NO_DUPLICATE_TYPES:
            libraries = self._get_writable_libraries()
            if len(libraries) == 1:
                dup_action = menu.addAction('Duplicate ...')
                lib_id = libraries[0][0]
                dup_action.triggered.connect(lambda: self._ctx_duplicate(item, lib_id))
            elif libraries:
                dup_menu = menu.addMenu('Duplicate ...')
                for lib_id, lib_name in libraries:
                    act = dup_menu.addAction(f'place in library {lib_name}')
                    act.triggered.connect(
                        lambda checked=False, lid=lib_id: self._ctx_duplicate(item, lid)
                    )
            else:
                dup_action = menu.addAction('Duplicate ...')
                dup_action.setEnabled(False)

        # Move ...
        if obj_type not in _NO_MOVE_TYPES and not effective_ro:
            current_lib_id = self._get_item_library_id(item)
            libraries = [
                (lid, lname)
                for lid, lname in self._get_writable_libraries()
                if lid != current_lib_id
            ]
            if len(libraries) == 1:
                move_action = menu.addAction('Move ...')
                lib_id = libraries[0][0]
                move_action.triggered.connect(lambda: self._ctx_move(item, lib_id))
            elif libraries:
                move_menu = menu.addMenu('Move ...')
                for lib_id, lib_name in libraries:
                    act = move_menu.addAction(f'to library {lib_name}')
                    act.triggered.connect(
                        lambda checked=False, lid=lib_id: self._ctx_move(item, lid)
                    )
            else:
                move_action = menu.addAction('Move ...')
                move_action.setEnabled(False)

        # Copy / Cut / Paste
        menu.addSeparator()

        can_copy = obj_type not in _NO_COPY_TYPES
        copy_action = menu.addAction('Copy')
        copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        copy_action.setEnabled(can_copy)
        copy_action.triggered.connect(lambda: self._ctx_copy(item))

        can_cut = can_copy and not effective_ro
        cut_action = menu.addAction('Cut')
        cut_action.setShortcut(QKeySequence.StandardKey.Cut)
        cut_action.setEnabled(can_cut)
        cut_action.triggered.connect(lambda: self._ctx_cut(item))

        can_paste = _tree_clipboard is not None and not effective_ro
        paste_action = menu.addAction('Paste')
        paste_action.setShortcut(QKeySequence.StandardKey.Paste)
        paste_action.setEnabled(can_paste)
        paste_action.triggered.connect(lambda: self._ctx_paste(item))

        # Delete
        menu.addSeparator()
        can_delete = obj_type not in _NO_DELETE_TYPES and not effective_ro
        delete_action = menu.addAction('Delete')
        delete_action.setShortcut(QKeySequence.StandardKey.Delete)
        delete_action.setEnabled(can_delete)
        delete_action.triggered.connect(lambda: self._ctx_delete(item))

        # New [Type] + New Subfolder (grouped in one section)
        new_types = self._get_new_object_types(item, obj_type)
        show_subfolder = obj_type == 'Library' or obj_type not in _NO_SUBFOLDER_TYPES
        if new_types or show_subfolder:
            menu.addSeparator()
        for type_name, display_name in new_types:
            icon_path = ICON_MAP.get(type_name, '')
            act = menu.addAction(QIcon(icon_path), f'New {display_name}')
            act.setEnabled(not effective_ro)
            act.triggered.connect(
                lambda checked=False, t=type_name: self._ctx_new_object(item, t)
            )
        if show_subfolder:
            sf_action = menu.addAction(
                QIcon(_CATEGORY_ICON),
                'New Subfolder',
            )
            sf_action.setEnabled(not effective_ro)
            sf_action.triggered.connect(lambda: self._ctx_new_subfolder(item))

        menu.exec(self._tree.viewport().mapToGlobal(pos))

    def _on_category_context_menu(self, item, pos):
        """Show a context menu for category folder items (New + Subfolder)."""
        folder_name = item.text(0)
        new_types = _NEW_TYPES_FOR_FOLDER.get(folder_name, [])

        # Determine read-only state from parent library.
        effective_ro = False
        parent = item.parent()
        while parent is not None:
            if parent.data(0, Qt.ItemDataRole.UserRole + 1) == 'Library':
                effective_ro = parent.data(0, Qt.ItemDataRole.UserRole + 5) or False
                break
            parent = parent.parent()

        menu = QMenu(self)

        for type_name, display_name in new_types:
            icon_path = ICON_MAP.get(type_name, '')
            act = menu.addAction(QIcon(icon_path), f'New {display_name}')
            act.setEnabled(not effective_ro)
            act.triggered.connect(
                lambda checked=False, t=type_name: self._ctx_new_object(item, t)
            )

        sf_action = menu.addAction(QIcon(_CATEGORY_ICON), 'New Subfolder')
        sf_action.setEnabled(not effective_ro)
        sf_action.triggered.connect(lambda: self._ctx_new_subfolder(item))

        menu.exec(self._tree.viewport().mapToGlobal(pos))

    def _ctx_edit(self, item):
        """Open the editor for the context-menu item (Edit / Inspect)."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type in _RULE_SET_TYPES:
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self.rule_set_activated.emit(obj_id, fw_name, item.text(0))
        else:
            self.object_activated.emit(obj_id, obj_type)

    # ------------------------------------------------------------------
    # Duplicate
    # ------------------------------------------------------------------

    def _get_writable_libraries(self):
        """Return [(lib_id, lib_name), ...] for non-read-only libraries."""
        if self._db_manager is None:
            return []
        result = []
        with self._db_manager.session() as session:
            for lib in session.scalars(sqlalchemy.select(Library)).all():
                if not lib.ro:
                    result.append((lib.id, lib.name))
        result.sort(key=lambda t: t[1].lower())
        return result

    def _ctx_duplicate(self, item, target_lib_id):
        """Duplicate the object referenced by *item* into *target_lib_id*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        model_cls = _MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        new_id = self._duplicate_object(uuid.UUID(obj_id), model_cls, target_lib_id)
        if new_id is not None:
            self.tree_changed.emit()
            # Select the newly created object.
            QTimer.singleShot(0, lambda: self.select_object(new_id))
            self.object_activated.emit(str(new_id), obj_type)

    def _duplicate_object(
        self,
        source_id,
        model_cls,
        target_lib_id,
        *,
        target_interface_id=None,
        target_group_id=None,
    ):
        """Deep-copy *source_id* into *target_lib_id*. Returns new UUID or None.

        Optional *target_interface_id* / *target_group_id* place the clone
        under a specific interface or group instead of the library root.
        """
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            source = session.get(model_cls, source_id)
            if source is None:
                session.close()
                return None

            id_map = {}
            new_obj = self._clone_object(source, id_map)

            # Clear all parent references first, then set the target.
            if hasattr(new_obj, 'interface_id'):
                new_obj.interface_id = None
            if hasattr(new_obj, 'group_id'):
                new_obj.group_id = None
            if hasattr(new_obj, 'parent_group_id'):
                new_obj.parent_group_id = None

            if target_interface_id is not None and hasattr(new_obj, 'interface_id'):
                new_obj.interface_id = target_interface_id
                # Addresses under interfaces don't carry library_id.
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = None
            elif target_group_id is not None:
                if hasattr(new_obj, 'group_id'):
                    new_obj.group_id = target_group_id
                elif hasattr(new_obj, 'parent_group_id'):
                    new_obj.parent_group_id = target_group_id
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = target_lib_id
            else:
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = target_lib_id

            # Make name unique within the target scope.
            new_obj.name = self._make_name_unique(session, new_obj)

            session.add(new_obj)

            # Deep-copy children for devices (interfaces, rule sets, rules, rule elements).
            if isinstance(source, Host):
                self._duplicate_device_children(session, source, new_obj, id_map)

            # Copy group_membership entries for groups.
            if isinstance(source, Group):
                self._duplicate_group_members(session, source, new_obj)

            session.commit()
            self._db_manager.save_state(f'Duplicate {source.type} {source.name}')
            new_id = new_obj.id
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

    @staticmethod
    def _clone_object(source, id_map):
        """Create a detached copy of *source* with a new UUID.

        All scalar/JSON column attributes are deep-copied.
        *id_map* is updated with ``{old_id: new_id}``.
        """
        mapper = sqlalchemy.inspect(type(source))
        new_id = uuid.uuid4()
        id_map[source.id] = new_id
        kwargs = {}
        for attr in mapper.column_attrs:
            key = attr.key
            if key == 'id':
                continue
            val = getattr(source, key)
            if isinstance(val, (dict, list, set)):
                val = copy.deepcopy(val)
            kwargs[key] = val
        return type(source)(id=new_id, **kwargs)

    def _duplicate_device_children(self, session, source_device, new_device, id_map):
        """Recursively duplicate interfaces, addresses, rule sets, rules, and rule elements."""
        # Interfaces + their child addresses.
        for iface in source_device.interfaces:
            new_iface = self._clone_object(iface, id_map)
            new_iface.device_id = new_device.id
            new_iface.library_id = new_device.library_id
            session.add(new_iface)
            for addr in iface.addresses:
                new_addr = self._clone_object(addr, id_map)
                new_addr.interface_id = new_iface.id
                new_addr.library_id = None
                new_addr.group_id = None
                session.add(new_addr)

        # Rule sets + their rules + rule_elements.
        for rs in source_device.rule_sets:
            new_rs = self._clone_object(rs, id_map)
            new_rs.device_id = new_device.id
            session.add(new_rs)
            for rule in rs.rules:
                new_rule = self._clone_object(rule, id_map)
                new_rule.rule_set_id = new_rs.id
                session.add(new_rule)
                # Copy rule_elements, remapping target_id for internal refs.
                rows = session.execute(
                    sqlalchemy.select(rule_elements).where(
                        rule_elements.c.rule_id == rule.id
                    )
                ).all()
                for row in rows:
                    target_id = id_map.get(row.target_id, row.target_id)
                    session.execute(
                        rule_elements.insert().values(
                            rule_id=new_rule.id,
                            slot=row.slot,
                            target_id=target_id,
                            position=row.position,
                        )
                    )

    @staticmethod
    def _duplicate_group_members(session, source_group, new_group):
        """Copy group_membership entries from *source_group* to *new_group*."""
        rows = session.execute(
            sqlalchemy.select(group_membership).where(
                group_membership.c.group_id == source_group.id
            )
        ).all()
        for row in rows:
            session.execute(
                group_membership.insert().values(
                    group_id=new_group.id,
                    member_id=row.member_id,
                    position=row.position,
                )
            )

    # ------------------------------------------------------------------
    # Move
    # ------------------------------------------------------------------

    @staticmethod
    def _get_item_library_id(item):
        """Walk up the tree to find the Library ancestor and return its UUID."""
        current = item
        while current is not None:
            if current.data(0, Qt.ItemDataRole.UserRole + 1) == 'Library':
                obj_id = current.data(0, Qt.ItemDataRole.UserRole)
                if obj_id:
                    return uuid.UUID(obj_id)
                return None
            current = current.parent()
        return None

    @staticmethod
    def _get_paste_context(item):
        """Determine the paste target from *item*'s position in the tree.

        Returns ``(interface_id, group_id)`` — at most one is non-None.
        If both are None the paste lands at the library root.
        """
        # Walk from the clicked item upwards to find the nearest container.
        current = item
        while current is not None:
            obj_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            obj_id = current.data(0, Qt.ItemDataRole.UserRole)
            if obj_type == 'Interface' and obj_id:
                return uuid.UUID(obj_id), None
            if obj_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup') and obj_id:
                return None, uuid.UUID(obj_id)
            if obj_type == 'Library':
                break
            # Skip devices and rule sets — paste on a firewall means
            # library root, not inside the device.
            if obj_type in (
                'Cluster',
                'Firewall',
                'Host',
                'NAT',
                'Policy',
                'Routing',
            ):
                break
            current = current.parent()
        return None, None

    def _ctx_move(self, item, target_lib_id):
        """Move the object referenced by *item* to *target_lib_id*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        model_cls = _MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        if self._move_object(uuid.UUID(obj_id), model_cls, target_lib_id):
            self.tree_changed.emit()
            QTimer.singleShot(0, lambda: self.select_object(uuid.UUID(obj_id)))

    def _move_object(self, obj_id, model_cls, target_lib_id):
        """Move *obj_id* to *target_lib_id*. Returns True on success."""
        if self._db_manager is None:
            return False

        session = self._db_manager.create_session()
        try:
            obj = session.get(model_cls, obj_id)
            if obj is None:
                session.close()
                return False

            obj_name = obj.name
            obj_type = getattr(obj, 'type', type(obj).__name__)
            obj.library_id = target_lib_id

            # Clear group/parent ownership — object lands at the library root.
            if hasattr(obj, 'group_id'):
                obj.group_id = None
            if hasattr(obj, 'parent_group_id'):
                obj.parent_group_id = None

            # For devices, also move child interfaces.
            if isinstance(obj, Host):
                for iface in obj.interfaces:
                    iface.library_id = target_lib_id

            session.commit()
            self._db_manager.save_state(f'Move {obj_type} {obj_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return True

    # ------------------------------------------------------------------
    # Copy / Cut / Paste
    # ------------------------------------------------------------------

    @staticmethod
    def _ctx_copy(item):
        """Copy the object reference to the tree and policy-view clipboards."""
        global _tree_clipboard
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_id and obj_type:
            _tree_clipboard = {'id': obj_id, 'type': obj_type, 'cut': False}
            # Also populate the policy-view object clipboard so that
            # paste into rule element cells works across components.
            from firewallfabrik.gui.policy_view import PolicyView

            PolicyView._object_clipboard = {
                'id': obj_id,
                'name': item.text(0),
                'type': obj_type,
            }

    @staticmethod
    def _ctx_cut(item):
        """Cut the object reference to the module-level clipboard.

        Also populates the policy-view clipboard (like Copy) so that
        paste into rule element cells works across components.
        """
        global _tree_clipboard
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_id and obj_type:
            _tree_clipboard = {'id': obj_id, 'type': obj_type, 'cut': True}
            from firewallfabrik.gui.policy_view import PolicyView

            PolicyView._object_clipboard = {
                'id': obj_id,
                'name': item.text(0),
                'type': obj_type,
            }

    def _ctx_paste(self, item):
        """Paste the clipboard object relative to *item*.

        Copy-paste duplicates; cut-paste moves.
        The paste target is determined by *item*'s position in the tree:
        paste on/near an Interface → under that interface; on/near a
        Group → under that group; otherwise → library root.
        """
        global _tree_clipboard
        if _tree_clipboard is None or self._db_manager is None:
            return

        cb = _tree_clipboard
        cb_id = uuid.UUID(cb['id'])
        cb_type = cb['type']
        model_cls = _MODEL_MAP.get(cb_type)
        if model_cls is None:
            return

        target_lib_id = self._get_item_library_id(item)
        if target_lib_id is None:
            return

        target_iface_id, target_group_id = self._get_paste_context(item)

        if cb['cut']:
            # Cut-paste = move to target library.
            if self._move_object(cb_id, model_cls, target_lib_id):
                _tree_clipboard = None
                self.tree_changed.emit()
                QTimer.singleShot(0, lambda: self.select_object(cb_id))
        else:
            # Copy-paste = duplicate into target context.
            new_id = self._duplicate_object(
                cb_id,
                model_cls,
                target_lib_id,
                target_interface_id=target_iface_id,
                target_group_id=target_group_id,
            )
            if new_id is not None:
                self.tree_changed.emit()
                QTimer.singleShot(0, lambda: self.select_object(new_id))
                self.object_activated.emit(str(new_id), cb_type)

    def _shortcut_copy(self):
        """Handle Ctrl+C on the currently selected tree item."""
        item = self._tree.currentItem()
        if item is None:
            return
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type and obj_type not in _NO_COPY_TYPES:
            self._ctx_copy(item)

    def _shortcut_cut(self):
        """Handle Ctrl+X on the currently selected tree item."""
        item = self._tree.currentItem()
        if item is None:
            return
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if obj_type and obj_type not in _NO_COPY_TYPES and not effective_ro:
            self._ctx_cut(item)

    def _shortcut_paste(self):
        """Handle Ctrl+V — paste into the selected item's library."""
        item = self._tree.currentItem()
        if item is None:
            return
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if not effective_ro:
            self._ctx_paste(item)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def _ctx_delete(self, item):
        """Delete the object referenced by *item* after confirmation.

        Mimics fwbuilder's ``ObjectManipulator::delObj()``:
        shows a confirmation dialog listing all groups and rules that
        reference the object, then removes those references and deletes
        the object itself.
        """
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        model_cls = _MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        obj_name = item.text(0)

        # Collect references for the confirmation dialog.
        ref_lines = self._find_references(uuid.UUID(obj_id))

        # Build confirmation message.
        msg = f"Delete '{obj_name}'?"
        if ref_lines:
            msg += (
                '\n\nThis object is referenced in the following places. '
                'All references will be removed:\n\n' + '\n'.join(ref_lines)
            )

        result = QMessageBox.question(
            self,
            'Delete',
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        if self._delete_object(uuid.UUID(obj_id), model_cls, obj_name, obj_type):
            self.tree_changed.emit()

    def _find_references(self, obj_id):
        """Return a list of human-readable strings describing references to *obj_id*.

        Searches group_membership and rule_elements tables.
        Also recursively checks children (interfaces, addresses) of
        devices so that references to children are reported.
        """
        if self._db_manager is None:
            return []

        lines = []
        with self._db_manager.session() as session:
            ids_to_check = self._collect_child_ids(session, obj_id)
            ids_to_check.add(obj_id)

            for check_id in ids_to_check:
                # Groups containing this object.
                grp_rows = session.execute(
                    sqlalchemy.select(group_membership.c.group_id).where(
                        group_membership.c.member_id == check_id
                    )
                ).all()
                for (grp_id,) in grp_rows:
                    grp = session.get(Group, grp_id)
                    if grp is not None:
                        lines.append(f'  Group: {grp.name}')

                # Rules referencing this object.
                from firewallfabrik.core.objects import Rule, RuleSet

                rule_rows = session.execute(
                    sqlalchemy.select(
                        rule_elements.c.slot,
                        Rule.position,
                        Rule.rule_set_id,
                    )
                    .join(Rule, Rule.id == rule_elements.c.rule_id)
                    .where(rule_elements.c.target_id == check_id)
                ).all()
                for slot, position, rule_set_id in rule_rows:
                    rs = session.get(RuleSet, rule_set_id)
                    if rs is not None:
                        fw_name = rs.device.name if rs.device else '?'
                        lines.append(
                            f'  {fw_name} / {rs.type} / Rule #{position} / {slot}'
                        )

        # Deduplicate and sort for readability.
        return sorted(set(lines))

    @staticmethod
    def _collect_child_ids(session, obj_id):
        """Collect IDs of all children (interfaces, addresses) of a device."""
        child_ids = set()
        # Check if it's a device with interfaces.
        obj = session.get(Host, obj_id)
        if obj is not None:
            for iface in obj.interfaces:
                child_ids.add(iface.id)
                for addr in iface.addresses:
                    child_ids.add(addr.id)
        # Check if it's an interface with addresses.
        iface = session.get(Interface, obj_id)
        if iface is not None:
            for addr in iface.addresses:
                child_ids.add(addr.id)
        return child_ids

    def _delete_object(self, obj_id, model_cls, obj_name, obj_type):
        """Delete *obj_id* and clean up all references.  Returns True on success."""
        if self._db_manager is None:
            return False

        session = self._db_manager.create_session()
        try:
            obj = session.get(model_cls, obj_id)
            if obj is None:
                session.close()
                return False

            child_ids = self._collect_child_ids(session, obj_id)
            all_ids = child_ids | {obj_id}

            # Remove from group_membership (as member).
            for del_id in all_ids:
                session.execute(
                    group_membership.delete().where(
                        group_membership.c.member_id == del_id
                    )
                )

            # Remove from rule_elements.
            for del_id in all_ids:
                session.execute(
                    rule_elements.delete().where(rule_elements.c.target_id == del_id)
                )

            # Delete child addresses of interfaces.
            if isinstance(obj, Host):
                for iface in obj.interfaces:
                    for addr in iface.addresses:
                        session.delete(addr)
                    session.delete(iface)
                # Delete rule sets, rules, and rule elements.
                for rs in obj.rule_sets:
                    for rule in rs.rules:
                        session.execute(
                            rule_elements.delete().where(
                                rule_elements.c.rule_id == rule.id
                            )
                        )
                        session.delete(rule)
                    session.delete(rs)
            elif isinstance(obj, Interface):
                for addr in obj.addresses:
                    session.delete(addr)
            elif isinstance(obj, Group):
                # Remove group_membership rows where this group is the group.
                session.execute(
                    group_membership.delete().where(
                        group_membership.c.group_id == obj_id
                    )
                )

            session.delete(obj)
            session.commit()
            self._db_manager.save_state(f'Delete {obj_type} {obj_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return True

    def _shortcut_delete(self):
        """Handle Delete key on the currently selected tree item."""
        item = self._tree.currentItem()
        if item is None:
            return
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if obj_type and obj_type not in _NO_DELETE_TYPES and not effective_ro:
            self._ctx_delete(item)

    # ------------------------------------------------------------------
    # New [Type]
    # ------------------------------------------------------------------

    def _get_new_object_types(self, item, obj_type):
        """Return a list of ``(type_name, display_name)`` for the New menu.

        Matches fwbuilder's context menu logic strictly:

        - Devices (Cluster/Firewall/Host) → fixed child types only.
        - Interface → dynamic list (addresses, subinterface, etc.).
        - Rule sets (Policy/NAT/Routing) → no "New" items.
        - Library → no "New" items (only subfolder, handled elsewhere).
        - Objects in category folders → folder-based items.
        - Objects under devices/interfaces → no "New" items.
        """
        # Devices: fixed child types only.
        if obj_type in ('Cluster', 'Firewall', 'Host'):
            return list(_NEW_TYPES_FOR_PARENT.get(obj_type, []))

        # Interface: dynamic list based on parent and existing children.
        if obj_type == 'Interface':
            return self._get_interface_new_types(item)

        # Rule sets and Library: no "New" items.
        if obj_type in ('Library', *_RULE_SET_TYPES):
            return []

        # All other objects: only get folder-based items if they live
        # directly under a category folder.  Objects under devices or
        # interfaces get nothing (matches fwbuilder's strict path check).
        folder = self._find_folder_context(item)
        if folder is not None:
            return list(_NEW_TYPES_FOR_FOLDER.get(folder, []))

        return []

    @staticmethod
    def _find_folder_context(item):
        """Walk up the tree to find the enclosing category folder.

        Returns the folder name string, or ``None`` if the item lives
        under a device or interface (where no folder-based "New" items
        are offered).
        """
        current = item.parent()
        while current is not None:
            current_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            if current_type is None:
                # Category folder (no obj_id/obj_type) — this is what we want.
                return current.text(0)
            if current_type in ('Cluster', 'Firewall', 'Host', 'Interface'):
                # Under a device or interface — no folder-based items.
                return None
            if current_type == 'Library':
                # Directly under library without a category folder.
                return None
            current = current.parent()

        return None

    @staticmethod
    def _get_interface_new_types(item):
        """Build the dynamic "New" list for an Interface item.

        Matches fwbuilder's logic:
        - New Interface (subinterface): only for Firewall interfaces
        - New Address (IPv4), New Address IPv6 (IPv6): always
        - New MAC Address (PhysAddress): always
        - New Attached Networks: only if not already present
        - New Failover Group: only for Cluster interfaces, if not
          already present
        """
        result = []

        # Determine parent device type.
        parent = item.parent()
        parent_type = parent.data(0, Qt.ItemDataRole.UserRole + 1) if parent else None

        # Subinterface: only for Firewall interfaces.
        if parent_type == 'Firewall':
            result.append(('Interface', 'Interface'))

        # Standard address types — always offered.
        result.append(('IPv4', 'Address'))
        result.append(('IPv6', 'Address IPv6'))
        result.append(('PhysAddress', 'MAC Address'))

        # Check existing children in the tree to suppress singleton items.
        has_attached = False
        has_failover = False
        for i in range(item.childCount()):
            child_type = item.child(i).data(0, Qt.ItemDataRole.UserRole + 1)
            if child_type == 'AttachedNetworks':
                has_attached = True
            elif child_type == 'FailoverClusterGroup':
                has_failover = True

        if not has_attached:
            result.append(('AttachedNetworks', 'Attached Networks'))

        if parent_type == 'Cluster' and not has_failover:
            result.append(('FailoverClusterGroup', 'Failover Group'))

        return result

    def _ctx_new_object(self, item, type_name):
        """Create a new object of *type_name* in the context of *item*."""
        if self._db_manager is None:
            return
        model_cls = _MODEL_MAP.get(type_name)
        if model_cls is None:
            return

        # Determine where to place the new object.
        lib_id = self._get_item_library_id(item)
        if lib_id is None:
            return

        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)

        # Figure out the parent context.
        interface_id = None
        parent_interface_id = None
        device_id = None
        folder = None

        if obj_type == 'Interface' and obj_id:
            if issubclass(model_cls, Address):
                interface_id = uuid.UUID(obj_id)
            elif issubclass(model_cls, Interface):
                # Sub-interface: set parent_interface_id and find device.
                parent_interface_id = uuid.UUID(obj_id)
                parent = item.parent()
                if parent:
                    pid = parent.data(0, Qt.ItemDataRole.UserRole)
                    if pid:
                        device_id = uuid.UUID(pid)
            # Groups (AttachedNetworks, FailoverClusterGroup) created
            # at library level — no special parent ref needed.
        elif obj_type in ('Cluster', 'Firewall', 'Host') and obj_id:
            if issubclass(model_cls, Interface) or issubclass(model_cls, RuleSet):
                device_id = uuid.UUID(obj_id)
        elif obj_type == 'Library':
            pass  # Library root — folder will be set from type.
        elif obj_type is None:
            # Category folder — the item text IS the folder name.
            folder = item.text(0)
        else:
            # Walk up to find device or interface context.
            parent = item.parent()
            while parent is not None:
                pt = parent.data(0, Qt.ItemDataRole.UserRole + 1)
                pid = parent.data(0, Qt.ItemDataRole.UserRole)
                if pt == 'Interface' and pid and issubclass(model_cls, Address):
                    interface_id = uuid.UUID(pid)
                    break
                if pt in ('Cluster', 'Firewall', 'Host') and pid:
                    if issubclass(model_cls, Interface):
                        device_id = uuid.UUID(pid)
                    break
                if pt == 'Library':
                    break
                # Category folder — remember its name for data.folder.
                if pt is None:
                    folder = parent.text(0)
                parent = parent.parent()

        # If no explicit folder, derive from type.
        if folder is None and interface_id is None and device_id is None:
            for f, type_list in _NEW_TYPES_FOR_FOLDER.items():
                if any(tn == type_name for tn, _dn in type_list):
                    folder = f
                    break

        new_id = self._create_new_object(
            model_cls,
            type_name,
            lib_id,
            device_id=device_id,
            folder=folder,
            interface_id=interface_id,
            parent_interface_id=parent_interface_id,
        )
        if new_id is not None:
            self.tree_changed.emit()
            QTimer.singleShot(0, lambda: self.select_object(new_id))
            self.object_activated.emit(str(new_id), type_name)

    def _create_new_object(
        self,
        model_cls,
        type_name,
        lib_id,
        *,
        device_id=None,
        folder=None,
        interface_id=None,
        parent_interface_id=None,
    ):
        """Create a new object and return its UUID, or None on failure."""
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            new_id = uuid.uuid4()
            kwargs = {'id': new_id, 'type': type_name}

            # Set parent references based on context.
            if interface_id is not None and hasattr(model_cls, 'interface_id'):
                kwargs['interface_id'] = interface_id
            elif parent_interface_id is not None and hasattr(
                model_cls, 'parent_interface_id'
            ):
                kwargs['parent_interface_id'] = parent_interface_id
                if device_id is not None and hasattr(model_cls, 'device_id'):
                    kwargs['device_id'] = device_id
                kwargs['library_id'] = lib_id
            elif device_id is not None and hasattr(model_cls, 'device_id'):
                kwargs['device_id'] = device_id
                kwargs['library_id'] = lib_id
            else:
                if hasattr(model_cls, 'library_id'):
                    kwargs['library_id'] = lib_id

            # Set data.folder for proper tree placement.
            if folder and hasattr(model_cls, 'data'):
                kwargs['data'] = {'folder': folder}

            new_obj = model_cls(**kwargs)
            new_obj.name = f'New {type_name}'

            # Make name unique.
            new_obj.name = self._make_name_unique(session, new_obj)

            session.add(new_obj)
            session.commit()
            self._db_manager.save_state(f'New {type_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

    # ------------------------------------------------------------------
    # New Subfolder
    # ------------------------------------------------------------------

    def _ctx_new_subfolder(self, item):
        """Prompt for a subfolder name and create it under *item*.

        User subfolders are stored in the Library's ``data.subfolders``
        list, matching fwbuilder's ``addSubfolderSlot()`` approach.
        """
        if self._db_manager is None:
            return

        name, ok = QInputDialog.getText(
            self._tree,
            'New Subfolder',
            'Enter subfolder name:',
        )
        name = name.strip() if ok else ''
        if not name:
            return
        if ',' in name:
            QMessageBox.warning(
                self._tree,
                'New Subfolder',
                'Subfolder name cannot contain a comma.',
            )
            return

        # Find the library for this item.
        lib_id = self._get_item_library_id(item)
        if lib_id is None:
            return

        session = self._db_manager.create_session()
        try:
            lib = session.get(Library, lib_id)
            if lib is None:
                return
            data = dict(lib.data or {})
            subfolders = list(data.get('subfolders', []))
            if name in subfolders:
                return  # Already exists.
            subfolders.append(name)
            subfolders.sort(key=str.casefold)
            data['subfolders'] = subfolders
            lib.data = data
            session.commit()
            self._db_manager.save_state(f'New subfolder "{name}"')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self.tree_changed.emit()

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_name_unique(session, obj):
        """Return a unique name like 'name-1', 'name-2', etc.

        Queries the appropriate table for existing names to find the
        next available suffix.
        """
        base_name = obj.name
        model_cls = type(obj)

        # Collect existing names in the same scope.
        stmt = sqlalchemy.select(model_cls.name).where(
            model_cls.name.like(f'{base_name}%')
        )
        if hasattr(obj, 'library_id') and obj.library_id is not None:
            stmt = stmt.where(model_cls.library_id == obj.library_id)
        existing = set(session.scalars(stmt).all())

        suffix = 1
        while True:
            candidate = f'{base_name}-{suffix}'
            if candidate not in existing:
                return candidate
            suffix += 1
