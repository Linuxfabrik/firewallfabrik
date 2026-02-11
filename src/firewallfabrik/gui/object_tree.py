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

import json
from datetime import UTC, datetime

import sqlalchemy
from PySide6.QtCore import QMimeData, QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.core.objects import (
    Group,
    Host,
    Library,
    group_membership,
)
from firewallfabrik.gui.policy_model import FWF_MIME_TYPE

# Map ORM type discriminator strings to QRC icon aliases.
ICON_MAP = {
    'AddressRange': ':/Icons/AddressRange/icon-tree',
    'AddressTable': ':/Icons/AddressTable/icon-tree',
    'Cluster': ':/Icons/Cluster/icon-tree',
    'CustomService': ':/Icons/CustomService/icon-tree',
    'DNSName': ':/Icons/DNSName/icon-tree',
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


class ObjectTree(QWidget):
    """Left-hand object tree panel with filter field and library selector."""

    rule_set_activated = Signal(str, str, str)
    """Emitted when a rule set node is double-clicked: (rule_set_id, firewall_name, rule_set_name)."""

    object_activated = Signal(str, str)
    """Emitted when a non-rule-set object is double-clicked: (obj_id, obj_type)."""

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

        self._groups_with_members = set(
            session.scalars(
                sqlalchemy.select(group_membership.c.group_id).distinct(),
            ).all()
        )

        for lib in libraries:
            lib_item = self._make_item(
                lib.name,
                'Library',
                str(lib.id),
                attrs=_obj_brief_attrs(lib),
                obj=lib,
                readonly=getattr(lib, 'ro', False),
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
        self._add_objects_with_folders(children, parent_item)

    def _add_object(self, obj, parent_item):
        """Create a tree item for *obj* and recurse into groups / devices."""
        type_str = getattr(obj, 'type', None) or type(obj).__name__
        item = self._make_item(
            _obj_display_name(obj),
            type_str,
            str(obj.id),
            parent_item,
            attrs=_obj_brief_attrs(obj),
            inactive=_is_inactive(obj),
            obj=obj,
            tags=_obj_tags(obj),
        )
        if isinstance(obj, Group):
            self._add_group_children(obj, item)
            if obj.id not in self._groups_with_members:
                item.setIcon(0, QIcon(_CATEGORY_ICON))
        elif isinstance(obj, Host):
            self._add_device_children(obj, item)

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

    def _add_objects_with_folders(self, objects, parent_item):
        """Add *objects* under *parent_item*, grouping by ``data.folder``."""
        sorted_objects = sorted(objects, key=_obj_sort_key)
        # Pre-create folder items (sorted) so they appear above ungrouped objects.
        folder_names = sorted(
            {self._get_folder_name(obj) for obj in sorted_objects} - {''},
            key=str.casefold,
        )
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
        for rs in sorted(device.rule_sets, key=_obj_sort_key):
            self._make_item(
                _obj_display_name(rs),
                rs.type,
                str(rs.id),
                parent_item,
                inactive=_is_inactive(rs),
                obj=rs,
            )
        for iface in sorted(device.interfaces, key=lambda o: o.name.lower()):
            self._add_interface(iface, parent_item)

    def _add_interface(self, iface, parent_item):
        """Add an Interface node with its child addresses."""
        iface_item = self._make_item(
            _obj_display_name(iface),
            'Interface',
            str(iface.id),
            parent_item,
            attrs=_obj_brief_attrs(iface),
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
