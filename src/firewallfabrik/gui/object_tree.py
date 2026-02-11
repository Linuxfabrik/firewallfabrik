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

import sqlalchemy
from PySide6.QtCore import QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QHeaderView,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.core.objects import (
    Firewall,
    Library,
)

# Map ORM type discriminator strings to QRC icon aliases.
ICON_MAP = {
    'AddressRange': ':/Icons/AddressRange/icon-tree',
    'Cluster': ':/Icons/Cluster/icon-tree',
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
    'Policy': ':/Icons/Policy/icon-tree',
    'Routing': ':/Icons/Routing/icon-tree',
    'ServiceGroup': ':/Icons/ServiceGroup/icon-tree',
    'TCPService': ':/Icons/TCPService/icon-tree',
    'UDPService': ':/Icons/UDPService/icon-tree',
}

_CATEGORY_ICON = ':/Icons/SystemGroup/icon-tree'
_LOCK_ICON = ':/Icons/lock'

# fwbuilder groups services by type into sub-categories.
_SERVICE_TYPE_CATEGORY = {
    'CustomService': 'Custom',
    'ICMP6Service': 'ICMP',
    'ICMPService': 'ICMP',
    'IPService': 'IP',
    'TagService': 'TagServices',
    'TCPService': 'TCP',
    'UDPService': 'UDP',
    'UserService': 'Users',
}


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
            return f'{platform}({version}) / {host_os}'
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
        protocol = getattr(obj, 'protocol', None)
        if protocol is not None:
            return f'protocol: {protocol}'
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


# Rule set types that can be opened via double-click.
_RULE_SET_TYPES = frozenset({'Policy', 'NAT', 'Routing'})


class ObjectTree(QWidget):
    """Left-hand object tree panel with filter field and library selector."""

    rule_set_activated = Signal(str, str, str)
    """Emitted when a rule set node is double-clicked: (rule_set_id, firewall_name, rule_set_name)."""

    object_activated = Signal(str, str)
    """Emitted when a non-rule-set object is double-clicked: (obj_id, obj_type)."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText('Filter...')
        self._filter.setClearButtonEnabled(True)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(['Object', 'Attribute'])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._filter)
        layout.addWidget(self._tree)

        self._show_attrs = QSettings().value(
            'UI/ShowObjectsAttributesInTree', True, type=bool
        )
        self._applying_saved_width = False
        self._apply_column_setup()

        self._tree.header().sectionResized.connect(self._on_section_resized)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        self._filter.textChanged.connect(self._apply_filter)

    def populate(self, session):
        """Build the tree from all libraries in *session*."""
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

        for lib in libraries:
            lib_item = self._make_item(
                lib.name,
                'Library',
                str(lib.id),
                attrs=_obj_brief_attrs(lib),
                readonly=getattr(lib, 'ro', False),
            )
            self._tree.addTopLevelItem(lib_item)
            self._add_devices(lib, lib_item)
            self._add_category(lib.addresses, 'Addresses', lib_item)
            self._add_services(lib.services, lib_item)
            self._add_category(lib.groups, 'Groups', lib_item)
            self._add_category(lib.intervals, 'Time', lib_item)
            # Collapse "Standard" by default, expand everything else.
            lib_item.setExpanded(lib.name != 'Standard')

        # Defer column setup so Qt has finished layout/painting first;
        # otherwise ResizeToContents computes zero width for column 1.
        QTimer.singleShot(0, self._apply_column_setup)

    def set_show_attrs(self, show):
        """Toggle the attribute column visibility."""
        self._show_attrs = show
        self._apply_column_setup()

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

    def _add_devices(self, library, parent_item):
        """Add Firewalls and Hosts categories under *parent_item*."""
        firewalls = sorted(
            (d for d in library.devices if isinstance(d, Firewall)),
            key=_obj_sort_key,
        )
        hosts = sorted(
            (d for d in library.devices if not isinstance(d, Firewall)),
            key=_obj_sort_key,
        )

        if firewalls:
            fw_cat = self._make_category('Firewalls', parent_item)
            # Create folder items first (sorted) so they appear above ungrouped devices.
            folder_items = self._build_folder_items(firewalls, fw_cat)
            for fw in firewalls:
                target = self._folder_target(fw, fw_cat, folder_items)
                fw_item = self._make_item(
                    _obj_display_name(fw),
                    fw.type,
                    str(fw.id),
                    target,
                    attrs=_obj_brief_attrs(fw),
                    inactive=_is_inactive(fw),
                    tags=_obj_tags(fw),
                )
                for rs in sorted(fw.rule_sets, key=_obj_sort_key):
                    self._make_item(
                        _obj_display_name(rs),
                        rs.type,
                        str(rs.id),
                        fw_item,
                        inactive=_is_inactive(rs),
                    )
                for iface in sorted(fw.interfaces, key=lambda o: o.name.lower()):
                    self._add_interface(iface, fw_item)
            fw_cat.setExpanded(True)

        if hosts:
            host_cat = self._make_category('Hosts', parent_item)
            # Create folder items first (sorted) so they appear above ungrouped devices.
            folder_items = self._build_folder_items(hosts, host_cat)
            for host in hosts:
                target = self._folder_target(host, host_cat, folder_items)
                host_item = self._make_item(
                    _obj_display_name(host),
                    host.type,
                    str(host.id),
                    target,
                    attrs=_obj_brief_attrs(host),
                    inactive=_is_inactive(host),
                    tags=_obj_tags(host),
                )
                for iface in sorted(host.interfaces, key=lambda o: o.name.lower()):
                    self._add_interface(iface, host_item)

    def _add_services(self, services, parent_item):
        """Add Services category with type-based sub-categories (TCP, UDP, …)."""
        if not services:
            return
        svc_cat = self._make_category('Services', parent_item)
        # Group services by type category.
        by_type_cat = {}
        for svc in services:
            type_str = getattr(svc, 'type', type(svc).__name__)
            cat_name = _SERVICE_TYPE_CATEGORY.get(type_str, type_str)
            by_type_cat.setdefault(cat_name, []).append(svc)
        for cat_name in sorted(by_type_cat, key=str.casefold):
            type_cat = self._make_category(cat_name, svc_cat)
            self._add_objects_with_folders(by_type_cat[cat_name], type_cat)

    def _add_interface(self, iface, parent_item):
        """Add an Interface node with its child addresses."""
        iface_item = self._make_item(
            _obj_display_name(iface),
            'Interface',
            str(iface.id),
            attrs=_obj_brief_attrs(iface),
            inactive=_is_inactive(iface),
            tags=_obj_tags(iface),
        )
        parent_item.addChild(iface_item)
        for addr in sorted(iface.addresses, key=_obj_sort_key):
            self._make_item(
                _obj_display_name(addr),
                addr.type,
                str(addr.id),
                iface_item,
                attrs=_obj_brief_attrs(addr, under_interface=True),
                inactive=_is_inactive(addr),
                tags=_obj_tags(addr),
            )

    def _add_category(self, objects, label, parent_item):
        """Add a category folder with child object nodes."""
        if not objects:
            return
        cat = self._make_category(label, parent_item)
        self._add_objects_with_folders(objects, cat)

    def _add_objects_with_folders(self, objects, parent_item):
        """Add objects to parent, grouping into folder sub-items where set."""
        sorted_objects = sorted(objects, key=_obj_sort_key)
        # Create folder items first (sorted) so they appear above ungrouped objects.
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
            type_str = getattr(obj, 'type', type(obj).__name__)
            self._make_item(
                _obj_display_name(obj),
                type_str,
                str(obj.id),
                target,
                attrs=_obj_brief_attrs(obj),
                inactive=_is_inactive(obj),
                tags=_obj_tags(obj),
            )

    @staticmethod
    def _get_folder_name(obj):
        """Return the folder name for *obj*, or empty string."""
        data = getattr(obj, 'data', None) or {}
        return data.get('folder', '')

    def _build_folder_items(self, objects, parent_item):
        """Pre-create sorted folder items for *objects* under *parent_item*."""
        folder_names = sorted(
            {self._get_folder_name(obj) for obj in objects} - {''}, key=str.casefold
        )
        return {name: self._make_category(name, parent_item) for name in folder_names}

    def _folder_target(self, obj, default_parent, folder_cache):
        """Return the folder item for *obj*, creating it if needed."""
        folder_name = self._get_folder_name(obj)
        if not folder_name:
            return default_parent
        if folder_name not in folder_cache:
            folder_cache[folder_name] = self._make_category(
                folder_name,
                default_parent,
            )
        return folder_cache[folder_name]

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
        if parent_item is not None:
            parent_item.addChild(item)
        return item

    def update_item_tags(self, obj_id, tags):
        """Update the stored tags for the tree item matching *obj_id*."""
        tags_str = _tags_to_str(tags)
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) == obj_id:
                item.setData(0, Qt.ItemDataRole.UserRole + 2, tags_str)
                return

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self, text):
        """Hide items whose name does not match *text* (case-insensitive)."""
        text = text.strip().lower()
        if not text:
            self._reset_visibility()
            return

        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            # Category items (no UserRole data) stay visible if any child matches.
            if item.data(0, Qt.ItemDataRole.UserRole) is None:
                continue
            tags_str = item.data(0, Qt.ItemDataRole.UserRole + 2) or ''
            match = text in item.text(0).lower() or text in tags_str
            if self._show_attrs:
                attrs_str = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
                match = match or text in attrs_str.lower()
            item.setHidden(not match)

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
