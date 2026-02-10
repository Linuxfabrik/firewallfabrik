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
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

from firewallfabrik.core.objects import (
    Firewall,
    Library,
    NAT,
    Policy,
    Routing,
)

# Map ORM type discriminator strings to QRC icon aliases.
ICON_MAP = {
    'Library': ':/Icons/Library/icon-tree',
    'Firewall': ':/Icons/Firewall/icon-tree',
    'Cluster': ':/Icons/Cluster/icon-tree',
    'Host': ':/Icons/Host/icon-tree',
    'Policy': ':/Icons/Policy/icon-tree',
    'NAT': ':/Icons/NAT/icon-tree',
    'Routing': ':/Icons/Routing/icon-tree',
    'Interface': ':/Icons/Interface/icon-tree',
    'IPv4': ':/Icons/IPv4/icon-tree',
    'IPv6': ':/Icons/IPv6/icon-tree',
    'Network': ':/Icons/Network/icon-tree',
    'NetworkIPv6': ':/Icons/NetworkIPv6/icon-tree',
    'AddressRange': ':/Icons/AddressRange/icon-tree',
    'TCPService': ':/Icons/TCPService/icon-tree',
    'UDPService': ':/Icons/UDPService/icon-tree',
    'ICMPService': ':/Icons/ICMPService/icon-tree',
    'ICMP6Service': ':/Icons/ICMP6Service/icon-tree',
    'IPService': ':/Icons/IPService/icon-tree',
    'ObjectGroup': ':/Icons/ObjectGroup/icon-tree',
    'ServiceGroup': ':/Icons/ServiceGroup/icon-tree',
    'IntervalGroup': ':/Icons/IntervalGroup/icon-tree',
    'Interval': ':/Icons/Interval/icon-tree',
}

_CATEGORY_ICON = ':/Icons/SystemGroup/icon-tree'

# Rule set types that can be opened via double-click.
_RULE_SET_TYPES = frozenset({'Policy', 'NAT', 'Routing'})


class ObjectTree(QTreeWidget):
    """Left-hand object tree replicating fwbuilder's hierarchy."""

    rule_set_activated = Signal(str, str, str)
    """Emitted when a rule set node is double-clicked: (rule_set_id, firewall_name, rule_set_name)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setColumnCount(1)
        self.itemDoubleClicked.connect(self._on_double_click)

    def populate(self, session):
        """Build the tree from all libraries in *session*."""
        self.clear()

        libraries = session.scalars(sqlalchemy.select(Library)).all()
        for lib in libraries:
            lib_item = self._make_item(lib.name, 'Library', str(lib.id))
            self.addTopLevelItem(lib_item)
            self._add_devices(lib, lib_item)
            self._add_category(lib.addresses, 'Addresses', lib_item)
            self._add_category(lib.services, 'Services', lib_item)
            self._add_category(lib.groups, 'Groups', lib_item)
            self._add_category(lib.intervals, 'Time', lib_item)
            lib_item.setExpanded(True)

    # ------------------------------------------------------------------
    # Tree building helpers
    # ------------------------------------------------------------------

    def _add_devices(self, library, parent_item):
        """Add Firewalls and Hosts categories under *parent_item*."""
        firewalls = [d for d in library.devices if isinstance(d, Firewall)]
        hosts = [d for d in library.devices if not isinstance(d, Firewall)]

        if firewalls:
            fw_cat = self._make_category('Firewalls', parent_item)
            for fw in firewalls:
                fw_item = self._make_item(fw.name, fw.type, str(fw.id))
                fw_cat.addChild(fw_item)
                for rs in fw.rule_sets:
                    self._make_item(rs.name, rs.type, str(rs.id), fw_item)
                for iface in fw.interfaces:
                    self._add_interface(iface, fw_item)
            fw_cat.setExpanded(True)

        if hosts:
            host_cat = self._make_category('Hosts', parent_item)
            for host in hosts:
                host_item = self._make_item(host.name, host.type, str(host.id))
                host_cat.addChild(host_item)
                for iface in host.interfaces:
                    self._add_interface(iface, host_item)

    def _add_interface(self, iface, parent_item):
        """Add an Interface node with its child addresses."""
        iface_item = self._make_item(iface.name, 'Interface', str(iface.id))
        parent_item.addChild(iface_item)
        for addr in iface.addresses:
            self._make_item(addr.name, addr.type, str(addr.id), iface_item)

    def _add_category(self, objects, label, parent_item):
        """Add a category folder with child object nodes."""
        if not objects:
            return
        cat = self._make_category(label, parent_item)
        for obj in objects:
            self._make_item(obj.name, obj.type, str(obj.id), cat)

    def _make_category(self, label, parent_item):
        """Create a non-selectable category folder item."""
        item = QTreeWidgetItem(parent_item, [label])
        item.setIcon(0, QIcon(_CATEGORY_ICON))
        return item

    def _make_item(self, name, type_str, obj_id, parent_item=None):
        """Create a tree item storing id and type in user roles."""
        item = QTreeWidgetItem([name])
        item.setData(0, Qt.ItemDataRole.UserRole, obj_id)
        item.setData(0, Qt.ItemDataRole.UserRole + 1, type_str)
        icon_path = ICON_MAP.get(type_str)
        if icon_path:
            item.setIcon(0, QIcon(icon_path))
        if parent_item is not None:
            parent_item.addChild(item)
        return item

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _on_double_click(self, item, _column):
        type_str = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if type_str not in _RULE_SET_TYPES:
            return
        rule_set_id = item.data(0, Qt.ItemDataRole.UserRole)
        # The firewall is the parent of this rule set node.
        fw_item = item.parent()
        fw_name = fw_item.text(0) if fw_item else ''
        self.rule_set_activated.emit(rule_set_id, fw_name, item.text(0))
