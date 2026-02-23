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

"""Find Where Used panel — shows all locations referencing a selected object."""

import logging
import uuid
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QWidget,
)

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    Interval,
    Rule,
    RuleSet,
    Service,
    group_membership,
    rule_elements,
)
from firewallfabrik.gui.ui_loader import FWFUiLoader

logger = logging.getLogger(__name__)

_UI_DIR = Path(__file__).resolve().parent / 'ui'


def _icon_for_type(obj_type):
    """Return a QIcon for the given object type string, or a null icon."""
    if obj_type:
        icon = QIcon(f':/Icons/{obj_type}/icon-tree')
        if not icon.isNull():
            return icon
    return QIcon()


# UserRole offsets for navigation data stored on result tree items.
_ROLE_OBJ_ID = Qt.ItemDataRole.UserRole
_ROLE_OBJ_TYPE = Qt.ItemDataRole.UserRole + 1
_ROLE_RULE_SET_ID = Qt.ItemDataRole.UserRole + 2
_ROLE_RULE_ID = Qt.ItemDataRole.UserRole + 3
_ROLE_SLOT = Qt.ItemDataRole.UserRole + 4


def find_group_references(session, obj_id):
    """Return group references for *obj_id*.

    Returns a list of ``(group_id, group_name, group_type)`` tuples for
    every group that contains *obj_id* as a member.
    """
    rows = session.execute(
        sqlalchemy.select(
            group_membership.c.group_id,
        ).where(group_membership.c.member_id == obj_id)
    ).all()

    results = []
    for (grp_id,) in rows:
        grp = session.get(Group, grp_id)
        if grp is None:
            continue
        results.append((grp_id, grp.name, grp.type))
    return results


def find_rule_references(session, obj_id):
    """Return rule references for *obj_id*.

    Returns a list of
    ``(rule_id, slot, rule_set_id, rs_type, rs_name, fw_name, fw_type, position)``
    tuples for every rule element that references *obj_id*.
    """
    rows = session.execute(
        sqlalchemy.select(
            rule_elements.c.rule_id,
            rule_elements.c.slot,
            Rule.rule_set_id,
            Rule.position,
        )
        .join(Rule, Rule.id == rule_elements.c.rule_id)
        .where(rule_elements.c.target_id == obj_id)
    ).all()

    results = []
    for rule_id, slot, rule_set_id, position in rows:
        rs = session.get(RuleSet, rule_set_id)
        if rs is None:
            continue
        fw_name = rs.device.name if rs.device else ''
        fw_type = rs.device.type if rs.device else ''
        results.append(
            (rule_id, slot, rule_set_id, rs.type, rs.name, fw_name, fw_type, position)
        )
    return results


class FindWhereUsedPanel(QWidget):
    """Panel for finding all locations where an object is referenced."""

    object_found = Signal(str, str)  # (obj_id, obj_type)
    navigate_to_rule = Signal(str, str, str)  # (rule_set_id, rule_id, slot)

    def __init__(self, parent=None):
        super().__init__(parent)
        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'findwhereusedwidget_q.ui'))

        self._tree = None
        self._db_manager = None

        self.dropArea.set_helper_text('Drop an object to find its usages')

        self.resListView.itemDoubleClicked.connect(self._on_item_clicked)

    @Slot(QTreeWidgetItem, int)
    def itemClicked(self, item, column):
        # TODO
        self._on_item_clicked(item, column)

    def set_tree(self, tree: QTreeWidget):
        """Set the object tree widget for resolving names/types."""
        self._tree = tree

    def set_db_manager(self, db_manager):
        """Set the database manager for queries."""
        self._db_manager = db_manager

    @Slot()
    def reset(self):
        """Clear results."""
        self.resListView.clear()

    def find_object(self, obj_id, name, obj_type):
        """Programmatic trigger: insert object into drop area and search."""
        self.dropArea.insert_object(uuid.UUID(obj_id), name, obj_type)
        self.find()

    @Slot()
    def find(self):
        """Run the where-used search for the object in the drop area."""
        obj_id = self.dropArea.get_object_id()
        if obj_id is None or self._db_manager is None:
            return

        self.resListView.clear()

        with self._db_manager.session() as session:
            if self.includeChildren.isChecked():
                ids = self._collect_descendants(session, obj_id)
            else:
                ids = [obj_id]

            logger.debug(
                'Find where used: searching for %d object(s): %s',
                len(ids),
                [str(i) for i in ids],
            )

            for search_id in ids:
                name, obj_type = self._resolve_name_and_type(search_id)
                obj_name = name or str(search_id)
                obj_icon = _icon_for_type(obj_type)
                self._find_in_containers(session, search_id, obj_name, obj_icon)
                self._find_in_groups(session, search_id, obj_name, obj_icon)
                self._find_in_rules(session, search_id, obj_name, obj_icon)

        for col in range(self.resListView.columnCount()):
            self.resListView.resizeColumnToContents(col)

    def _find_in_containers(self, session, obj_id, obj_name, obj_icon):
        """Find direct parent containers of obj_id via FK relationships.

        Mirrors the C++ UsageResolver logic that reports Interface and Device
        objects directly containing the searched object as a child.
        """
        # Address → parent Interface.
        addr = session.get(Address, obj_id)
        if addr is not None and addr.interface_id is not None:
            iface = session.get(Interface, addr.interface_id)
            if iface is not None:
                self._add_container_item(
                    obj_name, obj_icon, iface.name, 'Interface', str(iface.id)
                )

        # Interface → parent Device.
        iface = session.get(Interface, obj_id)
        if iface is not None and iface.device_id is not None:
            device = session.get(Host, iface.device_id)
            if device is not None:
                self._add_container_item(
                    obj_name, obj_icon, device.name, device.type, str(device.id)
                )

    def _add_container_item(
        self, obj_name, obj_icon, container_name, container_type, container_id
    ):
        """Create a result item for a direct containment relationship."""
        item = QTreeWidgetItem()
        item.setIcon(0, obj_icon)
        item.setText(0, obj_name)
        item.setIcon(1, _icon_for_type(container_type))
        item.setText(1, container_name)
        item.setText(2, f'Type: {container_type}')
        item.setData(0, _ROLE_OBJ_ID, container_id)
        item.setData(0, _ROLE_OBJ_TYPE, container_type)
        self.resListView.addTopLevelItem(item)

    def _find_in_groups(self, session, obj_id, obj_name, obj_icon):
        """Find groups containing obj_id via group_membership."""
        for grp_id, grp_name, grp_type in find_group_references(session, obj_id):
            item = QTreeWidgetItem()
            item.setIcon(0, obj_icon)
            item.setText(0, obj_name)
            item.setIcon(1, _icon_for_type(grp_type))
            item.setText(1, grp_name)
            item.setText(2, grp_type)
            item.setData(0, _ROLE_OBJ_ID, str(grp_id))
            item.setData(0, _ROLE_OBJ_TYPE, grp_type)
            self.resListView.addTopLevelItem(item)

    def _find_in_rules(self, session, obj_id, obj_name, obj_icon):
        """Find rules referencing obj_id via rule_elements."""
        for (
            rule_id,
            slot,
            rule_set_id,
            rs_type,
            rs_name,
            fw_name,
            fw_type,
            position,
        ) in find_rule_references(session, obj_id):
            detail = f"{rs_type} '{rs_name}' / Rule #{position} / {slot}"

            item = QTreeWidgetItem()
            item.setIcon(0, obj_icon)
            item.setText(0, obj_name)
            item.setIcon(1, _icon_for_type(fw_type))
            item.setText(1, fw_name)
            item.setText(2, detail)
            item.setData(0, _ROLE_RULE_SET_ID, str(rule_set_id))
            item.setData(0, _ROLE_RULE_ID, str(rule_id))
            item.setData(0, _ROLE_SLOT, slot)
            self.resListView.addTopLevelItem(item)

    def _collect_descendants(self, session, obj_id):
        """Collect obj_id plus all descendant IDs for include-children mode.

        Mirrors the recursive child traversal of the C++ UsageResolver's
        ``findAllReferenceHolders`` method.
        """
        ids = [obj_id]
        obj_type = self._resolve_type(obj_id)
        logger.debug('Collecting descendants of %s (type=%s)', obj_id, obj_type)

        if obj_type in (
            'ObjectGroup',
            'ServiceGroup',
            'IntervalGroup',
            'Group',
        ) or (obj_type and 'Group' in obj_type):
            self._collect_group_descendants(session, obj_id, ids)
        elif obj_type in ('Host', 'Firewall', 'Cluster'):
            self._collect_device_descendants(session, obj_id, ids)
        elif obj_type == 'Interface':
            self._collect_interface_descendants(session, obj_id, ids)

        return ids

    def _collect_group_descendants(self, session, group_id, ids):
        """Recursively collect children of a group."""
        # Child groups.
        child_groups = (
            session.execute(
                sqlalchemy.select(Group.id).where(Group.parent_group_id == group_id)
            )
            .scalars()
            .all()
        )
        for cid in child_groups:
            ids.append(cid)
            self._collect_group_descendants(session, cid, ids)

        # Addresses in this group.
        for (aid,) in session.execute(
            sqlalchemy.select(Address.id).where(Address.group_id == group_id)
        ).all():
            ids.append(aid)

        # Services in this group.
        for (sid,) in session.execute(
            sqlalchemy.select(Service.id).where(Service.group_id == group_id)
        ).all():
            ids.append(sid)

        # Intervals in this group.
        for (iid,) in session.execute(
            sqlalchemy.select(Interval.id).where(Interval.group_id == group_id)
        ).all():
            ids.append(iid)

        # Devices in this group.
        for (did,) in session.execute(
            sqlalchemy.select(Host.id).where(Host.group_id == group_id)
        ).all():
            ids.append(did)
            self._collect_device_descendants(session, did, ids)

    def _collect_device_descendants(self, session, device_id, ids):
        """Collect interfaces and their addresses for a device."""
        for (iface_id,) in session.execute(
            sqlalchemy.select(Interface.id).where(Interface.device_id == device_id)
        ).all():
            ids.append(iface_id)
            self._collect_interface_descendants(session, iface_id, ids)

    @staticmethod
    def _collect_interface_descendants(session, iface_id, ids):
        """Collect addresses belonging to an interface."""
        for (aid,) in session.execute(
            sqlalchemy.select(Address.id).where(Address.interface_id == iface_id)
        ).all():
            ids.append(aid)

    def _resolve_name_and_type(self, obj_id):
        """Look up an object's name and type from the tree widget."""
        if self._tree is None:
            return None, None
        target = str(obj_id)
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            if item.data(0, Qt.ItemDataRole.UserRole) == target:
                return item.text(0), item.data(0, Qt.ItemDataRole.UserRole + 1)
            it += 1
        return None, None

    def _resolve_type(self, obj_id):
        """Look up an object type from the tree widget."""
        _, obj_type = self._resolve_name_and_type(obj_id)
        return obj_type

    @Slot(QTreeWidgetItem, int)
    def _on_item_clicked(self, item, _column):
        """Navigate to the clicked result."""
        rule_set_id = item.data(0, _ROLE_RULE_SET_ID)
        rule_id = item.data(0, _ROLE_RULE_ID)
        slot = item.data(0, _ROLE_SLOT)

        if rule_set_id and rule_id:
            self.navigate_to_rule.emit(rule_set_id, rule_id, slot or '')
            return

        obj_id = item.data(0, _ROLE_OBJ_ID)
        obj_type = item.data(0, _ROLE_OBJ_TYPE)
        if obj_id and obj_type:
            self.object_found.emit(obj_id, obj_type)
