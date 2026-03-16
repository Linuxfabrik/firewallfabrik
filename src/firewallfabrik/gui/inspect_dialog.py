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

"""Inspect Rules dialog -- lists all policy/NAT rules that reference a given object.

Searches through the ``rule_elements`` association table to find which rules
reference the object directly, and also through ``group_membership`` to find
rules that reference the object indirectly via group membership.
"""

import logging
import uuid

import sqlalchemy
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QHeaderView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from firewallfabrik.core.objects import (
    Rule,
    RuleSet,
    group_membership,
    rule_elements,
)

logger = logging.getLogger(__name__)


def _icon_for_type(obj_type):
    """Return a QIcon for the given object type string, or a null icon."""
    if obj_type:
        icon = QIcon(f':/Icons/{obj_type}/icon-tree')
        if not icon.isNull():
            return icon
    return QIcon()


def _collect_group_ids_recursive(session, obj_id):
    """Find all groups that contain *obj_id*, recursively climbing the group hierarchy.

    Returns a set of group UUIDs.  This handles the case where an object is
    a member of group A, and group A is in turn a member of group B -- both
    groups are returned so rules referencing either group are found.
    """
    visited = set()
    queue = [obj_id]
    while queue:
        current_id = queue.pop()
        rows = session.execute(
            sqlalchemy.select(group_membership.c.group_id).where(
                group_membership.c.member_id == current_id
            )
        ).all()
        for (grp_id,) in rows:
            if grp_id not in visited:
                visited.add(grp_id)
                queue.append(grp_id)
    return visited


def find_inspect_results(session, obj_id):
    """Find all rules referencing *obj_id* directly or through group membership.

    Returns a sorted list of ``(fw_name, fw_type, rs_name, rs_type, position,
    rule_type, slot)`` tuples.
    """
    if isinstance(obj_id, str):
        obj_id = uuid.UUID(obj_id)

    # Collect the object itself plus all ancestor groups.
    search_ids = {obj_id} | _collect_group_ids_recursive(session, obj_id)

    seen = set()
    results = []
    for search_id in search_ids:
        rows = session.execute(
            sqlalchemy.select(
                rule_elements.c.rule_id,
                rule_elements.c.slot,
                Rule.rule_set_id,
                Rule.position,
                Rule.type,
            )
            .join(Rule, Rule.id == rule_elements.c.rule_id)
            .where(rule_elements.c.target_id == search_id)
        ).all()

        for rule_id, slot, rule_set_id, position, rule_type in rows:
            key = (rule_id, slot)
            if key in seen:
                continue
            seen.add(key)

            rs = session.get(RuleSet, rule_set_id)
            if rs is None:
                continue
            fw_name = rs.device.name if rs.device else '(unknown)'
            fw_type = rs.device.type if rs.device else ''
            results.append(
                (fw_name, fw_type, rs.name, rs.type, position, rule_type, slot)
            )

    # Sort alphabetically by firewall name, then rule set name, then position.
    results.sort(key=lambda r: (r[0].casefold(), r[2].casefold(), r[4]))
    return results


class InspectDialog(QDialog):
    """Dialog that lists all policy/NAT rules referencing a given object."""

    def __init__(self, db_manager, obj_id, obj_name, obj_type, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f'Inspect: {obj_name} ({obj_type})')
        self.setMinimumSize(700, 400)
        self.resize(800, 500)

        layout = QVBoxLayout(self)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(
            ['Firewall', 'Rule Set', 'Rule #', 'Rule Type', 'Slot']
        )
        self._tree.setRootIsDecorated(False)
        self._tree.setAlternatingRowColors(True)
        self._tree.setSortingEnabled(True)
        layout.addWidget(self._tree)

        self._populate(db_manager, obj_id)

        # Resize columns to content.
        header = self._tree.header()
        for col in range(self._tree.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)

        # Center on parent.
        if parent is not None:
            parent_geo = parent.geometry()
            self.move(
                parent_geo.center().x() - self.width() // 2,
                parent_geo.center().y() - self.height() // 2,
            )

    def _populate(self, db_manager, obj_id):
        """Query the database and populate the tree widget."""
        with db_manager.session() as session:
            results = find_inspect_results(session, obj_id)

        if not results:
            item = QTreeWidgetItem()
            item.setText(0, '(No rules reference this object)')
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self._tree.addTopLevelItem(item)
            return

        for fw_name, fw_type, rs_name, rs_type, position, rule_type, slot in results:
            item = QTreeWidgetItem()
            item.setIcon(0, _icon_for_type(fw_type))
            item.setText(0, fw_name)
            item.setText(1, f'{rs_type}: {rs_name}')
            item.setText(2, str(position))
            # Right-align the numeric position column for readability.
            item.setTextAlignment(
                2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            item.setText(3, rule_type)
            item.setText(4, slot)
            self._tree.addTopLevelItem(item)
