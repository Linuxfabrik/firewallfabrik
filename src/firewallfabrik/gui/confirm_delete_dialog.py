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

"""Confirm Delete Object dialog — warns before deleting in-use objects."""

from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QDialog, QTreeWidgetItem

from firewallfabrik.gui.find_where_used_panel import (
    find_group_references,
    find_rule_references,
)
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


def _icon_for_type(obj_type):
    """Return a QIcon for the given object type string, or a null icon."""
    if obj_type:
        icon = QIcon(f':/Icons/{obj_type}/icon-tree')
        if not icon.isNull():
            return icon
    return QIcon()


class ConfirmDeleteDialog(QDialog):
    """Dialog listing where-used references for objects about to be deleted.

    Mirrors fwbuilder's ``ConfirmDeleteObjectDialog``.  Shows a tree of
    groups and rules referencing each object so the user can decide
    whether to proceed.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'confirmdeleteobjectdialog_q.ui'))

    def load(self, objects, db_manager):
        """Populate *objectsView* with where-used info.

        Parameters
        ----------
        objects : list[tuple[str, str, str]]
            Each entry is ``(obj_id, obj_name, obj_type)`` for an object
            about to be deleted.
        db_manager :
            The database manager providing sessions.
        """
        with db_manager.session() as session:
            for obj_id, obj_name, obj_type in objects:
                self._find_for_object(session, obj_id, obj_name, obj_type)

        for col in range(self.objectsView.columnCount()):
            self.objectsView.resizeColumnToContents(col)

    def _find_for_object(self, session, obj_id, obj_name, obj_type):
        """Add tree items for all references to a single object."""
        obj_icon = _icon_for_type(obj_type)
        item_count = 0

        # Group references.
        for _grp_id, grp_name, grp_type in find_group_references(session, obj_id):
            item = QTreeWidgetItem()
            item.setIcon(0, obj_icon)
            item.setText(0, obj_name)
            item.setIcon(1, _icon_for_type(grp_type))
            item.setText(1, grp_name)
            item.setText(2, grp_type)
            self.objectsView.addTopLevelItem(item)
            item_count += 1

        # Rule references.
        for (
            _rule_id,
            slot,
            _rule_set_id,
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
            self.objectsView.addTopLevelItem(item)
            item_count += 1

        # If not used anywhere, show a placeholder row.
        if item_count == 0:
            item = QTreeWidgetItem()
            item.setIcon(0, obj_icon)
            item.setText(0, obj_name)
            item.setText(2, 'Not used anywhere')
            self.objectsView.addTopLevelItem(item)
