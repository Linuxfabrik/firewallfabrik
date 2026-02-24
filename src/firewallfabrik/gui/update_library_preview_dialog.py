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

"""Preview dialog for the Update Standard Library feature."""

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QDialog, QTreeWidgetItem

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


class UpdateLibraryPreviewDialog(QDialog):
    """Show a preview of changes before updating the Standard Library.

    Four columns: **Object**, **Changes**, **Firewall / Group**,
    **Details**.

    Four sections are displayed in a tree:

    - **Updated objects** — objects that exist in both old and new
      Standard Library whose content actually differs.  The *Changes*
      column shows a summary of what changed (e.g. port range, comment).
    - **Moved to User library** — objects removed from the new Standard
      Library that are still referenced; they will be migrated to User.
    - **Removed (unused)** — objects removed from the new Standard
      Library that have no references and will be silently deleted.
    - **Similar objects in User library** — informational: User library
      objects that have the same content identity (e.g. same port) as a
      new Standard Library object.  No automatic action is taken; the
      user can switch to the Standard version manually if desired.

    Parameters
    ----------
    updated : list[tuple[str, str, str, list]]
        ``(obj_name, obj_type, diff_summary,
        [(fw_or_group, detail), ...])``
    migrated : list[tuple[str, str, list]]
        ``(obj_name, obj_type, [(fw_or_group, detail), ...])``
    removed : list[tuple[str, str]]
        ``(obj_name, obj_type)``
    duplicates : list[tuple[str, str, str]]
        ``(user_name, user_type, std_name)``
    parent : QWidget | None
    """

    def __init__(self, updated, migrated, removed, duplicates=None, parent=None):
        super().__init__(parent)

        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'updatelibpreviewdialog_q.ui'))

        bold_font = QFont()
        bold_font.setBold(True)

        # -- Updated objects -------------------------------------------
        if updated:
            section = QTreeWidgetItem()
            section.setText(0, f'Will be updated ({len(updated)})')
            section.setFont(0, bold_font)
            section.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.changesTree.addTopLevelItem(section)
            for obj_name, obj_type, diff_summary, refs in updated:
                obj_item = QTreeWidgetItem()
                icon = QIcon(f':/Icons/{obj_type}/icon-tree')
                if not icon.isNull():
                    obj_item.setIcon(0, icon)
                obj_item.setText(0, obj_name)
                obj_item.setText(1, diff_summary)
                if refs:
                    obj_item.setText(3, f'{len(refs)} reference(s)')
                    for fw_or_group, detail in refs:
                        ref_child = QTreeWidgetItem()
                        ref_child.setText(2, fw_or_group)
                        ref_child.setText(3, detail)
                        obj_item.addChild(ref_child)
                section.addChild(obj_item)
            section.setExpanded(True)

        # -- Moved to User library ------------------------------------
        if migrated:
            section = QTreeWidgetItem()
            section.setText(
                0,
                f'Will be moved to User library ({len(migrated)})',
            )
            section.setFont(0, bold_font)
            section.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.changesTree.addTopLevelItem(section)
            for obj_name, obj_type, refs in migrated:
                obj_item = QTreeWidgetItem()
                icon = QIcon(f':/Icons/{obj_type}/icon-tree')
                if not icon.isNull():
                    obj_item.setIcon(0, icon)
                obj_item.setText(0, obj_name)
                if refs:
                    obj_item.setText(3, f'{len(refs)} reference(s)')
                    for fw_or_group, detail in refs:
                        ref_child = QTreeWidgetItem()
                        ref_child.setText(2, fw_or_group)
                        ref_child.setText(3, detail)
                        obj_item.addChild(ref_child)
                section.addChild(obj_item)
            section.setExpanded(True)

        # -- Removed (unused) -----------------------------------------
        if removed:
            section = QTreeWidgetItem()
            section.setText(0, f'Unused, will be removed ({len(removed)})')
            section.setFont(0, bold_font)
            section.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.changesTree.addTopLevelItem(section)
            for obj_name, obj_type in removed:
                child = QTreeWidgetItem()
                icon = QIcon(f':/Icons/{obj_type}/icon-tree')
                if not icon.isNull():
                    child.setIcon(0, icon)
                child.setText(0, obj_name)
                child.setText(3, '(no references)')
                section.addChild(child)
            section.setExpanded(True)

        # -- Similar objects in User library (informational) -----------
        if duplicates:
            section = QTreeWidgetItem()
            section.setText(
                0,
                f'Similar objects in User library \u2014 no action taken'
                f' ({len(duplicates)})',
            )
            section.setFont(0, bold_font)
            section.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.changesTree.addTopLevelItem(section)
            for user_name, user_type, std_name in duplicates:
                child = QTreeWidgetItem()
                icon = QIcon(f':/Icons/{user_type}/icon-tree')
                if not icon.isNull():
                    child.setIcon(0, icon)
                child.setText(0, user_name)
                child.setText(
                    1,
                    f'Standard Library now has \u201c{std_name}\u201d',
                )
                child.setText(
                    3,
                    'Consider switching to the Standard Library version',
                )
                section.addChild(child)
            section.setExpanded(True)
            self.duplicatesNote.setVisible(True)

        # Resize columns to fit contents.
        for col in range(self.changesTree.columnCount()):
            self.changesTree.resizeColumnToContents(col)

        self.adjustSize()

        if parent is not None:
            parent_center = parent.window().geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )
