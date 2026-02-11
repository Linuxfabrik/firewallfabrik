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

"""Tags editor dialog (port of the C++ KeywordsDialog)."""

from pathlib import Path

from PySide6.QtCore import QStringListModel, Slot
from PySide6.QtWidgets import QDialog, QMessageBox

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


class TagsDialog(QDialog):
    """Dialog for editing an object's tag set.

    Mirrors fwbuilder's KeywordsDialog: two list views (all / current),
    add/remove buttons, and a field to create new tags.
    """

    def __init__(self, current_tags, all_tags, parent=None):
        super().__init__(parent)

        self._all_tags = set(all_tags)
        self._curr_tags = set(current_tags)
        self._all_tags |= self._curr_tags

        self._all_model = QStringListModel()
        self._curr_model = QStringListModel()

        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'tagsdialog_q.ui'))

        self.allTagsListView.setModel(self._all_model)
        self.currTagsListView.setModel(self._curr_model)

        self.addButton.clicked.connect(self._on_add)
        self.allTagsListView.doubleClicked.connect(self._on_add)
        self.newTagButton.clicked.connect(self._on_create)
        self.removeButton.clicked.connect(self._on_remove)

        self._refresh_models()

        if parent is not None:
            parent_center = parent.window().geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    def get_tags(self):
        """Return the accepted tags as a sorted list."""
        return sorted(self._curr_model.stringList())

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot()
    def _on_add(self):
        for idx in self.allTagsListView.selectionModel().selectedIndexes():
            self._curr_tags.add(idx.data())
        self._refresh_models()

    @Slot()
    def _on_remove(self):
        for idx in self.currTagsListView.selectionModel().selectedIndexes():
            self._curr_tags.discard(idx.data())
        self._refresh_models()

    @Slot()
    def _on_create(self):
        tag = self.newTagLineEdit.text().strip()
        if not self._validate_tag(tag):
            return
        self._all_tags.add(tag)
        self._curr_tags.add(tag)
        self._refresh_models()
        self.newTagLineEdit.clear()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _refresh_models(self):
        self._all_model.setStringList(sorted(self._all_tags))
        self._curr_model.setStringList(sorted(self._curr_tags))

    def _validate_tag(self, tag):
        if not tag:
            QMessageBox.warning(
                self,
                self.tr('Tags'),
                self.tr('Tag must not be empty.'),
            )
            return False
        if ',' in tag:
            QMessageBox.warning(
                self,
                self.tr('Tags'),
                self.tr('Tag must not contain a comma.'),
            )
            return False
        return True
