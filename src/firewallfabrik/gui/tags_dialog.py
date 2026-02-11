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

from PySide6.QtCore import QStringListModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


class TagsDialog(QDialog):
    """Dialog for editing an object's tag set.

    Mirrors fwbuilder's KeywordsDialog: two list views (all / current),
    add/remove buttons, and a field to create new tags.
    """

    def __init__(self, current_tags, all_tags, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr('Tags'))
        self.resize(626, 387)

        self._all_tags = set(all_tags)
        self._curr_tags = set(current_tags)
        # Ensure current tags appear in the "all" pool too.
        self._all_tags |= self._curr_tags

        self._all_model = QStringListModel()
        self._curr_model = QStringListModel()
        self._refresh_models()

        self._build_ui()

    def get_tags(self):
        """Return the accepted tags as a sorted list."""
        return sorted(self._curr_model.stringList())

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        layout = QGridLayout(self)

        # Row 0: all-tags list | add/remove buttons | current-tags list
        all_label = QLabel(self.tr('All tags'))
        layout.addWidget(all_label, 0, 0, Qt.AlignmentFlag.AlignBottom)

        self._all_view = QListView()
        self._all_view.setModel(self._all_model)
        self._all_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._all_view.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection,
        )
        self._all_view.doubleClicked.connect(self._on_add)
        layout.addWidget(self._all_view, 1, 0)

        btn_widget = QWidget()
        btn_layout = QVBoxLayout(btn_widget)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self._add_btn = QPushButton(self.tr('Add >>'))
        self._remove_btn = QPushButton(self.tr('<< Remove'))
        btn_layout.addWidget(self._add_btn)
        btn_layout.addWidget(self._remove_btn)
        layout.addWidget(btn_widget, 1, 1)

        curr_label = QLabel(self.tr('Current tags'))
        layout.addWidget(curr_label, 0, 2, Qt.AlignmentFlag.AlignBottom)

        self._curr_view = QListView()
        self._curr_view.setModel(self._curr_model)
        self._curr_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._curr_view.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection,
        )
        layout.addWidget(self._curr_view, 1, 2)

        # Row 2: new tag input
        new_tag_layout = QHBoxLayout()
        new_tag_layout.addWidget(QLabel(self.tr('New Tag:')))
        self._new_tag_edit = QLineEdit()
        self._new_tag_edit.setMinimumWidth(200)
        self._new_tag_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        new_tag_layout.addWidget(self._new_tag_edit)
        self._create_btn = QPushButton(self.tr('Create'))
        self._create_btn.setDefault(True)
        new_tag_layout.addWidget(self._create_btn)
        layout.addLayout(new_tag_layout, 2, 0, 1, 3)

        # Row 3: OK / Cancel
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box, 3, 0, 1, 3)

        # Signals
        self._add_btn.clicked.connect(self._on_add)
        self._remove_btn.clicked.connect(self._on_remove)
        self._create_btn.clicked.connect(self._on_create)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_add(self):
        for idx in self._all_view.selectionModel().selectedIndexes():
            self._curr_tags.add(idx.data())
        self._refresh_models()

    def _on_remove(self):
        for idx in self._curr_view.selectionModel().selectedIndexes():
            self._curr_tags.discard(idx.data())
        self._refresh_models()

    def _on_create(self):
        tag = self._new_tag_edit.text().strip()
        if not self._validate_tag(tag):
            return
        self._all_tags.add(tag)
        self._curr_tags.add(tag)
        self._refresh_models()
        self._new_tag_edit.clear()

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
