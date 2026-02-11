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

"""Comment & tags editor widget (replaces the C++ CommentKeywords widget)."""

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QGridLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QWidget,
)

from firewallfabrik.gui.tags_dialog import TagsDialog


class CommentTags(QWidget):
    """Comment text area with a tags button, matching fwbuilder's layout.

    Emits ``changed`` whenever the user modifies text or tags.
    """

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._suppressing = False
        self._tags = set()
        self._all_tags = set()

        layout = QGridLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Row 0: comment text edit (spans 2 columns)
        self._text_edit = QTextEdit()
        self._text_edit.setPlaceholderText('Enter comment here')
        self._text_edit.setTabChangesFocus(True)
        self._text_edit.setMinimumWidth(200)
        self._text_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        layout.addWidget(self._text_edit, 0, 0, 1, 2)

        # Row 1, col 0: tags button
        self._tags_button = QPushButton('Tags...')
        self._tags_button.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Fixed,
        )
        layout.addWidget(self._tags_button, 1, 0)

        # Row 1, col 1: tags label
        self._tags_label = QLabel()
        self._tags_label.setWordWrap(True)
        layout.addWidget(self._tags_label, 1, 1)

        self._update_tags_label()
        self._text_edit.textChanged.connect(self._on_text_changed)
        self._tags_button.clicked.connect(self._on_tags_clicked)

    def load(self, text, tags=None, all_tags=None):
        """Load comment text and tags, suppressing the ``changed`` signal."""
        self._suppressing = True
        try:
            self._text_edit.setPlainText(text or '')
            self._tags = set(tags) if tags else set()
            self._all_tags = set(all_tags) if all_tags else set()
            self._all_tags |= self._tags
            self._update_tags_label()
        finally:
            self._suppressing = False

    def get_comment(self):
        """Return the current comment as plain text."""
        return self._text_edit.toPlainText()

    def get_tags(self):
        """Return the current tags as a set."""
        return set(self._tags)

    def _update_tags_label(self):
        if self._tags:
            self._tags_label.setText(', '.join(sorted(self._tags)))
        else:
            self._tags_label.setText('<i>No tags</i>')

    def _on_text_changed(self):
        if not self._suppressing:
            self.changed.emit()

    def _on_tags_clicked(self):
        dialog = TagsDialog(self._tags, self._all_tags, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._tags = set(dialog.get_tags())
            self._update_tags_label()
            self.changed.emit()
