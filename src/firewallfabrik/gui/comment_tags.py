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

from pathlib import Path

from PySide6.QtCore import Signal, Slot
from PySide6.QtWidgets import QDialog, QWidget

from firewallfabrik.gui.tags_dialog import TagsDialog
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


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

        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'commenttags_q.ui'))

        self._update_tags_label()
        self.comment.textChanged.connect(self._on_text_changed)

    def load(self, text, tags=None, all_tags=None):
        """Load comment text and tags, suppressing the ``changed`` signal."""
        self._suppressing = True
        try:
            self.comment.setPlainText(text or '')
            self._tags = set(tags) if tags else set()
            self._all_tags = set(all_tags) if all_tags else set()
            self._all_tags |= self._tags
            self._update_tags_label()
        finally:
            self._suppressing = False

    def get_comment(self):
        """Return the current comment as plain text."""
        return self.comment.toPlainText()

    def get_tags(self):
        """Return the current tags as a set."""
        return set(self._tags)

    def _update_tags_label(self):
        if self._tags:
            self.tagsLabel.setText(', '.join(sorted(self._tags)))
        else:
            self.tagsLabel.setText('<i>No tags</i>')

    def _on_text_changed(self):
        if not self._suppressing:
            self.changed.emit()

    @Slot()
    def tagsClicked(self):
        dialog = TagsDialog(self._tags, self._all_tags, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._tags = set(dialog.get_tags())
            self._update_tags_label()
            self.changed.emit()
