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

"""Comment editor panel for policy rules."""

from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QWidget

from firewallfabrik.gui.ui_loader import FWFUiLoader

_SAVE_DELAY_MS = 400


class CommentEditorPanel(QWidget):
    """Editor-pane widget for editing a policy rule's comment."""

    def __init__(self, parent=None):
        super().__init__(parent)
        ui_path = Path(__file__).resolve().parent / 'ui' / 'commenteditorpanel_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._model = None
        self._index = None
        self._rule_id = None
        self._loading = False
        self._signals_connected = False

        # Debounce timer: save after a short pause to avoid a model
        # reload on every keystroke.
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(_SAVE_DELAY_MS)
        self._save_timer.timeout.connect(self._save_comment)

    def load_rule(self, model, index):
        """Populate the editor from the rule at *index*."""
        self._save_timer.stop()
        self._disconnect_signals()
        self._model = model
        self._index = index
        row_data = model.get_row_data(index)
        self._rule_id = row_data.rule_id if row_data is not None else None
        self._load_comment()
        self._connect_signals()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_comment(self):
        """Read the comment from the model and populate the editor."""
        self._loading = True
        try:
            editor = getattr(self, 'editor', None)
            if editor is None:
                return
            row_data = self._get_row_data()
            editor.setPlainText(row_data.comment if row_data is not None else '')
        finally:
            self._loading = False

    def _save_comment(self):
        """Persist the current editor text back to the model."""
        if self._model is None or self._index is None:
            return
        editor = getattr(self, 'editor', None)
        if editor is None:
            return
        new_comment = editor.toPlainText().strip()
        self._model.set_comment(self._index, new_comment)
        # set_comment() calls reload(), invalidating all QModelIndex objects.
        if self._rule_id is not None:
            self._index = self._model.index_for_rule(self._rule_id)

    def _on_text_changed(self):
        """Schedule a save after a short debounce delay."""
        if self._loading:
            return
        self._save_timer.start()

    def _get_row_data(self):
        """Return the row data for the current index."""
        if self._model is None or self._index is None:
            return None
        return self._model.get_row_data(self._index)

    # ------------------------------------------------------------------
    # Signal management
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect change signals to auto-save."""
        if self._signals_connected:
            return
        editor = getattr(self, 'editor', None)
        if editor is not None:
            editor.textChanged.connect(self._on_text_changed)
        self._signals_connected = True

    def _disconnect_signals(self):
        """Disconnect change signals to avoid stale callbacks."""
        if not self._signals_connected:
            return
        editor = getattr(self, 'editor', None)
        if editor is not None:
            editor.textChanged.disconnect(self._on_text_changed)
        self._signals_connected = False
