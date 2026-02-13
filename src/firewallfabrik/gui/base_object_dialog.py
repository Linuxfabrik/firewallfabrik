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

"""Base class for all object editor panel dialogs."""

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDateTimeEdit,
    QLineEdit,
    QRadioButton,
    QSpinBox,
    QTimeEdit,
    QWidget,
)

from firewallfabrik.gui.comment_tags import CommentTags
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


class BaseObjectDialog(QWidget):
    """Base class for all editor panel dialogs.

    Subclasses must implement ``_populate()`` and ``_apply_changes()``.
    """

    changed = Signal()

    def __init__(self, ui_filename, parent=None):
        super().__init__(parent)
        self._obj = None
        self._loading = False
        self._signals_connected = False
        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / ui_filename))

        # Ensure input fields look clearly editable on all platforms.
        # Some Linux themes (Breeze, Adwaita) render QLineEdit/QSpinBox
        # flat inside sunken QFrames, making them hard to distinguish
        # from labels.  The focus/hover states follow Qt HIG: accent-
        # coloured border on focus, subtle darkening on hover.
        self.setStyleSheet(
            'QLineEdit, QSpinBox, QComboBox {'
            '  border: 1px solid palette(dark);'
            '  border-radius: 2px;'
            '  padding: 2px 4px;'
            '  background-color: palette(base);'
            '}'
            'QLineEdit:focus, QSpinBox:focus, QComboBox:focus {'
            '  border: 2px solid palette(highlight);'
            '  padding: 1px 3px;'
            '}'
            'QLineEdit:hover:!focus, QSpinBox:hover:!focus,'
            ' QComboBox:hover:!focus {'
            '  border: 1px solid palette(shadow);'
            '}'
            'QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {'
            '  background-color: palette(window);'
            '  border: 1px solid palette(mid);'
            '}'
        )

    def load_object(self, obj, *, all_tags=None):
        """Load *obj* into the editor: populate widgets and connect signals."""
        self._obj = obj
        self._loading = True
        try:
            self._populate()
            comment_widget = self.findChild(CommentTags, 'commentKeywords')
            if comment_widget is not None:
                comment_widget.load(
                    getattr(obj, 'comment', None),
                    tags=getattr(obj, 'keywords', None),
                    all_tags=all_tags,
                )
        finally:
            self._loading = False
        if not self._signals_connected:
            self._connect_change_signals()
            self._signals_connected = True
        self._set_read_only(self._is_read_only())

    def _populate(self):
        """Fill widgets from ``self._obj``. Must be overridden."""
        raise NotImplementedError

    def _apply_changes(self):
        """Write widget values back to ``self._obj``. Must be overridden."""
        raise NotImplementedError

    def apply_all(self):
        """Apply subclass-specific changes *and* comment/keywords."""
        if self._is_read_only():
            return
        self._apply_changes()
        comment_widget = self.findChild(CommentTags, 'commentKeywords')
        if comment_widget is not None and self._obj is not None:
            self._obj.comment = comment_widget.get_comment()
            if hasattr(type(self._obj), 'keywords'):
                self._obj.keywords = comment_widget.get_tags()

    def _is_read_only(self):
        """Return ``True`` if the current object must not be modified."""
        obj = self._obj
        if obj is None:
            return False
        return getattr(obj, 'ro', False) or getattr(
            getattr(obj, 'library', None),
            'ro',
            False,
        )

    def _set_read_only(self, read_only):
        """Enable or disable all editable child widgets."""
        editable_types = (
            CommentTags,
            QCheckBox,
            QComboBox,
            QDateEdit,
            QDateTimeEdit,
            QLineEdit,
            QRadioButton,
            QSpinBox,
            QTimeEdit,
        )
        enabled = not read_only
        for child in self.findChildren(QWidget):
            if isinstance(child, editable_types):
                child.setEnabled(enabled)

    def _connect_change_signals(self):
        """Auto-connect child widget edit signals to ``_on_changed``."""
        for child in self.findChildren(QWidget):
            if isinstance(child, CommentTags):
                child.changed.connect(self._on_changed)
            elif isinstance(child, QLineEdit):
                child.editingFinished.connect(self._on_changed)
            elif isinstance(child, QCheckBox):
                child.stateChanged.connect(self._on_changed)
            elif isinstance(child, QComboBox):
                child.currentIndexChanged.connect(self._on_changed)
            elif isinstance(child, QSpinBox):
                child.valueChanged.connect(self._on_changed)
            elif isinstance(child, QRadioButton):
                child.toggled.connect(self._on_changed)
            elif isinstance(child, QDateEdit | QTimeEdit | QDateTimeEdit):
                child.dateTimeChanged.connect(self._on_changed)

    def _on_changed(self, *_args):
        if not self._loading:
            self.changed.emit()
