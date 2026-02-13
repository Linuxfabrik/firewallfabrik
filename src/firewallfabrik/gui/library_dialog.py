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

"""Editor panel dialog for Library objects."""

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QColorDialog

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class LibraryDialog(BaseObjectDialog):
    """Editor for Library objects (name + color)."""

    def __init__(self, parent=None):
        super().__init__('librarydialog_q.ui', parent)
        self._color = '#ffffff'
        self.colorButton.clicked.connect(self._pick_color)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self._color = data.get('color', '#ffffff')
        self._update_color_button()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = dict(self._obj.data or {})
        data['color'] = self._color
        self._obj.data = data

    def _pick_color(self):
        color = QColorDialog.getColor(QColor(self._color), self)
        if color.isValid():
            self._color = color.name()
            self._update_color_button()
            self._on_changed()

    def _update_color_button(self):
        self.colorButton.setStyleSheet(
            f'background-color: {self._color}; min-width: 40px; min-height: 20px;'
        )
