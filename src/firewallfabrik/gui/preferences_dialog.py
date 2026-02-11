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

from pathlib import Path

from PySide6.QtCore import QSettings, Slot
from PySide6.QtGui import QColor, QIcon, QPixmap
from PySide6.QtWidgets import QColorDialog, QDialog

from firewallfabrik.gui.label_settings import (
    LABEL_KEYS,
    get_label_color,
    get_label_text,
    set_label_color,
    set_label_text,
)
from firewallfabrik.gui.ui_loader import FWFUiLoader


def _color_icon(hex_color, size=24):
    """Create a small square icon filled with *hex_color*."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(hex_color))
    return QIcon(pixmap)


class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        ui_path = Path(__file__).resolve().parent / 'ui' / 'prefsdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

        settings = QSettings()
        self.attributesInTree.setChecked(
            settings.value('UI/ShowObjectsAttributesInTree', True, type=bool)
        )
        self.objTooltips.setChecked(settings.value('UI/ObjTooltips', True, type=bool))

        # Icon size in rules: 25 (default) or 16.
        icon_size = settings.value('UI/IconSizeInRules', 25, type=int)
        if icon_size == 16:
            self.rb16.setChecked(True)
        else:
            self.rb25.setChecked(True)

        # Label colors: store current hex values so we can save on accept.
        self._label_colors = {}
        for key in LABEL_KEYS:
            hex_color = get_label_color(key)
            self._label_colors[key] = hex_color
            btn = getattr(self, f'{key}Btn')
            btn.setIcon(_color_icon(hex_color))
            text_field = getattr(self, f'{key}Text')
            text_field.setText(get_label_text(key))

        self.accepted.connect(self._save_settings)

    # ------------------------------------------------------------------
    # Icon size slots (connected via .ui signal/slot)
    # ------------------------------------------------------------------

    @Slot()
    def changeIconSize16(self):
        pass

    @Slot()
    def changeIconSize25(self):
        pass

    # ------------------------------------------------------------------
    # Label color picker slots (connected via .ui signal/slot)
    # ------------------------------------------------------------------

    @Slot()
    def changeColor1(self):
        self._pick_label_color('color1')

    @Slot()
    def changeColor2(self):
        self._pick_label_color('color2')

    @Slot()
    def changeColor3(self):
        self._pick_label_color('color3')

    @Slot()
    def changeColor4(self):
        self._pick_label_color('color4')

    @Slot()
    def changeColor5(self):
        self._pick_label_color('color5')

    @Slot()
    def changeColor6(self):
        self._pick_label_color('color6')

    @Slot()
    def changeColor7(self):
        self._pick_label_color('color7')

    def _pick_label_color(self, key):
        """Open a QColorDialog for the given label *key*."""
        current = QColor(self._label_colors[key])
        color = QColorDialog.getColor(current, self, f'Choose color for {key}')
        if color.isValid():
            hex_color = color.name()
            self._label_colors[key] = hex_color
            getattr(self, f'{key}Btn').setIcon(_color_icon(hex_color))

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save_settings(self):
        """Persist preference values to QSettings."""
        settings = QSettings()
        settings.setValue(
            'UI/ObjTooltips',
            self.objTooltips.isChecked(),
        )
        settings.setValue(
            'UI/ShowObjectsAttributesInTree',
            self.attributesInTree.isChecked(),
        )

        settings.setValue(
            'UI/IconSizeInRules',
            16 if self.rb16.isChecked() else 25,
        )

        # Persist label colors and texts.
        for key in LABEL_KEYS:
            set_label_color(key, self._label_colors[key])
            set_label_text(key, getattr(self, f'{key}Text').text())
