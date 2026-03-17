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

"""Preferences dialog for global application settings."""

import shutil
import sys
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, Slot
from PySide6.QtGui import QColor, QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QColorDialog,
    QDialog,
    QFileDialog,
    QFontDialog,
    QTableWidgetItem,
)

from firewallfabrik.gui.label_settings import (
    LABEL_KEYS,
    get_label_color,
    get_label_text,
    set_label_color,
    set_label_text,
)
from firewallfabrik.gui.platform_settings import (
    HOST_OS,
    PLATFORMS,
    is_os_enabled,
    is_platform_enabled,
    set_os_enabled,
    set_platform_enabled,
)
from firewallfabrik.gui.ui_loader import FWFUiLoader


def _color_icon(hex_color, size=24):
    """Create a small square icon filled with *hex_color*."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(hex_color))
    return QIcon(pixmap)


def _load_font(settings, key):
    """Load a QFont from QSettings, returning the app default if unset."""
    s = settings.value(key, '', type=str)
    if s:
        font = QFont()
        font.fromString(s)
        return font
    return QFont()


def _font_description(font):
    """Return a human-readable description of a QFont."""
    style = font.styleName() or ('Bold' if font.bold() else 'Regular')
    return f'{font.family()}, {font.pointSize()}pt, {style}'


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

        self._load_from_settings()

        self._populate_platform_table()
        self._populate_os_table()

        # Hide Windows SSH hint on non-Windows platforms.
        if sys.platform != 'win32':
            self.windowsSshHint.hide()

        self.accepted.connect(self._save_settings)
        self.buttonRestoreDefaults.clicked.connect(self._restore_defaults)

    def _load_from_settings(self):
        """Load current values from QSettings into all widgets."""
        settings = QSettings()
        self._apply_values(
            obj_tooltips=settings.value('UI/ObjTooltips', True, type=bool),
            attrs_in_tree=settings.value(
                'UI/ShowObjectsAttributesInTree', True, type=bool
            ),
            icon_size=settings.value('UI/IconSizeInRules', 25, type=int),
            dns_compile=settings.value(
                'Objects/DNSName/useCompileTimeForNewObjects', True, type=bool
            ),
            at_compile=settings.value(
                'Objects/AddressTable/useCompileTimeForNewObjects', True, type=bool
            ),
            rules_logging=settings.value(
                'Objects/PolicyRule/defaultLoggingState', True, type=bool
            ),
            rules_stateful=settings.value(
                'Objects/PolicyRule/defaultStateful', True, type=bool
            ),
            rules_action=settings.value(
                'Objects/PolicyRule/defaultAction', 0, type=int
            ),
            rules_direction=settings.value(
                'Objects/PolicyRule/defaultDirection', 0, type=int
            ),
            autoconfigure_iface=settings.value(
                'Objects/Interface/autoconfigureInterfaces', True, type=bool
            ),
        )

        # Installer tab.
        default_ssh = shutil.which('ssh') or 'ssh'
        default_scp = shutil.which('scp') or 'scp'
        self.sshPath.setText(
            settings.value('SSH/SSHPath', default_ssh, type=str),
        )
        self.scpPath.setText(
            settings.value('SSH/SCPPath', default_scp, type=str),
        )
        self.sshTimeout.setValue(
            settings.value('SSH/SSHTimeout', 10, type=int),
        )
        self.rememberSshPass.setChecked(
            settings.value('Environment/RememberSshPassEnabled', False, type=bool),
        )

        # Appearance tab.
        self._rules_font = _load_font(settings, 'UI/Fonts/RulesFont')
        self._tree_font = _load_font(settings, 'UI/Fonts/TreeFont')
        self._compiler_font = _load_font(settings, 'UI/Fonts/CompilerOutputFont')
        self.rulesFontDescr.setText(_font_description(self._rules_font))
        self.treeFontDescr.setText(_font_description(self._tree_font))
        self.compilerOutputFontDescr.setText(_font_description(self._compiler_font))

        self.chShowIcons.setChecked(
            settings.value('UI/Icons/ShowIconsInRules', True, type=bool),
        )
        self.showDirectionText.setChecked(
            settings.value('UI/Icons/ShowDirectionTextInRules', True, type=bool),
        )
        self.chClipComment.setChecked(
            settings.value('UI/ClipComment', False, type=bool),
        )
        self.toolbarIconsText.setChecked(
            settings.value('UI/IconWithText', False, type=bool),
        )

        # Enable/disable icon size radio buttons based on show-icons state.
        icons_shown = self.chShowIcons.isChecked()
        self.rb16.setEnabled(icons_shown)
        self.rb25.setEnabled(icons_shown)

        # Label colors: store current hex values so we can save on accept.
        self._label_colors = {}
        for key in LABEL_KEYS:
            hex_color = get_label_color(key)
            self._label_colors[key] = hex_color
            getattr(self, f'{key}Btn').setIcon(_color_icon(hex_color))
            getattr(self, f'{key}Text').setText(get_label_text(key))

    def _apply_values(
        self,
        *,
        obj_tooltips=True,
        attrs_in_tree=True,
        icon_size=25,
        dns_compile=True,
        at_compile=True,
        rules_logging=True,
        rules_stateful=True,
        rules_action=0,
        rules_direction=0,
        autoconfigure_iface=True,
    ):
        """Set widget values. Parameter defaults are the application defaults."""
        self.objTooltips.setChecked(obj_tooltips)
        self.attributesInTree.setChecked(attrs_in_tree)
        if icon_size == 16:
            self.rb16.setChecked(True)
        else:
            self.rb25.setChecked(True)
        self.new_dns_name_compile_tm.setChecked(dns_compile)
        self.new_dns_name_run_tm.setChecked(not dns_compile)
        self.new_addr_tbl_compile_tm.setChecked(at_compile)
        self.new_addr_tbl_run_tm.setChecked(not at_compile)
        self.rulesLoggingOn.setChecked(rules_logging)
        self.rulesDefaultStateful.setChecked(rules_stateful)
        self.rulesDefaultAction.setCurrentIndex(rules_action)
        self.rulesDefaultDirection.setCurrentIndex(rules_direction)
        self.autoconfigure_interfaces.setChecked(autoconfigure_iface)

    @Slot()
    def _restore_defaults(self):
        """Reset all widgets to application default values."""
        self._apply_values()  # all keyword defaults are the app defaults

        # Reset installer defaults.
        self.sshPath.setText(shutil.which('ssh') or 'ssh')
        self.scpPath.setText(shutil.which('scp') or 'scp')
        self.sshTimeout.setValue(10)
        self.rememberSshPass.setChecked(False)

        # Reset appearance defaults.
        self._rules_font = QFont()
        self._tree_font = QFont()
        self._compiler_font = QFont()
        self.rulesFontDescr.setText(_font_description(self._rules_font))
        self.treeFontDescr.setText(_font_description(self._tree_font))
        self.compilerOutputFontDescr.setText(_font_description(self._compiler_font))
        self.chShowIcons.setChecked(True)
        self.showDirectionText.setChecked(True)
        self.chClipComment.setChecked(False)
        self.toolbarIconsText.setChecked(False)
        self.rb16.setEnabled(True)
        self.rb25.setEnabled(True)

        # Reset label colors and texts to defaults.
        from firewallfabrik.gui.label_settings import LABEL_DEFAULTS

        for key in LABEL_KEYS:
            defaults = LABEL_DEFAULTS.get(key, {})
            hex_color = defaults.get('color', '#ffffff')
            self._label_colors[key] = hex_color
            getattr(self, f'{key}Btn').setIcon(_color_icon(hex_color))
            getattr(self, f'{key}Text').setText(defaults.get('text', ''))

        # Reset platform/OS to all enabled.
        for row in range(self.enabled_platforms.rowCount()):
            self.enabled_platforms.item(row, 0).setCheckState(Qt.CheckState.Checked)
        for row in range(self.enabled_os.rowCount()):
            self.enabled_os.item(row, 0).setCheckState(Qt.CheckState.Checked)

    def _populate_platform_table(self):
        table = self.enabled_platforms
        table.setRowCount(len(PLATFORMS))
        for row, (key, display) in enumerate(PLATFORMS.items()):
            item = QTableWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            item.setCheckState(
                Qt.CheckState.Checked
                if is_platform_enabled(key)
                else Qt.CheckState.Unchecked
            )
            table.setItem(row, 0, item)
        table.horizontalHeader().setStretchLastSection(True)

    def _populate_os_table(self):
        table = self.enabled_os
        table.setRowCount(len(HOST_OS))
        for row, (key, display) in enumerate(HOST_OS.items()):
            item = QTableWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            item.setCheckState(
                Qt.CheckState.Checked if is_os_enabled(key) else Qt.CheckState.Unchecked
            )
            table.setItem(row, 0, item)
        table.horizontalHeader().setStretchLastSection(True)

    # ------------------------------------------------------------------
    # Installer tab: Browse slots (connected via .ui signal/slot)
    # ------------------------------------------------------------------

    @Slot()
    def findSSH(self):
        """Open a file dialog to locate the SSH utility."""
        start_dir = self.sshPath.text() or ''
        if start_dir and not Path(start_dir).is_file():
            start_dir = (
                str(Path(start_dir).parent) if Path(start_dir).parent.is_dir() else ''
            )
        fp, _ = QFileDialog.getOpenFileName(
            self,
            'Find Secure Shell utility',
            start_dir,
        )
        if fp:
            self.sshPath.setText(fp)

    @Slot()
    def findSCP(self):
        """Open a file dialog to locate the SCP utility."""
        start_dir = self.scpPath.text() or ''
        if start_dir and not Path(start_dir).is_file():
            start_dir = (
                str(Path(start_dir).parent) if Path(start_dir).parent.is_dir() else ''
            )
        fp, _ = QFileDialog.getOpenFileName(
            self,
            'Find SCP utility',
            start_dir,
        )
        if fp:
            self.scpPath.setText(fp)

    # ------------------------------------------------------------------
    # Appearance tab: Font and icon slots (connected via .ui signal/slot)
    # ------------------------------------------------------------------

    @Slot()
    def changeRulesFont(self):
        ok, font = QFontDialog.getFont(self._rules_font, self)
        if ok:
            self._rules_font = font
            self.rulesFontDescr.setText(_font_description(font))

    @Slot()
    def changeTreeFont(self):
        ok, font = QFontDialog.getFont(self._tree_font, self)
        if ok:
            self._tree_font = font
            self.treeFontDescr.setText(_font_description(font))

    @Slot()
    def changeCompilerOutputFont(self):
        ok, font = QFontDialog.getFont(self._compiler_font, self)
        if ok:
            self._compiler_font = font
            self.compilerOutputFontDescr.setText(_font_description(font))

    @Slot()
    def changeShowIcons(self):
        shown = self.chShowIcons.isChecked()
        self.rb16.setEnabled(shown)
        self.rb25.setEnabled(shown)

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

        # Appearance: fonts
        settings.setValue('UI/Fonts/RulesFont', self._rules_font.toString())
        settings.setValue('UI/Fonts/TreeFont', self._tree_font.toString())
        settings.setValue('UI/Fonts/CompilerOutputFont', self._compiler_font.toString())

        # Appearance: checkboxes
        settings.setValue('UI/Icons/ShowIconsInRules', self.chShowIcons.isChecked())
        settings.setValue(
            'UI/Icons/ShowDirectionTextInRules',
            self.showDirectionText.isChecked(),
        )
        settings.setValue('UI/ClipComment', self.chClipComment.isChecked())
        settings.setValue('UI/IconWithText', self.toolbarIconsText.isChecked())

        # Installer
        settings.setValue('SSH/SSHPath', self.sshPath.text())
        settings.setValue('SSH/SCPPath', self.scpPath.text())
        settings.setValue('SSH/SSHTimeout', self.sshTimeout.value())
        settings.setValue(
            'Environment/RememberSshPassEnabled',
            self.rememberSshPass.isChecked(),
        )

        # Persist label colors and texts.
        for key in LABEL_KEYS:
            set_label_color(key, self._label_colors[key])
            set_label_text(key, getattr(self, f'{key}Text').text())

        # DNS Name
        settings.setValue(
            'Objects/DNSName/useCompileTimeForNewObjects',
            self.new_dns_name_compile_tm.isChecked(),
        )
        # Address Table
        settings.setValue(
            'Objects/AddressTable/useCompileTimeForNewObjects',
            self.new_addr_tbl_compile_tm.isChecked(),
        )

        # Policy Rules
        settings.setValue(
            'Objects/PolicyRule/defaultLoggingState',
            self.rulesLoggingOn.isChecked(),
        )
        settings.setValue(
            'Objects/PolicyRule/defaultStateful',
            self.rulesDefaultStateful.isChecked(),
        )
        settings.setValue(
            'Objects/PolicyRule/defaultAction',
            self.rulesDefaultAction.currentIndex(),
        )
        settings.setValue(
            'Objects/PolicyRule/defaultDirection',
            self.rulesDefaultDirection.currentIndex(),
        )

        # Interface
        settings.setValue(
            'Objects/Interface/autoconfigureInterfaces',
            self.autoconfigure_interfaces.isChecked(),
        )

        # Persist platform / OS enabled states.
        for row in range(self.enabled_platforms.rowCount()):
            item = self.enabled_platforms.item(row, 0)
            set_platform_enabled(
                item.data(Qt.ItemDataRole.UserRole),
                item.checkState() == Qt.CheckState.Checked,
            )
        for row in range(self.enabled_os.rowCount()):
            item = self.enabled_os.item(row, 0)
            set_os_enabled(
                item.data(Qt.ItemDataRole.UserRole),
                item.checkState() == Qt.CheckState.Checked,
            )
