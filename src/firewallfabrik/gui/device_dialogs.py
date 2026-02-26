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

"""Editor panel dialogs for device objects (Host, Firewall, Interface)."""

from datetime import UTC, datetime

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.iptables_settings_dialog import IptablesSettingsDialog
from firewallfabrik.gui.linux_settings_dialog import LinuxSettingsDialog
from firewallfabrik.gui.nftables_settings_dialog import NftablesSettingsDialog
from firewallfabrik.gui.platform_settings import (
    HOST_OS,
    PLATFORMS,
    get_enabled_os,
    get_enabled_platforms,
)

# Reverse mapping: display name → internal key for host OS.
_HOST_OS_INTERNAL = {v: k for k, v in HOST_OS.items()}

# Platform display name → settings dialog class.
_PLATFORM_SETTINGS_DIALOG = {
    'iptables': IptablesSettingsDialog,
    'nftables': NftablesSettingsDialog,
}


class HostDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('hostdialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.MACmatching.setChecked(bool(self._obj.host_mac_filter_enabled))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.host_mac_filter_enabled = self.MACmatching.isChecked()


class FirewallDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('firewalldialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')

        # Populate combos with enabled entries before setting the current value.
        self.platform.clear()
        for display in get_enabled_platforms().values():
            self.platform.addItem(display)
        self.hostOS.clear()
        for display in get_enabled_os().values():
            self.hostOS.addItem(display)

        self._set_combo_text(self.platform, self._obj.host_platform or '')
        self._set_combo_text(self.version, self._obj.host_version or '')
        host_os = self._obj.host_os_val or ''
        self._set_combo_text(self.hostOS, HOST_OS.get(host_os, host_os))
        self.inactive.setChecked(bool(self._obj.host_inactive))
        for attr, ts in (
            ('last_modified', self._obj.host_last_modified),
            ('last_compiled', self._obj.host_last_compiled),
            ('last_installed', self._obj.host_last_installed),
        ):
            text = (
                datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')
                if ts
                else '-'
            )
            getattr(self, attr).setText(text)

        self.platform.currentTextChanged.connect(self._update_settings_buttons)
        self.hostOS.currentTextChanged.connect(self._update_settings_buttons)
        self._update_settings_buttons()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.host_platform = self.platform.currentText()
        self._obj.host_version = self.version.currentText()
        host_os_text = self.hostOS.currentText()
        self._obj.host_os_val = _HOST_OS_INTERNAL.get(host_os_text, host_os_text)
        self._obj.host_inactive = self.inactive.isChecked()

    def _update_settings_buttons(self):
        self.fwAdvanced.setEnabled(self.platform.currentText() in PLATFORMS.values())
        self.osAdvanced.setEnabled(self.hostOS.currentText() in HOST_OS.values())

    @Slot()
    def openFWDialog(self):
        dialog_cls = _PLATFORM_SETTINGS_DIALOG.get(self.platform.currentText())
        if dialog_cls is None:
            return
        dlg = dialog_cls(self._obj, parent=self.window())
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.changed.emit()

    @Slot()
    def openOSDialog(self):
        dlg = LinuxSettingsDialog(
            self._obj, platform=self.platform.currentText(), parent=self.window()
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.changed.emit()

    @staticmethod
    def _set_combo_text(combo, text):
        idx = combo.findText(text)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        elif text:
            combo.addItem(text)
            combo.setCurrentIndex(combo.count() - 1)


class InterfaceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('interfacedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.label.setText(self._obj.iface_label or '')
        self.seclevel.setValue(int(self._obj.iface_security_level or 0))
        self.management.setChecked(bool(self._obj.iface_management))
        self.unprotected.setChecked(bool(self._obj.iface_unprotected))
        self.dedicated_failover.setChecked(bool(self._obj.iface_dedicated_failover))
        if self._obj.iface_dyn:
            self.dynamic.setChecked(True)
        elif self._obj.iface_unnum:
            self.unnumbered.setChecked(True)
        else:
            self.regular.setChecked(True)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.iface_label = self.label.text()
        self._obj.iface_security_level = str(self.seclevel.value())
        self._obj.iface_management = self.management.isChecked()
        self._obj.iface_unprotected = self.unprotected.isChecked()
        self._obj.iface_dedicated_failover = self.dedicated_failover.isChecked()
        self._obj.iface_dyn = self.dynamic.isChecked()
        self._obj.iface_unnum = self.unnumbered.isChecked()

    @Slot()
    def openIfaceDialog(self):
        # TODO
        pass
