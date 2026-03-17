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


def _is_true(val):
    """Return True for bool True or string 'True'/'true'."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() == 'true'
    return False


def _set_data_key(data: dict, key: str, value, default=None) -> None:
    """Set *key* in *data* only if it already exists or *value* differs from *default*.

    This avoids injecting new keys with default values into the data
    dict, which would cause the ORM to detect a change and bump
    ``lastModified`` even when the user didn't change anything.
    """
    if key in data or value != default:
        data[key] = value


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
        data = self._obj.data or {}
        self.MACmatching.setChecked(_is_true(data.get('mac_filter_enabled')))

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        old_data = self._obj.data or {}
        data = dict(old_data)
        _set_data_key(data, 'mac_filter_enabled', self.MACmatching.isChecked(), False)
        if data != old_data:
            self._obj.data = data


class FirewallDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('firewalldialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}

        # Populate combos with enabled entries before setting the current value.
        self.platform.clear()
        for display in get_enabled_platforms().values():
            self.platform.addItem(display)
        self.hostOS.clear()
        for display in get_enabled_os().values():
            self.hostOS.addItem(display)

        self._set_combo_text(self.platform, data.get('platform', ''))
        self._set_combo_text(self.version, data.get('version', ''))
        host_os = data.get('host_OS', '')
        self._set_combo_text(self.hostOS, HOST_OS.get(host_os, host_os))
        self.inactive.setChecked(data.get('inactive') in (True, 'True'))
        for attr, key in (
            ('last_modified', 'lastModified'),
            ('last_compiled', 'lastCompiled'),
            ('last_installed', 'lastInstalled'),
        ):
            ts = int(data.get(key, 0) or 0)
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
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        old_data = self._obj.data or {}
        data = dict(old_data)
        data['platform'] = self.platform.currentText()
        data['version'] = self.version.currentText()
        host_os_text = self.hostOS.currentText()
        data['host_OS'] = _HOST_OS_INTERNAL.get(host_os_text, host_os_text)
        _set_data_key(data, 'inactive', self.inactive.isChecked(), False)
        if data != old_data:
            self._obj.data = data

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

    def _is_bridge_port(self):
        """Check if this interface is a bridge port.

        Mirrors fwbuilder's ``Interface::isBridgePort()``: a
        sub-interface whose parent has ``type == "bridge"`` in its
        options is a bridge port, regardless of an explicit
        ``bridge_port`` option.
        """
        if self._obj.is_bridge_port():
            return True
        parent = getattr(self._obj, 'parent_interface', None)
        if parent is not None:
            return (parent.options or {}).get('type') == 'bridge'
        return False

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.label.setText(data.get('label', ''))
        self.seclevel.setValue(int(data.get('security_level', 0)))
        self.management.setChecked(bool(data.get('management', False)))
        self.dedicated_failover.setChecked(bool(data.get('dedicated_failover', False)))
        if data.get('dyn', False):
            self.dynamic.setChecked(True)
        elif data.get('unnum', False):
            self.unnumbered.setChecked(True)
        else:
            self.regular.setChecked(True)

        # Bridge port interfaces: hide regular options, show label.
        if self._is_bridge_port():
            self.regular.hide()
            self.dynamic.hide()
            self.unnumbered.hide()
            self.management.hide()
            self.dedicated_failover.hide()
            self.bridge_port_label.show()
        else:
            self.regular.show()
            self.dynamic.show()
            self.unnumbered.show()
            self.management.show()
            self.dedicated_failover.show()
            self.bridge_port_label.hide()

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        old_data = self._obj.data or {}
        data = dict(old_data)
        _set_data_key(data, 'label', self.label.text(), '')
        _set_data_key(data, 'security_level', str(self.seclevel.value()), '0')
        _set_data_key(data, 'management', self.management.isChecked(), False)
        _set_data_key(
            data, 'dedicated_failover', self.dedicated_failover.isChecked(), False
        )
        _set_data_key(data, 'dyn', self.dynamic.isChecked(), False)
        _set_data_key(data, 'unnum', self.unnumbered.isChecked(), False)
        if data != old_data:
            self._obj.data = data

        # Autoconfigure interface type from name if enabled in Preferences.
        from PySide6.QtCore import QSettings

        if QSettings().value(
            'Objects/Interface/autoconfigureInterfaces', True, type=bool
        ):
            from firewallfabrik.gui.interface_autoconfigure import guess_interface_type

            parent = getattr(self._obj, 'parent_interface', None)
            guessed = guess_interface_type(self._obj.name or '', parent)

            # Handle VLAN name mismatch warning.
            if '_vlan_name_mismatch' in guessed:
                from PySide6.QtWidgets import QMessageBox

                parent_name = guessed['_vlan_name_mismatch']
                QMessageBox.warning(
                    self.window(),
                    'FirewallFabrik',
                    f"'{self._obj.name}' looks like a name of a VLAN "
                    f'interface but it does not match the name of the '
                    f"parent interface '{parent_name}'",
                )
                return

            # Handle top-level VLAN that needs a parent interface.
            if '_vlan_needs_parent' in guessed:
                from PySide6.QtWidgets import QMessageBox

                base_name = guessed['_vlan_needs_parent']
                QMessageBox.warning(
                    self.window(),
                    'FirewallFabrik',
                    f"'{self._obj.name}' looks like a name of a VLAN "
                    f'interface but it is not a sub-interface of '
                    f"'{base_name}'. Create it as a sub-interface of "
                    f"'{base_name}' instead.",
                )
                return

            if guessed:
                options = dict(self._obj.options or {})
                changed = False

                # Handle special _set_unnumbered flag (bonding slaves).
                if guessed.pop('_set_unnumbered', False):
                    old_data = self._obj.data or {}
                    if not old_data.get('unnum', False):
                        new_data = dict(old_data)
                        new_data['unnum'] = True
                        self._obj.data = new_data
                        self.unnumbered.setChecked(True)

                for key, val in guessed.items():
                    if key not in options or not options[key]:
                        options[key] = val
                        changed = True
                if changed:
                    self._obj.options = options

    @Slot()
    def openIfaceDialog(self):
        """Open the advanced interface settings dialog (device type, VLAN, bridge, bonding)."""
        from firewallfabrik.gui.iface_opts_dialog import IfaceOptsDialog

        dlg = IfaceOptsDialog(self._obj, parent=self.window())
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.changed.emit()
