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

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class HostDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('hostdialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.MACmatching.setChecked(data.get('mac_filter_enabled') == 'True')

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = self._obj.data or {}
        data['mac_filter_enabled'] = str(self.MACmatching.isChecked())
        self._obj.data = data


class FirewallDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('firewalldialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self._set_combo_text(self.platform, data.get('platform', ''))
        self._set_combo_text(self.version, data.get('version', ''))
        self._set_combo_text(self.hostOS, data.get('host_OS', ''))
        self.inactive.setChecked(data.get('inactive') == 'True')

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = self._obj.data or {}
        data['platform'] = self.platform.currentText()
        data['version'] = self.version.currentText()
        data['host_OS'] = self.hostOS.currentText()
        data['inactive'] = str(self.inactive.isChecked())
        self._obj.data = data

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
        data = self._obj.data or {}
        self.label.setText(data.get('label', ''))
        self.seclevel.setValue(int(data.get('security_level', 0)))
        self.management.setChecked(bool(data.get('management', False)))
        self.unprotected.setChecked(bool(data.get('unprotected', False)))
        self.dedicated_failover.setChecked(bool(data.get('dedicated_failover', False)))
        if data.get('dyn', False):
            self.dynamic.setChecked(True)
        elif data.get('unnum', False):
            self.unnumbered.setChecked(True)
        else:
            self.regular.setChecked(True)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = self._obj.data or {}
        data['label'] = self.label.text()
        data['security_level'] = str(self.seclevel.value())
        data['management'] = self.management.isChecked()
        data['unprotected'] = self.unprotected.isChecked()
        data['dedicated_failover'] = self.dedicated_failover.isChecked()
        data['dyn'] = self.dynamic.isChecked()
        data['unnum'] = self.unnumbered.isChecked()
        self._obj.data = data
