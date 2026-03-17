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

"""Advanced interface settings dialog (device type, VLAN, bridge, bonding).

Ports fwbuilder's ``linux24IfaceOptsDialog``.
"""

from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'linux24ifaceoptsdialog_q.ui'

# Device types shown in the combo box: (display_text, internal_key)
_DEVICE_TYPES = [
    ('ethernet', 'ethernet'),
    ('VLAN (802.1Q)', '8021q'),
    ('bridge', 'bridge'),
    ('bonding', 'bonding'),
]

# Stacked widget page indices matching _DEVICE_TYPES order.
_PAGE_MAP = {
    'ethernet': 0,
    '8021q': 1,
    'bridge': 2,
    'bonding': 3,
}


class IfaceOptsDialog(QDialog):
    """Modal dialog for advanced interface settings."""

    def __init__(self, iface_obj, parent=None):
        super().__init__(parent)
        self._iface = iface_obj

        loader = FWFUiLoader(self)
        loader.load(str(_UI_PATH))

        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

        # Populate device type combo.
        for display, key in _DEVICE_TYPES:
            self.iface_type.addItem(display, key)

        self._populate()

        self.iface_type.currentIndexChanged.connect(self._on_type_changed)
        self.bonding_policy.currentIndexChanged.connect(
            self._on_bonding_policy_changed,
        )
        self.accepted.connect(self._save)

    def _populate(self):
        opts = self._iface.options or {}
        current_type = opts.get('type', 'ethernet')

        # Select the current type in the combo.
        for i in range(self.iface_type.count()):
            if self.iface_type.itemData(i) == current_type:
                self.iface_type.setCurrentIndex(i)
                break

        # VLAN
        self.vlan_id.setValue(int(opts.get('vlan_id', 1)))

        # Bridge
        self.enable_stp.setChecked(bool(opts.get('enable_stp', False)))

        # Bonding
        policy = opts.get('bonding_policy', '')
        idx = self.bonding_policy.findText(policy)
        self.bonding_policy.setCurrentIndex(max(idx, 0))

        xmit = opts.get('xmit_hash_policy', '')
        idx = self.xmit_hash_policy.findText(xmit)
        self.xmit_hash_policy.setCurrentIndex(max(idx, 0))

        self.bondng_driver_options.setText(opts.get('bondng_driver_options', ''))

        self._on_type_changed()
        self._on_bonding_policy_changed()

    @Slot()
    def _on_type_changed(self):
        key = self.iface_type.currentData()
        self.options_stack.setCurrentIndex(_PAGE_MAP.get(key, 0))

    @Slot()
    def _on_bonding_policy_changed(self):
        policy = self.bonding_policy.currentText()
        self.xmit_hash_policy.setEnabled(policy in ('802.3ad', 'balance-xor'))

    def _save(self):
        opts = dict(self._iface.options or {})
        new_type = self.iface_type.currentData()
        opts['type'] = new_type

        if new_type == '8021q':
            opts['vlan_id'] = str(self.vlan_id.value())

        if new_type == 'bridge':
            opts['enable_stp'] = self.enable_stp.isChecked()

        if new_type == 'bonding':
            opts['bonding_policy'] = self.bonding_policy.currentText()
            opts['xmit_hash_policy'] = self.xmit_hash_policy.currentText()
            opts['bondng_driver_options'] = self.bondng_driver_options.text()

        self._iface.options = opts
