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

from firewallfabrik.core._options import option_is_true
from firewallfabrik.core.objects import Cluster
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'linux24ifaceoptsdialog_q.ui'

# Device type → text shown in the combo box.
_TYPE_LABELS = {
    '8021q': 'VLAN (802.1Q)',
    'bonding': 'bonding',
    'bridge': 'bridge',
    'ethernet': 'ethernet',
    'unknown': 'unknown',
}

# The types an interface can have, from Firewall Builder's
# ``res/os/linux24.xml`` (``interfaces/firewall`` and ``subinterfaces/<parent
# type>``, read by ``setInterfaceTypes`` in ``libgui/platforms.cpp``), in
# the order given there and deliberately not sorted.  A parent without a
# list there offers its sub-interfaces no type.
_INTERFACE_TYPES = ['ethernet', 'bridge', 'bonding']
_SUBINTERFACE_TYPES = {
    'bonding': ['ethernet', '8021q', 'unknown'],
    'bridge': ['ethernet', '8021q', 'unknown'],
    'ethernet': ['8021q', 'unknown'],
}

# Stacked widget page index per device type.
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

        # Firewall Builder hides the type of a cluster interface and stores
        # it as "cluster_interface" (linux24IfaceOptsDialog.cpp).
        self._cluster_interface = iface_obj.parent_interface is None and isinstance(
            iface_obj.device, Cluster
        )
        self.iface_type.setVisible(not self._cluster_interface)
        self.iface_type_label.setVisible(not self._cluster_interface)

        self._populate()

        self.iface_type.currentIndexChanged.connect(self._on_type_changed)
        self.bonding_policy.currentIndexChanged.connect(
            self._on_bonding_policy_changed,
        )
        self.accepted.connect(self._save)

    def _populate(self):
        opts = self._iface.options or {}
        current_type = str(opts.get('type', '') or '')

        parent = self._iface.parent_interface
        if parent is None:
            types = list(_INTERFACE_TYPES)
        else:
            # An empty parent type is ethernet, as in Firewall Builder.
            parent_type = (parent.options or {}).get('type', '') or 'ethernet'
            types = list(_SUBINTERFACE_TYPES.get(parent_type, []))
        if not current_type:
            # No type means ethernet to the compilers (Interface::isBridgePort);
            # where the list has none, Firewall Builder picks "unknown".
            current_type = 'ethernet' if 'ethernet' in types else 'unknown'
        if current_type not in types:
            # Saving must not change a type the list does not offer.
            types.append(current_type)
        for key in types:
            self.iface_type.addItem(_TYPE_LABELS.get(key, key), key)
        self.iface_type.setCurrentIndex(types.index(current_type))

        # VLAN
        self.vlan_id.setValue(int(opts.get('vlan_id', 1)))

        # Bridge
        self.enable_stp.setChecked(option_is_true(opts.get('enable_stp')))

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
        if self._cluster_interface:
            new_type = 'cluster_interface'
        else:
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
