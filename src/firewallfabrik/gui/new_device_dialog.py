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

"""Creation dialog for Firewall, Cluster, and Host objects."""

from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QDialog, QMessageBox

from firewallfabrik.gui.platform_settings import get_enabled_os, get_enabled_platforms
from firewallfabrik.gui.ui_loader import FWFUiLoader

# Display titles per object type.
_TITLES = {
    'Cluster': 'Create New Cluster',
    'Firewall': 'Create New Firewall',
    'Host': 'Create New Host',
}


class NewDeviceDialog(QDialog):
    """Modal dialog for creating a new Firewall, Cluster, or Host.

    Mirrors fwbuilder's ``newFirewallDialog`` / ``newHostDialog`` first
    page (name + platform + host OS).  For Host objects the platform and
    host OS rows are hidden.
    """

    def __init__(self, type_name, parent=None):
        super().__init__(parent)

        ui_path = Path(__file__).resolve().parent / 'ui' / 'newdevicedialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self.setWindowTitle(_TITLES.get(type_name, f'Create New {type_name}'))

        icon_path = f':/Icons/{type_name}/icon-tree'
        self.setWindowIcon(QIcon(icon_path))

        self._type_name = type_name

        # Default name.
        self.obj_name.setText(f'New {type_name}')
        self.obj_name.selectAll()

        if type_name == 'Host':
            # Host objects have no platform/host OS fields.
            self.platformLabel.setVisible(False)
            self.platform.setVisible(False)
            self.hostOSLabel.setVisible(False)
            self.hostOS.setVisible(False)
        else:
            # Populate platform combo.
            platforms = get_enabled_platforms()
            for key, display in sorted(
                platforms.items(), key=lambda t: t[1].casefold()
            ):
                self.platform.addItem(display, key)
            # Default to iptables if available.
            idx = self.platform.findData('iptables')
            if idx >= 0:
                self.platform.setCurrentIndex(idx)

            # Populate host OS combo.
            os_entries = get_enabled_os()
            for key, display in sorted(
                os_entries.items(), key=lambda t: t[1].casefold()
            ):
                self.hostOS.addItem(display, key)

        self.adjustSize()

        # Center on parent window.
        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    def accept(self):
        """Validate input before accepting."""
        name = self.obj_name.text().strip()
        if not name:
            QMessageBox.warning(
                self,
                self.windowTitle(),
                'Please enter a name for the new object.',
            )
            self.obj_name.setFocus()
            return
        super().accept()

    def get_result(self):
        """Return ``(name, extra_data)`` for object creation.

        *extra_data* is a dict with ``platform``, ``host_OS``, and
        ``version`` keys for Firewall/Cluster, or an empty dict for Host.
        """
        name = self.obj_name.text().strip()
        if self._type_name == 'Host':
            return name, {}
        return name, {
            'host_OS': self.hostOS.currentData() or '',
            'platform': self.platform.currentData() or '',
            'version': '',
        }
