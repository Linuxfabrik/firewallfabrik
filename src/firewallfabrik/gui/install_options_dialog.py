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

"""Install options dialog — collects per-firewall install parameters."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.firewall_installer import InstallConfig
from firewallfabrik.gui.ui_loader import FWFUiLoader

_CANCEL_ALL = -1

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'instoptionsdialog_q.ui'


class InstallOptionsDialog(QDialog):
    """Modal dialog that collects per-firewall install parameters.

    Returns:
        QDialog.Accepted (1): proceed with install.
        QDialog.Rejected (0): skip this firewall.
        -1: cancel all remaining firewalls.
    """

    def __init__(
        self,
        fw_name: str,
        config: InstallConfig,
        installing_many: bool,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._config = config

        loader = FWFUiLoader(self)
        loader.load(str(_UI_PATH))

        self.dialogTitleLine.setText(
            f'<p align="center"><b><font size="+2">'
            f"Install options for firewall '{fw_name}'"
            f'</font></b></p>'
        )

        # Pre-fill from config.
        self.uname.setText(config.user)
        self.altAddress.setText(config.alt_address or config.mgmt_address)
        self.verbose.setChecked(config.verbose)
        self.quiet.setChecked(config.quiet)
        self.copyFWB.setChecked(config.copy_fwb)
        self.batchInstall.setChecked(config.batch_install)

        # Hide batch install option when installing a single firewall.
        if not installing_many:
            self.batchInstallText.hide()
            self.batchInstall.hide()

        # Hide Cancel All when only one firewall.
        if not installing_many:
            self.cancelAllButton.hide()

    def get_config(self) -> InstallConfig:
        """Return the updated config from the dialog fields."""
        self._config.user = self.uname.text().strip() or 'root'
        addr = self.altAddress.text().strip()
        if addr:
            self._config.alt_address = addr
            self._config.mgmt_address = addr
        self._config.verbose = self.verbose.isChecked()
        self._config.quiet = self.quiet.isChecked()
        self._config.copy_fwb = self.copyFWB.isChecked()
        self._config.batch_install = self.batchInstall.isChecked()
        return self._config

    @Slot()
    def cancelAll(self):
        self.done(_CANCEL_ALL)

    @Slot()
    def batchInstallStateChange(self):
        # When batch install is checked, the alt address field is
        # disabled — the same address is reused for all firewalls.
        self.altAddress.setEnabled(not self.batchInstall.isChecked())
