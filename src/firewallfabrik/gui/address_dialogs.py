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

"""Editor panel dialogs for address objects (IPv4, IPv6, Network, NetworkIPv6)."""

from pathlib import Path

from PySide6.QtWidgets import QWidget

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'


class _BaseAddressDialog(QWidget):
    """Base class for address editor dialogs.

    Loads the given .ui file via ``FWFUiLoader`` and provides a common
    ``load_object`` method to populate the Name / Address / Netmask fields.
    """

    def __init__(self, ui_filename, parent=None):
        super().__init__(parent)
        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / ui_filename))

    def load_object(self, name, address, netmask):
        """Fill the editor fields with values from the database object."""
        self.obj_name.setText(name or '')
        self.address.setText(address or '')
        self.netmask.setText(netmask or '')


class IPv4Dialog(_BaseAddressDialog):

    def __init__(self, parent=None):
        super().__init__('ipv4dialog_q.ui', parent)


class IPv6Dialog(_BaseAddressDialog):

    def __init__(self, parent=None):
        super().__init__('ipv6dialog_q.ui', parent)


class NetworkDialog(_BaseAddressDialog):

    def __init__(self, parent=None):
        super().__init__('networkdialog_q.ui', parent)


class NetworkDialogIPv6(_BaseAddressDialog):

    def __init__(self, parent=None):
        super().__init__('networkdialogipv6_q.ui', parent)
