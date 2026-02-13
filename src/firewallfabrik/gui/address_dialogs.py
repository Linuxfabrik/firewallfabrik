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

"""Editor panel dialogs for address objects."""

from PySide6.QtCore import Slot

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class _BaseAddressDialog(BaseObjectDialog):
    """Base for IPv4/IPv6/Network/NetworkIPv6 dialogs (name + address + netmask)."""

    def _populate(self):
        inet = self._obj.inet_addr_mask or {}
        self.obj_name.setText(self._obj.name or '')
        self.address.setText(inet.get('address', ''))
        self.netmask.setText(inet.get('netmask', ''))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        inet = dict(self._obj.inet_addr_mask or {})
        inet['address'] = self.address.text()
        inet['netmask'] = self.netmask.text()
        self._obj.inet_addr_mask = inet


class IPv4Dialog(_BaseAddressDialog):
    def __init__(self, parent=None):
        super().__init__('ipv4dialog_q.ui', parent)

    @Slot()
    def DNSlookup(self):
        # TODO
        pass


class IPv6Dialog(_BaseAddressDialog):
    def __init__(self, parent=None):
        super().__init__('ipv6dialog_q.ui', parent)

    @Slot()
    def changed(self):
        # TODO
        pass

    @Slot()
    def DNSlookup(self):
        # TODO
        pass


class NetworkDialog(_BaseAddressDialog):
    def __init__(self, parent=None):
        super().__init__('networkdialog_q.ui', parent)

    @Slot()
    def addressEntered(self):
        # TODO
        pass


class NetworkDialogIPv6(_BaseAddressDialog):
    def __init__(self, parent=None):
        super().__init__('networkdialogipv6_q.ui', parent)

    @Slot()
    def addressEntered(self):
        # TODO
        pass


class AddressRangeDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('addressrangedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        start = self._obj.start_address or {}
        end = self._obj.end_address or {}
        self.rangeStart.setText(start.get('address', ''))
        self.rangeEnd.setText(end.get('address', ''))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        start = dict(self._obj.start_address or {})
        start['address'] = self.rangeStart.text()
        self._obj.start_address = start
        end = dict(self._obj.end_address or {})
        end['address'] = self.rangeEnd.text()
        self._obj.end_address = end

    @Slot()
    def addressEntered(self):
        # TODO
        pass


class PhysAddressDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('physaddressdialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        inet = self._obj.inet_addr_mask or {}
        self.pAddress.setText(inet.get('address', ''))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        inet = dict(self._obj.inet_addr_mask or {})
        inet['address'] = self.pAddress.text()
        self._obj.inet_addr_mask = inet

    @Slot()
    def changed(self):
        # TODO
        pass
