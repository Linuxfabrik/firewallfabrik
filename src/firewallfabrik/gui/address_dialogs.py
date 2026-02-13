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

import ipaddress
import logging

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QMessageBox

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog

logger = logging.getLogger(__name__)


def _validate_ipv4(address_text):
    """Validate an IPv4 address string.  Return the normalised address or *None*."""
    try:
        return str(ipaddress.IPv4Address(address_text.strip()))
    except ValueError:
        return None


def _validate_ipv6(address_text):
    """Validate an IPv6 address string.  Return the normalised address or *None*."""
    try:
        return str(ipaddress.IPv6Address(address_text.strip()))
    except ValueError:
        return None


def _validate_ipv4_netmask(netmask_text):
    """Validate an IPv4 netmask (dotted-decimal or CIDR prefix length).

    Returns the normalised netmask string or *None*.
    """
    text = netmask_text.strip()
    if not text:
        return None
    # CIDR prefix length (e.g. "24").
    try:
        prefix = int(text)
        if 0 <= prefix <= 32:
            net = ipaddress.IPv4Network(f'0.0.0.0/{prefix}', strict=False)
            return str(net.netmask)
        return None
    except ValueError:
        pass
    # Dotted-decimal (e.g. "255.255.255.0").
    try:
        addr = ipaddress.IPv4Address(text)
        # Verify it's a valid contiguous netmask by round-tripping
        # through IPv4Network.
        ipaddress.IPv4Network(f'0.0.0.0/{addr}', strict=False)
        return str(addr)
    except ValueError:
        return None


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

    def _apply_changes(self):
        addr = self.address.text().strip()
        if addr and _validate_ipv4(addr) is None:
            QMessageBox.warning(
                self,
                self.tr('Invalid Address'),
                self.tr("Illegal IP address '%1'").replace('%1', addr),
            )
            return
        nm = self.netmask.text().strip()
        if nm and _validate_ipv4_netmask(nm) is None:
            QMessageBox.warning(
                self,
                self.tr('Invalid Netmask'),
                self.tr("Illegal netmask '%1'").replace('%1', nm),
            )
            return
        super()._apply_changes()

    @Slot()
    def addressEntered(self):
        """Parse CIDR notation (e.g. '192.168.1.1/24') into address + netmask."""
        text = self.address.text().strip()
        if '/' not in text:
            return
        try:
            net = ipaddress.IPv4Network(text, strict=False)
            self.address.setText(str(ipaddress.IPv4Address(text.split('/')[0])))
            self.netmask.setText(str(net.netmask))
        except ValueError:
            pass

    @Slot()
    def DNSlookup(self):
        # TODO
        pass


class IPv6Dialog(_BaseAddressDialog):
    def __init__(self, parent=None):
        super().__init__('ipv6dialog_q.ui', parent)

    def _apply_changes(self):
        addr = self.address.text().strip()
        if addr and _validate_ipv6(addr) is None:
            QMessageBox.warning(
                self,
                self.tr('Invalid Address'),
                self.tr("Illegal IPv6 address '%1'").replace('%1', addr),
            )
            return
        nm = self.netmask.text().strip()
        if nm:
            try:
                prefix = int(nm)
                if prefix < 1 or prefix > 127:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(
                    self,
                    self.tr('Invalid Netmask'),
                    self.tr("Illegal netmask '%1'").replace('%1', nm),
                )
                return
        super()._apply_changes()

    @Slot()
    def addressEntered(self):
        """Parse CIDR notation (e.g. '2001:db8::1/64') into address + prefix length."""
        text = self.address.text().strip()
        if '/' not in text:
            return
        try:
            net = ipaddress.IPv6Network(text, strict=False)
            self.address.setText(str(ipaddress.IPv6Address(text.split('/')[0])))
            self.netmask.setText(str(net.prefixlen))
        except ValueError:
            pass

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

    def _apply_changes(self):
        addr = self.address.text().strip()
        if addr and _validate_ipv4(addr) is None:
            QMessageBox.warning(
                self,
                self.tr('Invalid Address'),
                self.tr("Illegal IP address '%1'").replace('%1', addr),
            )
            return
        nm = self.netmask.text().strip()
        if nm and _validate_ipv4_netmask(nm) is None:
            QMessageBox.warning(
                self,
                self.tr('Invalid Netmask'),
                self.tr("Illegal netmask '%1'").replace('%1', nm),
            )
            return
        super()._apply_changes()

    @Slot()
    def addressEntered(self):
        """Parse CIDR notation (e.g. '192.168.1.0/24') into address + netmask."""
        text = self.address.text().strip()
        if '/' not in text:
            return
        try:
            net = ipaddress.IPv4Network(text, strict=False)
            self.address.setText(str(net.network_address))
            self.netmask.setText(str(net.netmask))
        except ValueError:
            pass


class NetworkDialogIPv6(_BaseAddressDialog):
    def __init__(self, parent=None):
        super().__init__('networkdialogipv6_q.ui', parent)

    def _apply_changes(self):
        addr = self.address.text().strip()
        if addr and _validate_ipv6(addr) is None:
            QMessageBox.warning(
                self,
                self.tr('Invalid Address'),
                self.tr("Illegal IPv6 address '%1'").replace('%1', addr),
            )
            return
        nm = self.netmask.text().strip()
        if nm:
            try:
                prefix = int(nm)
                if prefix < 1 or prefix > 127:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(
                    self,
                    self.tr('Invalid Netmask'),
                    self.tr("Illegal netmask '%1'").replace('%1', nm),
                )
                return
        super()._apply_changes()

    @Slot()
    def addressEntered(self):
        """Parse CIDR notation (e.g. '2001:db8::/32') into address + prefix length."""
        text = self.address.text().strip()
        if '/' not in text:
            return
        try:
            net = ipaddress.IPv6Network(text, strict=False)
            self.address.setText(str(net.network_address))
            self.netmask.setText(str(net.prefixlen))
        except ValueError:
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
        start_text = self.rangeStart.text().strip()
        end_text = self.rangeEnd.text().strip()
        # Validate both addresses and ensure same family.
        start_addr = end_addr = None
        if start_text:
            try:
                start_addr = ipaddress.ip_address(start_text)
            except ValueError:
                QMessageBox.warning(
                    self,
                    self.tr('Invalid Address'),
                    self.tr("Illegal IP address '%1'").replace(
                        '%1',
                        start_text,
                    ),
                )
                return
        if end_text:
            try:
                end_addr = ipaddress.ip_address(end_text)
            except ValueError:
                QMessageBox.warning(
                    self,
                    self.tr('Invalid Address'),
                    self.tr("Illegal IP address '%1'").replace(
                        '%1',
                        end_text,
                    ),
                )
                return
        if start_addr and end_addr:
            if start_addr.version != end_addr.version:
                QMessageBox.warning(
                    self,
                    self.tr('Address Mismatch'),
                    self.tr(
                        "Range start '%1' and end '%2' must be the same IP version.",
                    )
                    .replace('%1', start_text)
                    .replace('%2', end_text),
                )
                return
            # Auto-correct: end must be >= start.
            if end_addr < start_addr:
                end_addr = start_addr
                self.rangeEnd.setText(str(end_addr))
        start = dict(self._obj.start_address or {})
        start['address'] = self.rangeStart.text().strip()
        self._obj.start_address = start
        end = dict(self._obj.end_address or {})
        end['address'] = self.rangeEnd.text().strip()
        self._obj.end_address = end

    @Slot()
    def addressEntered(self):
        """Parse CIDR notation in rangeStart into start/end host addresses."""
        text = self.rangeStart.text().strip()
        if '/' not in text:
            return
        try:
            net = ipaddress.ip_network(text, strict=False)
            hosts = list(net.hosts())
            if hosts:
                self.rangeStart.setText(str(hosts[0]))
                self.rangeEnd.setText(str(hosts[-1]))
            else:
                # Single-host network (e.g. /32 or /128).
                self.rangeStart.setText(str(net.network_address))
                self.rangeEnd.setText(str(net.network_address))
        except ValueError:
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
