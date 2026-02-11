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

"""IPTables preprocessor.

Handles AttachedNetworks objects for iptables compilation.
Corresponds to fwbuilder's iptlib/preprocessor_ipt.py.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

import sqlalchemy

from firewallfabrik.compiler._preprocessor import Preprocessor
from firewallfabrik.core.objects import (
    AttachedNetworks,
    Firewall,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


class PreprocessorIpt(Preprocessor):
    """IPTables preprocessor: expands AttachedNetworks objects.

    For each AttachedNetworks object used in rules, determines the
    networks attached to the referenced interface and creates network
    objects for them.
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6: bool = False,
    ) -> None:
        super().__init__(session, fw, ipv6)

    def run(self) -> None:
        """Process AttachedNetworks objects on the firewall's interfaces."""
        for iface in self.fw.interfaces:
            for addr in iface.addresses:
                if not isinstance(addr, AttachedNetworks):
                    continue
                self._process_attached_networks(iface, addr)

    def _process_attached_networks(
        self,
        iface: Interface,
        attached_networks: AttachedNetworks,
    ) -> None:
        """Generate network objects for the networks attached to an interface.

        For each address on the interface, computes the network address
        and adds it as a member of the AttachedNetworks group.
        """
        for addr in iface.addresses:
            if isinstance(addr, AttachedNetworks):
                continue

            addr_str = addr.get_address()
            mask_str = addr.get_netmask()
            if not addr_str or not mask_str:
                continue

            try:
                net = ipaddress.ip_network(f'{addr_str}/{mask_str}', strict=False)
            except ValueError:
                continue

            # Create a transient network object representing this attached network
            if isinstance(addr, (IPv4, Network)):
                if self.ipv6:
                    continue
                net_addr_str = str(net.network_address)
            elif isinstance(addr, (IPv6, NetworkIPv6)):
                if not self.ipv6:
                    continue
                net_addr_str = str(net.network_address)
            else:
                continue

            self.info(
                f'  Attached network: {net_addr_str}/{net.prefixlen} '
                f'on interface {iface.name}',
            )
