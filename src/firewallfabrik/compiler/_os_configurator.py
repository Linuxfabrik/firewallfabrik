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

"""OSConfigurator base class.

Generates OS-specific configuration script sections:
interface configuration, kernel parameters, module loading, etc.
"""

from __future__ import annotations

import io
import ipaddress
from typing import TYPE_CHECKING

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core.objects import (
    Firewall,
    Interface,
    Network,
    NetworkIPv6,
)
from firewallfabrik.driver._interface_properties import (
    LinuxInterfaceProperties,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


class OSConfigurator(BaseCompiler):
    """Generates OS-specific configuration script sections.

    Platform-specific subclasses produce interface configuration,
    kernel parameter settings, module loading, etc.
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6: bool = False,
    ) -> None:
        super().__init__()
        self.session: sqlalchemy.orm.Session = session
        self.fw: Firewall = fw
        self.ipv6: bool = ipv6
        self.output: io.StringIO = io.StringIO()
        self.virtual_addresses: list = []
        self.virtual_addresses_for_nat: dict[str, str] = {}
        self.known_interfaces: list[str] = []

    def prolog(self) -> str:
        return ''

    def epilog(self) -> str:
        return ''

    def print_shell_functions(self) -> str:
        return ''

    def generate_interfaces(self) -> str:
        return ''

    def add_virtual_address_for_nat(self, addr, expand_network: bool = False) -> None:
        """Register an address the firewall has to carry for a NAT rule.

        A DNAT rule to a spare address of a directly attached segment only
        works when the firewall answers ARP for it, and the kernel answers
        only for an address that routes as ``RTN_LOCAL``
        (netfilter linux/net/ipv4/arp.c, ``arp_process``).  So the address is
        recorded against the interface whose network holds it and added with
        ``ip addr add`` when the script runs.  An SNAT rule to a spare
        address has the same problem for the return traffic.

        *expand_network* mirrors which of fwbuilder's two
        ``addVirtualAddressForNAT`` overloads applies.  An SNAT or DNAT rule
        reaches the one taking an ``Address``, so even a network object
        contributes its own address once; only a NETMAP rule explicitly casts
        to ``Network`` and gets one address per host.
        """
        if not self.fw.get_option('manage_virtual_addr'):
            return

        for address, prefix_len, iface in self._virtual_address_targets(
            addr, expand_network
        ):
            entry = f'{address}/{prefix_len}'
            existing = self.virtual_addresses_for_nat.get(iface.name, '')
            if entry in existing.split():
                continue
            self.virtual_addresses_for_nat[iface.name] = f'{existing} {entry}'.strip()
            self.virtual_addresses.append(address)

    # A network in a NETMAP rule becomes one address per host.  fwbuilder
    # walks the whole range; a mistyped prefix would put tens of thousands of
    # addresses on an interface, so stop and say so instead.
    MAX_VIRTUAL_ADDRESSES_PER_NETWORK = 256

    def _virtual_address_targets(
        self, addr, expand_network: bool
    ) -> list[tuple[str, int, Interface]]:
        """Return (address, prefix length, interface) for *addr*.

        The prefix length is the one the matching interface carries, because
        the virtual address joins that interface's subnet.
        """
        addr_str = addr.get_address() if hasattr(addr, 'get_address') else None
        if not addr_str:
            return []

        is_network = expand_network and isinstance(addr, (Network, NetworkIPv6))
        host_prefix = 128 if isinstance(addr, NetworkIPv6) else 32
        try:
            if is_network:
                mask = addr.get_netmask()
                if not mask:
                    return []
                network = ipaddress.ip_network(f'{addr_str}/{mask}', strict=False)
                # fwbuilder walks from the network address up to, but not
                # including, the broadcast address, and gives each one a host
                # prefix.
                count = int(network.broadcast_address) - int(network.network_address)
                if count > self.MAX_VIRTUAL_ADDRESSES_PER_NETWORK:
                    self.warning(
                        f'Not adding virtual addresses for "{addr.name}": the '
                        f'network holds {count} addresses, more than the '
                        f'{self.MAX_VIRTUAL_ADDRESSES_PER_NETWORK} this would '
                        f'put on an interface'
                    )
                    return []
                wanted = [
                    (str(network.network_address + offset), host_prefix)
                    for offset in range(count)
                ]
            else:
                wanted = [(addr_str, None)]
        except (ValueError, TypeError):
            return []

        targets = []
        unplaceable = []
        for address, forced_prefix in wanted:
            iface, prefix_len = self._interface_carrying(address)
            if iface is None:
                unplaceable.append(address)
                continue
            if self._interface_already_has(iface, address):
                # The interface is configured with this address anyway, so
                # adding it again would only repeat it in the ip command.
                continue
            targets.append((address, forced_prefix or prefix_len, iface))
        if unplaceable:
            # One sentence per object, the way fwbuilder says it: its
            # `addVirtualAddressForNAT(const Network*)` asks
            # `findInterfaceFor(nw, fw)` once, for the network, and warns
            # naming the network's own address
            # (OSConfigurator_linux24.cpp:236).  Saying it once per host a
            # network stands for is 254 lines about one object, and they go
            # into the generated script as comments.
            self.warning(
                f'Can not add virtual address {unplaceable[0]} (object '
                f'"{addr.name}"): no interface of the firewall is on '
                f'that network'
            )
        return targets

    @staticmethod
    def _interface_already_has(iface: Interface, address: str) -> bool:
        """Whether *iface* is already configured with *address*."""
        return any(a.get_address() == address for a in iface.addresses)

    def _interface_carrying(self, address: str) -> tuple[Interface | None, int]:
        """Find the firewall interface whose subnet contains *address*."""
        try:
            target = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            return None, 0

        for iface in self.fw.interfaces:
            if not iface.is_regular():
                continue
            for iface_addr in iface.addresses:
                addr_str = iface_addr.get_address()
                mask_str = iface_addr.get_netmask()
                if not addr_str or not mask_str:
                    continue
                try:
                    network = ipaddress.ip_network(
                        f'{addr_str}/{mask_str}', strict=False
                    )
                except (ValueError, TypeError):
                    continue
                if target in network:
                    return iface, network.prefixlen
        return None, 0

    def print_virtual_addresses_for_nat_commands(self) -> str:
        """Add the NAT addresses without touching the interface's own ones.

        This is the case where "Add virtual addresses for NAT" is on but
        "Configure interfaces" is off: the addresses the admin configured
        elsewhere must stay, so they go on the ignore list and only the NAT
        addresses are managed.

        Ports fwbuilder's
        ``OSConfigurator_linux24::printVirtualAddressesForNatCommands``.
        """
        int_prop = LinuxInterfaceProperties()
        gencmd: list[str] = []

        for iface in self.fw.interfaces:
            should_manage, update_addresses, ignore_addresses = (
                int_prop.manage_ip_addresses(iface)
            )
            if should_manage:
                virtual = self.virtual_addresses_for_nat.get(iface.name, '')
                if virtual:
                    ignore_addresses = [*ignore_addresses, *update_addresses]
                    gencmd.append(
                        self._print_update_address_command(
                            iface, [virtual], ignore_addresses
                        )
                    )
            self.known_interfaces.append(iface.name)

        if not gencmd:
            return ''
        return '\n'.join(gencmd) + '\n'

    def print_path_for_all_tools(self, os_name: str) -> str:
        return ''
