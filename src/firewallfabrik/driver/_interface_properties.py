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

"""Interface name validation per platform."""

from __future__ import annotations

import re

from firewallfabrik.core.objects import (
    Interface,
)

#: The failover protocols whose shared address the generated script puts
#: on the interface itself, rather than leaving it to the daemon.  Empty
#: on Linux: `res/os/linux24.xml` sets `manage_addresses` False for vrrp,
#: heartbeat and openais.  It is a set rather than a constant because the
#: question is per protocol, and a resource file is where the answer comes
#: from.
FAILOVER_PROTOCOLS_MANAGING_ADDRESSES: frozenset[str] = frozenset()


def get_interface_var_name(iface: Interface, suffix: str = '') -> str:
    """Generate a shell variable name for an interface.

    Replaces characters not valid in shell variable names with underscores.
    E.g., "eth0.100" -> "i_eth0_100"
    """
    name = iface.name
    # Replace non-alphanumeric characters with underscore
    var_name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    if suffix:
        return f'i_{var_name}_{suffix}'
    return f'i_{var_name}'


class InterfaceProperties:
    """Platform-agnostic interface validation and name checking."""

    def validate_interface_name(self, name: str) -> tuple[bool, str]:
        """Check if interface name is valid. Returns (ok, error_msg)."""
        if ' ' in name:
            return False, f"Interface name '{name}' contains spaces"
        if '-' in name and not self._allow_hyphens():
            return False, f"Interface name '{name}' contains hyphens"
        if not name:
            return False, 'Interface name is empty'
        return True, ''

    def _allow_hyphens(self) -> bool:
        return False

    def looks_like_vlan(self, name: str) -> bool:
        """Check if name looks like a VLAN interface (e.g., eth0.100)."""
        return bool(re.match(r'^.+\.\d+$', name))

    def parse_vlan(self, name: str) -> tuple[str, int] | None:
        """Parse VLAN interface name. Returns (base_name, vlan_id) or None."""
        m = re.match(r'^(.+)\.(\d+)$', name)
        if m:
            return m.group(1), int(m.group(2))
        return None

    def is_valid_vlan_name(
        self,
        name: str,
        parent_name: str,
    ) -> tuple[bool, str]:
        """Validate VLAN interface name against parent."""
        parsed = self.parse_vlan(name)
        if parsed is None:
            return False, f"'{name}' is not a valid VLAN interface name"
        base, _vlan_id = parsed
        if base != parent_name:
            return False, (
                f"VLAN interface '{name}' base name '{base}' "
                f"does not match parent '{parent_name}'"
            )
        return True, ''

    def is_eligible_for_cluster(self, iface: Interface) -> bool:
        """Check if interface can be part of a cluster."""
        return not iface.is_loopback()

    def manage_ip_addresses(
        self,
        iface: Interface,
    ) -> tuple[bool, list[str], list[str]]:
        """Which addresses of *iface* the generated script configures.

        Returns ``(should_manage, update_addresses, ignore_addresses)``,
        the three arguments of the ``update_addresses_of_interface`` shell
        function: whether to emit the call at all, the addresses the
        interface is to end up with, and the addresses the function must
        leave exactly as it finds them.

        Ports ``interfaceProperties::manageIpAddresses``.  The second list
        exists for clusters: the address a failover group shares is put on
        and taken off the interface by keepalived, heartbeat or corosync,
        and none of the three wants it managed from outside
        (``manage_addresses`` is false for every one of them in Firewall
        Builder's host OS resource file).  So the copy of a cluster
        interface configures nothing of its own, and the member's own
        interface of that name says "ignore the shared address" - without
        which the script would take the address away from whichever member
        is master, on every activation, and add it on the other one at the
        same time.
        """
        update_addresses: list[str] = []
        ignore_addresses: list[str] = []

        if (
            iface.is_dynamic()
            or iface.is_bridge_port()
            or iface.is_slave()
            or iface.is_unnumbered()
        ):
            return False, update_addresses, ignore_addresses

        if iface.cluster_interface:
            if iface.is_loopback():
                return False, update_addresses, ignore_addresses
            if self._failover_manages_addresses(iface):
                return True, self._get_list_of_addresses(iface), ignore_addresses
            return False, update_addresses, ignore_addresses

        update_addresses = self._get_list_of_addresses(iface)
        device = iface.device
        for other in getattr(device, 'interfaces', []) or []:
            if (
                other.name == iface.name
                and other.cluster_interface
                and not self._failover_manages_addresses(other)
            ):
                ignore_addresses = self._get_list_of_addresses(other)
                break
        return True, update_addresses, ignore_addresses

    @staticmethod
    def _failover_manages_addresses(cluster_iface: Interface) -> bool:
        """Does the failover protocol want its address configured for it?

        `manage_addresses` in Firewall Builder's host OS resource file,
        which says False for vrrp, heartbeat and openais alike - on Linux
        the daemon owns the address, and taking it away from under one is
        what the ignore list exists to prevent.  A cluster interface with
        no failover group (the loopback of a cluster) answers False too:
        there is no protocol to ask.
        """
        protocol = (cluster_iface.options or {}).get('failover_protocol', '')
        return protocol in FAILOVER_PROTOCOLS_MANAGING_ADDRESSES

    @staticmethod
    def _get_list_of_addresses(iface: Interface) -> list[str]:
        """Get list of addresses as 'addr/prefix' strings."""
        import ipaddress

        addr_list: list[str] = []
        for addr_obj in iface.addresses:
            addr_str = addr_obj.get_address()
            mask_str = addr_obj.get_netmask()
            if addr_str and mask_str:
                try:
                    net = ipaddress.ip_network(f'{addr_str}/{mask_str}', strict=False)
                    addr_list.append(f'{addr_str}/{net.prefixlen}')
                except ValueError:
                    addr_list.append(f'{addr_str}/{mask_str}')
        return addr_list


class LinuxInterfaceProperties(InterfaceProperties):
    """Linux-specific interface validation."""

    def _allow_hyphens(self) -> bool:
        return True

    def looks_like_vlan(self, name: str) -> bool:
        if super().looks_like_vlan(name):
            return True
        return bool(re.match(r'^vlan\d+$', name))
