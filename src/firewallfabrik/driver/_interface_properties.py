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
        """Determine if addresses should be managed for this interface.

        Returns (should_manage, update_addresses, ignore_addresses).
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

        update_addresses = self._get_list_of_addresses(iface)
        return True, update_addresses, ignore_addresses

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
