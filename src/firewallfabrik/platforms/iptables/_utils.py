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

"""IPTables utility functions.

Corresponds to fwbuilder's iptlib/ipt_utils.py.
"""

from __future__ import annotations

import re

from firewallfabrik.core.objects import (
    Address,
    AddressTable,
    Interface,
    PhysAddress,
)


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


def get_address_table_var_name(at: AddressTable) -> str:
    """Generate a shell variable name for an address table."""
    name = at.name
    var_name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    return f'at_{var_name}'


def normalize_set_name(name: str) -> str:
    """Normalize an ipset set name (max 31 chars, valid chars only)."""
    result = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if len(result) > 31:
        result = result[:31]
    return result


def expand_interface_with_phys_address(
    iface: Interface,
    addr_obj: Address,
) -> tuple[Address | None, PhysAddress | None]:
    """Find the MAC address associated with an interface address.

    Returns (addr, phys_addr) tuple where phys_addr is the MAC address
    if found, None otherwise.
    """
    phys_addr = None
    for a in iface.addresses:
        if isinstance(a, PhysAddress):
            phys_addr = a
            break

    return addr_obj, phys_addr
