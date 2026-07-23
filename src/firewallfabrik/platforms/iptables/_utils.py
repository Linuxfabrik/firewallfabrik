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
from firewallfabrik.driver._interface_properties import (
    get_interface_var_name,
)

__all__ = ['get_interface_var_name']

# Version assumed for a firewall object that does not pin an iptables
# version.  The compiler adapts its output to the target version in a
# number of places (extrapositioned negation since 1.4.3, ``-m conntrack``
# since 1.4.4, ``-w`` since 1.4.20, ``-m set`` since 1.4.1.1).  Without a
# pinned version the target is whatever iptables the host runs, which for
# every currently supported distribution is 1.8.x.  Assuming the oldest
# known release instead would emit forms that current iptables rejects,
# such as the intrapositioned ``-s ! 192.0.2.0/24``.
DEFAULT_IPTABLES_VERSION = '1.8'


def get_iptables_version(fw) -> str:
    """Return the iptables version a firewall is compiled for."""
    return fw.version or DEFAULT_IPTABLES_VERSION


def version_compare(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""

    def _normalize(v):
        return [int(x) for x in v.split('.') if x.isdigit()]

    parts1 = _normalize(v1) if v1 else [0]
    parts2 = _normalize(v2) if v2 else [0]
    for a, b in zip(parts1, parts2, strict=False):
        if a < b:
            return -1
        if a > b:
            return 1
    if len(parts1) < len(parts2):
        return -1
    if len(parts1) > len(parts2):
        return 1
    return 0


# Seconds the generated script waits for the xtables lock.  A bare "-w"
# makes iptables block indefinitely (xtables_lock() only arms the alarm
# for a positive wait), which would stall an unattended rollout instead
# of failing; with no "-w" at all iptables gives up on the first lock
# collision.  Waiting a few seconds and then aborting with a clear
# message is the useful behaviour for a deployment script.  The bounded
# form needs iptables 1.6.0; older releases only understand a bare "-w".
IPTABLES_LOCK_WAIT_SECONDS = 5


def get_wait_option(version: str) -> str:
    """Return the xtables lock option, empty when the version lacks it."""
    if version_compare(version, '1.6.0') >= 0:
        return f'-w {IPTABLES_LOCK_WAIT_SECONDS}'
    if version_compare(version, '1.4.20') >= 0:
        return '-w'
    return ''


# iptables refuses a chain or target name of XT_EXTENSION_MAXNAMELEN
# characters or more (include/linux/netfilter/x_tables.h, checked in
# xshared.c), so 28 characters is the longest name that loads.  fwbuilder
# only rejects names longer than 30 and lets two unloadable lengths pass.
MAX_CHAIN_NAME_LENGTH = 28


def check_chain_name(compiler, chain: str, already_reported: set[str]) -> None:
    """Report chain names iptables would refuse, once per name."""
    if len(chain) <= MAX_CHAIN_NAME_LENGTH or chain in already_reported:
        return
    already_reported.add(chain)
    compiler.error(
        f'Chain name "{chain}" is longer than {MAX_CHAIN_NAME_LENGTH} '
        'characters, iptables refuses to create it. Shorten the name of the '
        'rule set or branch it is generated from.',
    )


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
