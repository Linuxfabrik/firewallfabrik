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

"""CombinedAddress: pairs an IP address with an optional MAC address.

Used by the iptables compiler for rules that match both MAC and IP.
"""

from __future__ import annotations

import dataclasses
import uuid

from firewallfabrik.core.objects import (
    Address,
    Host,
    PhysAddress,
)


def host_matches_by_mac(host: Host | None) -> bool:
    """Return whether the host's addresses are matched together with its MAC.

    The "MAC address matching" checkbox of the host dialog.  fwbuilder
    reads it in ``Compiler::_expand_interface``
    (libfwbuilder/fwcompiler/Compiler.cpp) and leaves the physAddress out
    of the expansion when it is off.  :meth:`Host.matches_by_mac` knows
    where the value is kept.
    """
    if host is None:
        return False
    return host.matches_by_mac()


@dataclasses.dataclass
class CombinedAddress:
    """An IP address optionally paired with a MAC address.

    This is a lightweight in-memory object (not persisted) used during
    compilation when a rule needs to match both MAC and IP addresses.
    It wraps an Address model object and an optional PhysAddress.
    """

    address: Address
    phys_address: PhysAddress | None = None

    @property
    def id(self) -> uuid.UUID:
        return self.address.id

    @property
    def name(self) -> str:
        return self.address.name

    @property
    def type(self) -> str:
        return self.address.type

    def get_address(self) -> str:
        return self.address.get_address()

    def get_netmask(self) -> str:
        return self.address.get_netmask()

    def is_v4(self) -> bool:
        return self.address.is_v4()

    def is_v6(self) -> bool:
        return self.address.is_v6()

    def has_phys_address(self) -> bool:
        return self.phys_address is not None

    def get_phys_address(self) -> str:
        if self.phys_address and self.phys_address.get_address():
            return self.phys_address.get_address()
        return ''

    def drop_phys_address(self) -> None:
        """Keep the IP half and forget the MAC.

        What ``combinedAddress::setPhysAddress("")`` does in fwbuilder's
        ``NATCompiler_ipt::verifyRuleWithMAC``: a chain that cannot match a
        MAC can still match the address the object also carries.
        """
        self.phys_address = None

    def is_address_any(self) -> bool:
        """Return whether nothing but the MAC is left to match on."""
        return not (self.address.get_address() or '')
