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

"""What a dynamic interface contributes when a host is expanded.

Firewall Builder stores a placeholder address of 0.0.0.0 under an
interface whose address is only known on the firewall.  Taking that
placeholder into the rule writes ``-s 0.0.0.0``, which iptables reads as
``0.0.0.0/32`` and no packet carries - so an anti-spoofing rule written
about the firewall's own dynamic address never matched it.  The C++
returns the interface itself before it looks at any child
(``Compiler::_expand_interface``); the print rules then turn it into the
run-time loop over ``$i_<interface>_list`` on iptables and into a named
set on nftables.
"""

import uuid

import pytest

from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import Interface, IPv4, IPv6, PhysAddress

# The placeholder Firewall Builder writes under a dynamic interface.
UNKNOWN_ADDRESS = '0.0.0.0'  # nosec B104


def _address(cls, address, netmask):
    obj = cls()
    obj.id = uuid.uuid4()
    obj.name = 'address'
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


def _interface(name, addresses, *, dynamic=False):
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = name
    iface.addresses = list(addresses)
    iface.data = {'dyn': dynamic}
    return iface


class _Compiler(Compiler):
    """Only the address-family flag matters for the method under test."""

    def __init__(self, ipv6=False):
        self.ipv6_policy = ipv6


@pytest.fixture
def compiler():
    return _Compiler()


def test_a_dynamic_interface_contributes_itself(compiler):
    """Not the 0.0.0.0 placeholder Firewall Builder stores under it."""
    placeholder = _address(IPv4, UNKNOWN_ADDRESS, UNKNOWN_ADDRESS)
    iface = _interface('ppp0', [placeholder], dynamic=True)

    assert compiler._expand_interface(iface, use_mac=False) == [iface]


def test_a_dynamic_interface_survives_the_ipv6_pass_too():
    """Its address is unknown, so no family can rule it out."""
    iface = _interface(
        'ppp0', [_address(IPv4, UNKNOWN_ADDRESS, UNKNOWN_ADDRESS)], dynamic=True
    )

    assert _Compiler(ipv6=True)._expand_interface(iface, use_mac=False) == [iface]


def test_a_dynamic_interface_is_taken_over_its_mac(compiler):
    """The C++ returns before it reaches the physAddress child."""
    mac = PhysAddress()
    mac.id = uuid.uuid4()
    mac.name = 'mac'
    mac.inet_addr_mask = {'address': '00:11:22:33:44:55', 'netmask': ''}
    iface = _interface('ppp0', [mac], dynamic=True)

    assert compiler._expand_interface(iface, use_mac=True) == [iface]


def test_a_regular_interface_still_contributes_its_addresses(compiler):
    address = _address(IPv4, '192.0.2.1', '255.255.255.0')
    iface = _interface('eth0', [address, _address(IPv6, '2001:db8::1', '64')])

    assert compiler._expand_interface(iface, use_mac=False) == [address]
