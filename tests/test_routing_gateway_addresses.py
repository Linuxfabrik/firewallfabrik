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

"""How many next hops an object used as a routing gateway offers.

``ip route add ... via`` takes one next hop, so an object carrying more
than one address cannot name it.  A MAC address is not a next hop, though:
an interface of a host with "MAC address matching" turned on carries an IP
*and* a MAC, and counting whatever answers ``get_address()`` made such a
gateway look ambiguous and cost the route.  The C++ counts IPv4 children
and nothing else (fwbuilder libfwbuilder/src/fwbuilder/RuleElement.cpp,
RuleElementRGtw::checkSingleIPAdress).
"""

from firewallfabrik.core.objects import Host, Interface, IPv4, IPv6, PhysAddress
from firewallfabrik.platforms.linux._routing_compiler import _count_addresses


def _ipv4(address='192.0.2.1'):
    obj = IPv4()
    obj.name = 'gw'
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


def _ipv6(address='2001:db8::1'):
    obj = IPv6()
    obj.name = 'gw6'
    obj.inet_addr_mask = {'address': address, 'netmask': '128'}
    return obj


def _mac(address='00:11:22:33:44:55'):
    obj = PhysAddress()
    obj.name = 'mac'
    obj.inet_addr_mask = {'address': address, 'netmask': ''}
    return obj


def _interface(addresses):
    iface = Interface()
    iface.name = 'eth0'
    iface.addresses = list(addresses)
    return iface


def test_a_single_address_is_one_next_hop():
    assert _count_addresses(_ipv4()) == 1
    assert _count_addresses(_ipv6()) == 1


def test_a_mac_address_is_no_next_hop():
    assert _count_addresses(_mac()) == 0


def test_an_interface_with_an_address_and_a_mac_offers_one():
    """The shape a host with "MAC address matching" turned on expands to."""
    assert _count_addresses(_interface([_ipv4(), _mac()])) == 1


def test_an_interface_with_two_addresses_offers_two():
    assert _count_addresses(_interface([_ipv4(), _ipv4('192.0.2.2')])) == 2


def test_a_host_counts_across_its_interfaces():
    host = Host()
    host.name = 'gw-host'
    host.interfaces = [_interface([_ipv4(), _mac()])]
    assert _count_addresses(host) == 1


def test_the_routing_debug_flag_reaches_the_routing_compiler():
    """--xr is the routing counterpart of --xp and --xn.

    Both siblings are handed to their compilers by the drivers; this one
    was set on the driver and read by nobody, so the flag did nothing on
    either platform although the developer guide describes it as working.
    """
    import inspect

    from firewallfabrik.platforms.iptables import _compiler_driver as ipt
    from firewallfabrik.platforms.nftables import _compiler_driver as nft

    for module in (ipt, nft):
        source = inspect.getsource(module)
        assert 'routing_compiler.debug_rule = self.debug_rule_routing' in source
