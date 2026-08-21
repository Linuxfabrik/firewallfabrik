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

"""Whether a routing rule names a gateway the firewall can reach.

``ip route add ... via <gw>`` needs the next hop on a network the box is
attached to, and ``dev`` says which of its interfaces that is.  The kernel
answers anything else with "Error: Nexthop has invalid gateway" and
installs nothing, so without these two checks the mistake shows up as one
line of stderr in the middle of the activation and the route is simply not
there.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Firewall, Interface, IPv4, IPv6, Network
from firewallfabrik.platforms.linux._routing_compiler import (
    GatewayOnRoutingInterface,
    ReachableGateway,
)


class _Compiler:
    def __init__(self, fw):
        self.fw = fw
        self.errors = []

    def error(self, rule, msg):
        self.errors.append(msg)

    def warning(self, rule, msg):
        pass


class _Source:
    def __init__(self, rules):
        self._rules = list(rules)

    def get_next_rule(self):
        return self._rules.pop(0) if self._rules else None


def _address(cls, address, netmask):
    obj = cls()
    obj.id = uuid.uuid4()
    obj.name = f'addr-{address}'
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


def _interface(name, addresses):
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = name
    iface.addresses = list(addresses)
    iface.data = {}
    return iface


def _firewall(interfaces):
    fw = Firewall()
    fw.id = uuid.uuid4()
    fw.name = 'fw'
    fw.interfaces = list(interfaces)
    return fw


def _rule(rgtw, ritf=None):
    return CompRule(
        id=uuid.uuid4(),
        type='RoutingRule',
        position=0,
        label='0 (main)',
        comment='',
        options={},
        negations={},
        rdst=[],
        rgtw=[rgtw],
        ritf=[ritf] if ritf is not None else [],
    )


def _run(processor, fw, rules):
    compiler = _Compiler(fw)
    processor.compiler = compiler
    processor.prev_processor = _Source(rules)
    out = []
    while True:
        rule = processor.get_next_rule()
        if rule is None:
            break
        out.append(rule)
    return compiler, out


@pytest.fixture
def fw():
    return _firewall(
        [
            _interface('eth0', [_address(IPv4, '192.0.2.11', '255.255.255.0')]),
            _interface('eth1', [_address(IPv4, '198.51.100.11', '255.255.255.0')]),
            _interface('eth2', [_address(IPv6, '2001:db8::11', '64')]),
        ]
    )


def test_a_gateway_on_a_local_network_is_kept(fw):
    gw = _address(IPv4, '192.0.2.1', '255.255.255.255')
    _compiler, out = _run(ReachableGateway(), fw, [_rule(gw)])

    assert len(out) == 1


def test_a_gateway_on_no_local_network_is_reported(fw):
    gw = _address(IPv4, '203.0.113.1', '255.255.255.255')
    compiler, out = _run(ReachableGateway(), fw, [_rule(gw)])

    assert out == []
    assert len(compiler.errors) == 1
    assert 'none of the local networks' in compiler.errors[0]


def test_an_ipv6_gateway_is_checked_against_ipv6_addresses(fw):
    """The C++ walks IPv4 children only, which fails every IPv6 route."""
    gw = _address(IPv6, '2001:db8::1', '128')
    _compiler, out = _run(ReachableGateway(), fw, [_rule(gw)])

    assert len(out) == 1


def test_a_network_is_no_single_next_hop(fw):
    """Only an object that *is* one address can be checked this way."""
    net = _address(Network, '203.0.113.0', '255.255.255.0')
    _compiler, out = _run(ReachableGateway(), fw, [_rule(net)])

    assert len(out) == 1


def test_the_gateway_has_to_be_on_the_interface_the_rule_names(fw):
    gw = _address(IPv4, '192.0.2.1', '255.255.255.255')
    rule = _rule(gw, ritf=fw.interfaces[1])
    compiler, out = _run(GatewayOnRoutingInterface(), fw, [rule])

    assert out == []
    assert len(compiler.errors) == 1
    assert 'eth1' in compiler.errors[0]


def test_the_matching_interface_passes(fw):
    gw = _address(IPv4, '192.0.2.1', '255.255.255.255')
    rule = _rule(gw, ritf=fw.interfaces[0])
    _compiler, out = _run(GatewayOnRoutingInterface(), fw, [rule])

    assert len(out) == 1


def test_a_rule_without_an_interface_is_left_alone(fw):
    gw = _address(IPv4, '192.0.2.1', '255.255.255.255')
    _compiler, out = _run(GatewayOnRoutingInterface(), fw, [_rule(gw)])

    assert len(out) == 1


def test_an_interface_with_no_address_of_that_family_is_left_alone(fw):
    """It gets its address while the firewall runs; nothing can be said here."""
    gw = _address(IPv4, '192.0.2.1', '255.255.255.255')
    rule = _rule(gw, ritf=fw.interfaces[2])
    _compiler, out = _run(GatewayOnRoutingInterface(), fw, [rule])

    assert len(out) == 1
