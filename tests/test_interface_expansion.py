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

"""An interface named in a rule stands for every address it carries.

`Compiler::_expand_addr_recursive` hands every Interface it finds in a
rule element to `_expand_interface`, which walks the interface's address
children and recurses into its sub-interfaces.  The port left the object
in the element, and the print rules then wrote the *first* address alone:
a rule "permit SSH to eth0" covered one of the two addresses eth0 carries
and none of the VLAN below it.  Firewall Builder's own reference output
shows both (`firewall2-1.fw.orig` rule 21 names 192.168.2.1 and
192.168.2.40).

Three kinds of interface stay in the element as objects, because they
carry no address the compiler could write down: a dynamic one, whose
address the generated script looks up while it runs, an unnumbered one
and a bridge port.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import (
    Direction,
    Firewall,
    Interface,
    IPv4,
    IPv6,
    PhysAddress,
    PolicyAction,
)


def _address(name, address, netmask='255.255.255.0'):
    addr = IPv4(id=uuid.uuid4(), name=name)
    addr.data = {}
    addr.inet_addr_mask = {'address': address, 'netmask': netmask}
    return addr


def _interface(device, name, addresses=(), parent=None, **data):
    iface = Interface(id=uuid.uuid4(), name=name)
    iface.data = dict(data)
    iface.options = {}
    iface.device = device
    if parent is not None:
        iface.parent_interface = parent
    for addr in addresses:
        addr.interface = iface
    return iface


class _Compiler(Compiler):
    """The expansion and nothing else; it reads `fw` and `ipv6_policy`."""

    def __init__(self, fw):
        self.fw = fw
        self.ipv6_policy = False


@pytest.fixture
def firewall():
    fw = Firewall(id=uuid.uuid4(), name='fw-test')
    fw.data = {}
    fw.options = {}
    return fw


def _expand(fw, obj):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='',
        comment='',
        options={},
        negations={},
        dst=[obj],
        action=PolicyAction.Accept,
        direction=Direction.Both,
    )
    _Compiler(fw).expand_addr(rule, 'dst')
    return rule


def test_every_address_of_the_interface_is_named(firewall):
    eth0 = _interface(
        firewall,
        'eth0',
        [_address('eth0:ip', '192.168.2.1'), _address('eth0:ip1', '192.168.2.40')],
    )

    rule = _expand(firewall, eth0)

    assert sorted(a.get_address() for a in rule.dst) == [
        '192.168.2.1',
        '192.168.2.40',
    ]


def test_a_sub_interface_contributes_its_address_too(firewall):
    eth0 = _interface(firewall, 'eth0', [_address('eth0:ip', '172.24.0.2')])
    _interface(
        firewall, 'eth0.100', [_address('vlan:ip', '192.168.100.1')], parent=eth0
    )

    rule = _expand(firewall, eth0)

    assert sorted(a.get_address() for a in rule.dst) == [
        '172.24.0.2',
        '192.168.100.1',
    ]


def test_an_address_of_the_other_family_is_left_out(firewall):
    eth0 = _interface(firewall, 'eth0', [_address('eth0:ip', '172.24.0.2')])
    v6 = IPv6(id=uuid.uuid4(), name='eth0:ip6')
    v6.data = {}
    v6.inet_addr_mask = {'address': 'fe80::1', 'netmask': '64'}
    v6.interface = eth0

    rule = _expand(firewall, eth0)

    assert [a.get_address() for a in rule.dst] == ['172.24.0.2']


@pytest.mark.parametrize('flag', ['dyn', 'unnum'])
def test_an_interface_with_no_compile_time_address_stays_an_object(firewall, flag):
    """The dynamic one becomes the run-time loop; both are reported as such."""
    eth0 = _interface(firewall, 'eth0', **{flag: True})

    rule = _expand(firewall, eth0)

    assert rule.dst == [eth0]


def test_a_bridge_port_stays_an_object(firewall):
    bridge = _interface(firewall, 'br0')
    bridge.options = {'type': 'bridge'}
    port = _interface(firewall, 'eth0', parent=bridge)

    rule = _expand(firewall, port)

    assert rule.dst == [port]


def test_the_mac_comes_with_the_address_when_the_host_says_so(firewall):
    """`use_mac_addr_filter` decides, as it does when a Host is expanded."""
    firewall.options = {'use_mac_addr_filter': True}
    eth0 = _interface(firewall, 'eth0', [_address('eth0:ip', '192.168.1.10')])
    mac = PhysAddress(id=uuid.uuid4(), name='eth0:mac')
    mac.data = {}
    mac.inet_addr_mask = {'address': '00:10:4b:de:e9:6f', 'netmask': ''}
    mac.interface = eth0

    rule = _expand(firewall, eth0)

    (combined,) = rule.dst
    assert combined.get_address() == '192.168.1.10'
    assert combined.get_phys_address() == '00:10:4b:de:e9:6f'
