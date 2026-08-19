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

"""Which interfaces a source translation names when its address has none.

`NATCompiler_ipt::AssignInterface` walks fwbuilder's `regular_interfaces`
map, which groups the firewall's interfaces by name pattern: eth0..eth3
are one group called `eth+`, so the rule is written once.  The map leaves
out the loopback, an unnumbered interface, a bridge port and an interface
that carries no address of the family being compiled - a rule about
"the firewall's interfaces" can mean none of those.
"""

import uuid

import pytest

from firewallfabrik.platforms.linux._netfilter import (
    build_interface_groups,
    interface_group_name,
    interface_group_object,
)


def _IPv4():
    from firewallfabrik.core.objects import IPv4

    return IPv4(id=uuid.uuid4(), name='addr4')


def _IPv6():
    from firewallfabrik.core.objects import IPv6

    return IPv6(id=uuid.uuid4(), name='addr6')


class _Interface:
    def __init__(self, name, addresses=(), unnumbered=False, bridge_port=False):
        self.name = name
        self.addresses = list(addresses)
        self._unnumbered = unnumbered
        self._bridge_port = bridge_port

    def is_loopback(self):
        return self.name == 'lo'

    def is_unnumbered(self):
        return self._unnumbered

    def is_bridge_port(self):
        return self._bridge_port


class _Firewall:
    id = uuid.uuid4()

    def __init__(self, interfaces):
        self.interfaces = interfaces


@pytest.mark.parametrize(
    ('name', 'group'),
    [
        ('eth0', 'eth*'),
        ('eth10', 'eth*'),
        ('ppp*', 'ppp*'),
        ('bond0', 'bond*'),
        ('eth0.100', 'eth0.*'),
    ],
)
def test_the_group_name_is_the_pattern_that_matches_the_siblings(name, group):
    assert interface_group_name(name) == group


def test_interfaces_of_one_family_are_one_group():
    fw = _Firewall(
        [
            _Interface('eth0', [_IPv4()]),
            _Interface('eth1', [_IPv4()]),
            _Interface('eth2', [_IPv4()]),
        ]
    )
    groups = build_interface_groups(fw, ipv6=False)
    assert sorted(groups) == ['*', 'eth*']
    assert len(groups['eth*']) == 3


def test_what_the_map_leaves_out():
    fw = _Firewall(
        [
            _Interface('lo', [_IPv4()]),
            _Interface('eth0', [_IPv4()]),
            _Interface('eth1', unnumbered=True),
            _Interface('eth2', [_IPv4()], bridge_port=True),
        ]
    )
    groups = build_interface_groups(fw, ipv6=False)
    assert [iface.name for iface in groups['*']] == ['eth0']


def test_an_interface_of_the_other_family_only_is_left_out():
    fw = _Firewall(
        [
            _Interface('eth0', [_IPv4()]),
            _Interface('eth1', [_IPv6()]),
            _Interface('eth2'),
        ]
    )
    v4 = [iface.name for iface in build_interface_groups(fw, ipv6=False)['*']]
    v6 = [iface.name for iface in build_interface_groups(fw, ipv6=True)['*']]
    assert v4 == ['eth0', 'eth2']
    assert v6 == ['eth1', 'eth2']


def test_the_stand_in_object_carries_the_pattern_as_its_name():
    fw = _Firewall([])
    obj = interface_group_object(fw, 'eth*')
    assert obj.name == 'eth*'
    assert not obj.is_loopback()
    assert not obj.is_bridge_port()
    assert obj.device_id == fw.id
