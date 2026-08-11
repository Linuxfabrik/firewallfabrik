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


"""Grouping the destinations of an SNAT rule by the interface behind them.

`ReplaceFirewallObjectsTSrc` resolves a firewall object in the translated
source from the first original destination and applies the answer to the
whole rule, and `AssignInterface` takes the outgoing interface from the
same place.  Destinations reached through different interfaces therefore
have to be in rules of their own, or all but the first get an interface
they can never match on and their traffic leaves the firewall
untranslated.

A negated destination stays whole: "none of these" is one condition, and
one rule per destination asks "not this one" in each, which together let
nearly everything through.
"""

import ipaddress
import uuid

from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.core.objects import IPv4, NATRuleType
from firewallfabrik.platforms.nftables._nat_compiler import SplitODstForSNAT


def _addr(name: str, address: str) -> IPv4:
    obj = IPv4(id=uuid.uuid4(), name=name)
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


class _Interface:
    """A firewall interface with one address on a /24."""

    def __init__(self, name: str, address: str) -> None:
        self.id = uuid.uuid4()
        self.name = name
        self.addresses = [_addr(f'{name}:0', address)]
        self.addresses[0].inet_addr_mask['netmask'] = '255.255.255.0'

    def is_regular(self) -> bool:
        return True


class _Firewall:
    def __init__(self, interfaces) -> None:
        self.interfaces = interfaces


class _Compiler:
    def __init__(self, fw) -> None:
        self.fw = fw


class _Rule:
    type = 'NATRule'

    def __init__(self, odst, negated=False) -> None:
        self.nat_rule_type = NATRuleType.SNAT
        self.odst = odst
        self.odst_single_object_negation = negated
        self._neg = {'odst': negated}

    def get_neg(self, slot: str) -> bool:
        return self._neg.get(slot, False)

    def clone(self):
        other = _Rule(list(self.odst), self.odst_single_object_negation)
        return other


class _Feeder(NATRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


ETH0 = _Interface('eth0', '198.51.100.1')
ETH1 = _Interface('eth1', '203.0.113.1')
FW = _Firewall([ETH0, ETH1])

BEHIND_ETH0 = _addr('server-a', '198.51.100.5')
ALSO_ETH0 = _addr('server-b', '198.51.100.6')
BEHIND_ETH1 = _addr('server-c', '203.0.113.5')


def _split(rule):
    proc = SplitODstForSNAT('split ODst')
    proc.compiler = _Compiler(FW)
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    return [r.odst for r in proc.tmp_queue]


def test_destinations_behind_two_interfaces_get_a_rule_each():
    groups = _split(_Rule([BEHIND_ETH0, BEHIND_ETH1]))
    assert sorted(len(g) for g in groups) == [1, 1]
    assert {obj.name for group in groups for obj in group} == {
        'server-a',
        'server-c',
    }


def test_destinations_behind_one_interface_stay_together():
    groups = _split(_Rule([BEHIND_ETH0, ALSO_ETH0]))
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_a_negated_destination_is_never_split():
    """Splitting it would turn "none of these" into "not this one, or not that one"."""
    groups = _split(_Rule([BEHIND_ETH0, BEHIND_ETH1], negated=True))
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_the_interface_lookup_is_the_one_the_rule_relies_on():
    """Guards the assumption the split rests on, not the split itself."""
    from firewallfabrik.platforms.nftables._nat_compiler import (
        ReplaceFirewallObjectsTSrc,
    )

    assert ReplaceFirewallObjectsTSrc._find_interface_for(BEHIND_ETH1, FW) is ETH1
    assert ipaddress.ip_address('203.0.113.5') in ipaddress.ip_network('203.0.113.0/24')
