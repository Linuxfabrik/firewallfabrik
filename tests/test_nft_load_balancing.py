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


"""Backends of a load balancing NAT rule that are Host objects.

`get_address` is defined on Address alone, so a Host in the translated
destination answers nothing.  Reading the backends off the rule element
before the pipeline has expanded the hosts therefore collected nothing,
the rule kept its several destinations, and `ConvertToAtomicForAddresses`
gave each one a rule of its own.  DNAT terminates, so the first rule took
every connection and the other backends got none.

`NATCompiler_ipt.ConvertLoadBalancingRules` expands the element itself
for the same reason; this is the nftables half of it.
"""

import uuid

from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.core.objects import IPv4, NATRuleType
from firewallfabrik.platforms.nftables._nat_compiler import ConvertLoadBalancingRules


def _addr(name: str, address: str) -> IPv4:
    obj = IPv4(id=uuid.uuid4(), name=name)
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


class _Host:
    """A host object, which carries its addresses on its interfaces."""

    def __init__(self, name: str, addresses) -> None:
        self.id = uuid.uuid4()
        self.name = name
        self.addresses = addresses


class _Compiler:
    """A compiler whose `expand_addr` does what the real one does to a Host."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.expanded: list[str] = []

    def expand_addr(self, rule, slot: str) -> None:
        self.expanded.append(slot)
        expanded = []
        for obj in getattr(rule, slot):
            expanded.extend(getattr(obj, 'addresses', None) or [obj])
        setattr(rule, slot, expanded)

    def error(self, _rule, msg: str = '') -> None:
        self.errors.append(msg)


class _Rule:
    type = 'NATRule'

    def __init__(self, tdst) -> None:
        self.nat_rule_type = NATRuleType.DNAT
        self.tdst = tdst
        self.options: dict = {}

    def set_option(self, key: str, value) -> None:
        self.options[key] = value

    def get_option(self, key: str, default=None):
        return self.options.get(key, default)


class _Feeder(NATRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _convert(rule):
    proc = ConvertLoadBalancingRules('convert load balancing rules')
    proc.compiler = _Compiler()
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    return proc


def test_host_backends_become_one_numgen_map():
    hosts = [
        _Host('backend-a', [_addr('a', '192.168.1.10')]),
        _Host('backend-b', [_addr('b', '192.168.1.11')]),
    ]
    proc = _convert(_Rule(hosts))
    rule = proc.tmp_queue[0]

    assert 'tdst' in proc.compiler.expanded
    assert rule.get_option('nft_load_balance') is True
    assert rule.get_option('nft_lb_backends') == ['192.168.1.10', '192.168.1.11']
    assert len(rule.tdst) == 1


def test_address_backends_still_become_one_numgen_map():
    """The case the corpus already covered must not change."""
    rule = _Rule([_addr('a', '192.168.1.10'), _addr('b', '192.168.1.11')])
    proc = _convert(rule)

    assert proc.tmp_queue[0].get_option('nft_lb_backends') == [
        '192.168.1.10',
        '192.168.1.11',
    ]


def test_a_backend_without_an_address_is_reported_and_the_rule_left_out():
    """Dropping it in silence would send its share of the traffic nowhere."""
    rule = _Rule([_addr('a', '192.168.1.10'), _Host('backend-b', [])])
    proc = _convert(rule)

    assert len(proc.tmp_queue) == 0
    assert any('backend-b' in msg for msg in proc.compiler.errors)


def test_a_single_destination_is_not_a_load_balancing_rule():
    rule = _Rule([_addr('a', '192.168.1.10')])
    proc = _convert(rule)

    assert proc.compiler.expanded == []
    assert proc.tmp_queue[0].get_option('nft_load_balance') is None
