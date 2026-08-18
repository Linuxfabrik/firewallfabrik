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

"""What a NAT rule does with an interface that has no address.

An unnumbered interface and a bridge port carry no IP address, so neither
can be matched as one.  `NATCompiler_ipt::specialCaseWithUnnumberedInterface`
(NATCompiler_ipt.cpp:970) takes such an object out of the element the rule
translates on - the original source for Masquerade and SNAT, the original
destination for DNAT - and keeps the rule as long as anything else is
left, which is what naming several objects means.

Neither NAT pipeline runs the `CheckForUnnumbered` that makes this
unreachable in the policy pipelines, so this is a live processor: the
iptables pipeline has had it since the port, the nftables one had nothing.
There the print rule reports an addressless object and leaves out the
*whole* rule, so a rule translating "this network and that bridge port"
translated the network on iptables and nothing at all on nftables.
"""

import uuid

import pytest

from firewallfabrik.compiler.processors._generic import (
    NATSpecialCaseWithUnnumberedInterface,
)
from firewallfabrik.core.objects import Interface, NATRuleType, Network


def _interface(name, **data) -> Interface:
    made = Interface(id=uuid.uuid4(), name=name)
    made.data = data
    return made


def _network(name) -> Network:
    return Network(id=uuid.uuid4(), name=name)


class _Rule:
    type = 'NATRule'

    def __init__(self, rule_type, **slots) -> None:
        self.nat_rule_type = rule_type
        self.osrc = slots.get('osrc', [])
        self.odst = slots.get('odst', [])


class _Feeder:
    def __init__(self, rule) -> None:
        self._rule = rule

    def get_next_rule(self):
        rule, self._rule = self._rule, None
        return rule


def _run(rule):
    proc = NATSpecialCaseWithUnnumberedInterface()
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    return list(proc.tmp_queue)


NET = _network('office net')
UNNUMBERED = _interface('eth9', unnum=True)


@pytest.mark.parametrize('rule_type', [NATRuleType.SNAT, NATRuleType.Masq])
def test_a_translating_rule_keeps_what_is_left_of_its_source(rule_type):
    rule = _Rule(rule_type, osrc=[NET, UNNUMBERED])

    assert _run(rule) == [rule]
    assert rule.osrc == [NET]


def test_a_dnat_rule_is_asked_about_its_destination():
    rule = _Rule(NATRuleType.DNAT, odst=[NET, UNNUMBERED])

    assert _run(rule) == [rule]
    assert rule.odst == [NET]


def test_a_rule_that_names_nothing_else_is_left_out():
    """An emptied element reads as "any", which would translate everything."""
    rule = _Rule(NATRuleType.SNAT, osrc=[UNNUMBERED])

    assert _run(rule) == []


def test_a_rule_whose_source_was_any_to_begin_with_stays():
    rule = _Rule(NATRuleType.SNAT, osrc=[])

    assert _run(rule) == [rule]


def test_a_bridge_port_goes_the_same_way():
    """It carries no address either, and nftables cannot match it at all."""
    bridge = _interface('br0')
    bridge.options = {'type': 'bridge'}
    port = _interface('eth4')
    port.options = {'type': 'ethernet'}
    port.parent_interface = bridge
    rule = _Rule(NATRuleType.SNAT, osrc=[NET, port])

    assert _run(rule) == [rule]
    assert rule.osrc == [NET]


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_both_nat_pipelines_run_it(platform):
    import ast
    import inspect

    module = __import__(
        f'firewallfabrik.platforms.{platform}._nat_compiler', fromlist=['x']
    )
    compiler_class = getattr(
        module, 'NATCompiler_ipt' if platform == 'iptables' else 'NATCompiler_nft'
    )
    source = inspect.getsource(compiler_class.compile)
    wired = [
        call.args[0].func.id
        for call in ast.walk(ast.parse(source.lstrip()))
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == 'add'
        and call.args
        and isinstance(call.args[0], ast.Call)
        and isinstance(call.args[0].func, ast.Name)
    ]

    assert NATSpecialCaseWithUnnumberedInterface.__name__ in wired
