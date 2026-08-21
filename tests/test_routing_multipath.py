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

"""What happens when two routing rules aim at the same destination.

``ip route add`` answers "RTNETLINK answers: File exists" for a
destination that is already routed, so two rules that agree on the
destination and the metric cannot both be installed.  What the
administrator asked for there is one route with several next hops, which
is what ``nexthop ... nexthop ...`` gives.  Two rules that also agree on
the next hop are simply the same rule twice, and two that differ only in
the metric name no answer at all.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Interface, IPv4, Network, RoutingRuleType
from firewallfabrik.platforms.linux._routing_compiler import (
    ClassifyRoutingRules,
    CompetingRoutingRules,
    EliminateDuplicateRoutingRules,
)


class _Compiler:
    """The two message sinks the processors under test reach for."""

    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, rule, msg):
        self.errors.append(msg)

    def warning(self, rule, msg):
        self.warnings.append(msg)


def _network(name, address, netmask='255.255.255.0'):
    obj = Network()
    obj.id = uuid.uuid4()
    obj.name = name
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


def _gateway(name='gw', address='192.0.2.1'):
    obj = IPv4()
    obj.id = uuid.uuid4()
    obj.name = name
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


def _interface(name='eth0'):
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = name
    return iface


def _rule(position, rdst, rgtw=None, ritf=None, metric=0):
    return CompRule(
        id=uuid.uuid4(),
        type='RoutingRule',
        position=position,
        label=f'{position} (main)',
        comment='',
        options={'metric': str(metric)},
        negations={},
        rdst=list(rdst),
        rgtw=[rgtw] if rgtw is not None else [],
        ritf=[ritf] if ritf is not None else [],
    )


def _run(processor, rules):
    """Feed *rules* through *processor* and return what comes out.

    Drains the processor the way the engine does, so a slurping processor
    terminates as well.
    """
    compiler = _Compiler()
    processor.compiler = compiler
    processor.prev_processor = _Source(rules)
    out = []
    while True:
        rule = processor.get_next_rule()
        if rule is None:
            break
        out.append(rule)
    return compiler, out


class _Source:
    """Stands in for the previous processor in the chain."""

    def __init__(self, rules):
        self._rules = list(rules)

    def get_next_rule(self):
        return self._rules.pop(0) if self._rules else None


def test_two_paths_to_one_destination_become_one_multipath_route():
    dst = _network('net', '10.1.0.0')
    gw = _gateway()
    rules = [
        _rule(0, [dst], gw, _interface('eth0')),
        _rule(1, [dst], gw, _interface('eth1')),
    ]
    processor = ClassifyRoutingRules()
    _compiler, out = _run(processor, rules)

    assert len(out) == 2
    assert all(r.routing_rule_type == RoutingRuleType.MultiPath for r in out)


def test_different_metrics_stay_single_path():
    """Two metrics are two routes the kernel keeps side by side."""
    dst = _network('net', '10.1.0.0')
    gw = _gateway()
    rules = [
        _rule(0, [dst], gw, _interface('eth0'), metric=0),
        _rule(1, [dst], gw, _interface('eth1'), metric=100),
    ]
    processor = ClassifyRoutingRules()
    _compiler, out = _run(processor, rules)

    assert all(r.routing_rule_type == RoutingRuleType.SinglePath for r in out)


def test_different_destinations_stay_single_path():
    gw = _gateway()
    rules = [
        _rule(0, [_network('a', '10.1.0.0')], gw, _interface('eth0')),
        _rule(1, [_network('b', '10.2.0.0')], gw, _interface('eth1')),
    ]
    processor = ClassifyRoutingRules()
    _compiler, out = _run(processor, rules)

    assert all(r.routing_rule_type == RoutingRuleType.SinglePath for r in out)


def test_the_same_rule_twice_is_installed_once():
    dst = _network('net', '10.1.0.0')
    gw = _gateway()
    itf = _interface('eth0')
    rules = [_rule(0, [dst], gw, itf), _rule(1, [dst], gw, itf)]
    compiler, out = _run(CompetingRoutingRules(), rules)

    assert len(out) == 1
    assert len(compiler.warnings) == 1
    assert 'identical' in compiler.warnings[0]


def test_the_same_rule_with_two_metrics_is_refused():
    dst = _network('net', '10.1.0.0')
    gw = _gateway()
    itf = _interface('eth0')
    rules = [
        _rule(0, [dst], gw, itf, metric=0),
        _rule(1, [dst], gw, itf, metric=100),
    ]
    compiler, out = _run(CompetingRoutingRules(), rules)

    assert len(out) == 1
    assert len(compiler.errors) == 1
    assert 'metric' in compiler.errors[0]


def test_a_destination_named_by_two_rules_is_routed_once():
    """What ``CompetingRoutingRules`` cannot see before the atomic split."""
    shared = _network('shared', '10.2.0.0')
    gw = _gateway()
    itf = _interface('eth0')
    rules = [_rule(0, [shared], gw, itf), _rule(1, [shared], gw, itf)]
    compiler, out = _run(EliminateDuplicateRoutingRules(), rules)

    assert len(out) == 1
    assert len(compiler.warnings) == 1


def test_two_copies_of_one_rule_are_dropped_without_a_word():
    """The atomic split can produce them; nobody can act on the message."""
    shared = _network('shared', '10.2.0.0')
    gw = _gateway()
    itf = _interface('eth0')
    rules = [_rule(0, [shared], gw, itf), _rule(0, [shared], gw, itf)]
    compiler, out = _run(EliminateDuplicateRoutingRules(), rules)

    assert len(out) == 1
    assert compiler.warnings == []
