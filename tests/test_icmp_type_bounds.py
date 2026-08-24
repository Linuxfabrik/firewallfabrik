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

"""An ICMP service naming a type or a code that does not fit in a byte.

The ICMP header has one byte for each, and both tools bound the value
there.  Verified against iptables 1.8.11 and nft 1.1.6:

    iptables -A INPUT -p icmp --icmp-type 300 -j DROP
    -> Unknown ICMP type `300'
    nft add rule ip t c icmp type 300 drop
    -> Error: Value 300 exceeds valid range 0-255

iptables reads the pair with ``xtables_strtoui(str, ..., 0, 255)``
(netfilter iptables extensions/libxt_icmp.h), so the activation script
stops there with the built-in policies already at DROP; nftables refuses
the whole ruleset, so the firewall never gets the new policy.

Both editors bound the field to -1..255, which is why neither compiler
asked - the same reasoning as for a port range that runs backwards.  A
data file written by an older release, another tool or by hand carries
whatever it carries.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._service import (
    VerifyIcmpTypes,
    icmp_type_problem,
)
from firewallfabrik.core.objects import (
    ICMP6Service,
    ICMPService,
    PolicyAction,
    TCPService,
)
from firewallfabrik.platforms.nftables._print_rule import other_protocols_for


def _srv(cls=ICMPService, **data):
    srv = cls(id=uuid.uuid4(), name='probe')
    srv.data = data
    return srv


@pytest.mark.parametrize(
    'data',
    [
        {'type': '256'},
        {'type': '300'},
        {'type': '8', 'code': '256'},
        {'type': 'echo-request'},
        {'type': '8', 'code': 'nonsense'},
    ],
)
def test_a_value_neither_tool_takes_is_reported(data):
    assert icmp_type_problem(_srv(**data))


@pytest.mark.parametrize(
    'data',
    [
        {},
        # -1 is the model's "any" and is what the print rules read the
        # absence of the attribute as.
        {'type': '-1'},
        {'type': '-1', 'code': '-1'},
        {'type': '8', 'code': '0'},
        {'type': '0'},
        {'type': 255, 'code': 255},
        {'type': '3', 'code': ''},
    ],
)
def test_a_value_both_tools_take(data):
    assert not icmp_type_problem(_srv(**data))


def test_icmpv6_is_asked_the_same_question():
    assert icmp_type_problem(_srv(ICMP6Service, type='999'))


def test_only_an_icmp_service_is_asked():
    assert not icmp_type_problem(_srv(TCPService, type='999'))


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(services, rule_type='PolicyRule', slot='srv'):
    rule = CompRule(
        id=uuid.uuid4(),
        type=rule_type,
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    setattr(rule, slot, services)
    return rule


def _run(rule):
    proc = VerifyIcmpTypes(name='VerifyIcmpTypes')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return proc


def test_the_rule_is_left_out_and_the_service_is_named():
    proc = _run(_rule([_srv(type='300')]))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages
    assert 'probe' in proc.compiler.messages[0]


def test_a_nat_rule_is_asked_about_its_original_service():
    proc = _run(_rule([_srv(type='300')], rule_type='NATRule', slot='osrv'))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages


def test_an_ordinary_icmp_rule_passes_through():
    proc = _run(_rule([_srv(type='8', code='0')]))
    assert len(proc.tmp_queue) == 1
    assert proc.compiler.messages == []


@pytest.mark.parametrize('value', ['abc', '', None, '-1'])
def test_the_negated_service_split_answers_before_the_check_runs(value):
    """``AddOtherProtocolsForNegatedService`` is far ahead of VerifyIcmpTypes.

    It sits at the front of the nftables policy chain, so a stored type
    that is not a number reached ``int()`` there and ended the compile
    with no script at all - ahead of the check that leaves the rule out
    and names the service.  "Cannot say what the element leaves out" is
    the right answer for a value nobody can read.
    """
    assert other_protocols_for([_srv(type=value)], ipv6=False) == []


def test_the_negated_service_split_still_names_a_real_type():
    assert other_protocols_for([_srv(type='8')], ipv6=False) == ['icmp']
