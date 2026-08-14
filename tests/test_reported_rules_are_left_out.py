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

"""A rule the compiler says it cannot express must not reach the script.

The C++ ``abort()`` throws (fwbuilder
libfwbuilder/src/fwcompiler/BaseCompiler.cpp), so nothing is emitted at
all.  fwf reports and carries on, to show the administrator every problem
in one run - which only works if the reported rule is left behind.  Four
processors recorded the message and then pushed the rule on regardless.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import CheckForTCPEstablished
from firewallfabrik.core.objects import PolicyAction, TCPService


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

    def my_platform_name(self) -> str:
        return 'iptables'

    def abort(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(services):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    rule.srv = services
    return rule


def _tcp(established: bool):
    srv = TCPService()
    srv.name = 'All TCP established' if established else 'http'
    srv.data = {'established': 'True'} if established else {}
    return srv


def _run(rule):
    proc = CheckForTCPEstablished(name='CheckForTCPEstablished')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return proc


def test_a_service_with_established_takes_its_rule_with_it():
    """Neither packet filter has that match, so nothing replaces it."""
    proc = _run(_rule([_tcp(established=True)]))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages


@pytest.mark.parametrize('services', [[], [_tcp(established=False)]])
def test_an_ordinary_rule_passes_through(services):
    proc = _run(_rule(services))
    assert len(proc.tmp_queue) == 1
    assert proc.compiler.messages == []


def test_a_nat_branch_rule_without_a_rule_set_is_left_out():
    """The C++ fallback behind its abort() is for test mode only.

    ``NATCompiler_ipt.cpp:1886`` sets the chain to PREROUTING and the target
    to "UNDEFINED" and says so in a comment - "in case we are in the test
    mode and abort() does not really abort.  Both the chain and the target
    are bogus".  In normal operation abort() throws, which is why the gold
    for firewall2-4 carries neither `-N UNDEFINED` nor the jump.  Copying
    the two lines put a jump into an empty chain of that name into the nat
    table: the rule translated nothing and the activation reported success.
    """
    from firewallfabrik.core.objects import NATRuleType
    from firewallfabrik.platforms.iptables._nat_compiler import SplitNATBranchRule

    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=7,
        label='7 (NAT)',
        comment='',
        options={'branch_name': ''},
        negations={},
        action=None,
    )
    rule.nat_rule_type = NATRuleType.NATBranch

    compiler = _Compiler()
    compiler.branch_ruleset_to_chain_mapping = None
    compiler.rule_set_chain = ''
    proc = SplitNATBranchRule(name='SplitNATBranchRule')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()

    assert list(proc.tmp_queue) == []
    assert compiler.messages
    assert rule.ipt_target != 'UNDEFINED'


def test_a_nat_rule_with_a_foreign_dynamic_interface_is_left_out():
    """The address it names cannot be resolved by the firewall running it.

    iptables wrote `-d $i_eth0`, a shell variable nothing assigns, so the
    command lost its argument and the activation stopped with every chain
    already at DROP.  nftables wrote `@i_eth0`, a set its loader fills from
    the *local* interface of that name, which translates for the wrong
    host - and its NAT pipeline had no such check at all.
    """
    from firewallfabrik.compiler.processors._generic import (
        NATCheckForDynamicInterfacesOfOtherObjects,
    )
    from firewallfabrik.core.objects import Interface

    other = Interface()
    other.name = 'eth0'
    other.data = {'dyn': True}
    other.id = uuid.uuid4()

    own = Interface()
    own.name = 'eth1'
    own.data = {'dyn': True}
    own.id = uuid.uuid4()

    class _FW:
        interfaces = [own]

    def _nat_rule(interface):
        rule = CompRule(
            id=uuid.uuid4(),
            type='NATRule',
            position=4,
            label='4 (NAT)',
            comment='',
            options={},
            negations={},
            action=None,
        )
        rule.odst = [interface]
        return rule

    compiler = _Compiler()
    compiler.fw = _FW()
    proc = NATCheckForDynamicInterfacesOfOtherObjects()
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([_nat_rule(other)]))
    proc.process_next()
    assert list(proc.tmp_queue) == []
    assert compiler.messages

    # The firewall's own dynamic interface is fine: the script asks the
    # host it runs on for that one.
    compiler = _Compiler()
    compiler.fw = _FW()
    proc = NATCheckForDynamicInterfacesOfOtherObjects()
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([_nat_rule(own)]))
    proc.process_next()
    assert len(proc.tmp_queue) == 1
    assert compiler.messages == []


def test_a_message_is_recorded_once_per_rule_not_once_per_copy():
    """One rule as the administrator wrote it reaches the printer as several.

    The service split gives an ICMP and a TCP half a rule each, the
    negation expansion builds three, the chain decisions split on top of
    that.  Saying the same sentence about each copy buries the rest of the
    report: firewall37-2 named its rules 12 to 15 twice for the same
    reason.  Two different rules still get one message each, and so does
    the same rule in another compiler - the iptables filter and mangle
    passes report separately, the way the Firewall Builder output does.
    """
    from firewallfabrik.compiler._base import BaseCompiler

    class _Rule:
        def __init__(self, label):
            self.label = label
            self.position = 0

    compiler = BaseCompiler()
    compiler.error(_Rule('12 (eth0)'), 'no incoming interface here')
    compiler.error(_Rule('12 (eth0)'), 'no incoming interface here')
    compiler.error(_Rule('13 (eth0)'), 'no incoming interface here')
    compiler.warning(_Rule('12 (eth0)'), 'something else entirely')

    assert len(compiler.get_errors()) == 2
    assert len(compiler.get_warnings()) == 1

    second = BaseCompiler()
    second.error(_Rule('12 (eth0)'), 'no incoming interface here')
    assert len(second.get_errors()) == 1
