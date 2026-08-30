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

"""A Branch rule may not jump into a chain that can reach itself.

The kernel walks every jump reachable from a base chain and answers
``-EMLINK`` once it has descended ``NFT_JUMP_STACK_SIZE`` levels
(``nft_chain_validate``, netfilter ``net/netfilter/nf_tables_api.c``), which
both tools report as "Too many links".  ``nft --check`` never sees it, so
only loading the ruleset does.

What it costs differs by tool and is bad on both: nftables refuses the whole
ruleset and the firewall keeps the rules it had, iptables refuses the jump
from every built-in chain and installs everything else.  Both compilers
therefore report the jump that closes the cycle and leave that one rule out,
which keeps the rest of the branch tree reachable.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import (
    DecideOnTarget as DecideOnTarget_ipt,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    DecideOnTarget as DecideOnTarget_nft,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _RuleSet:
    def __init__(self, name):
        self.name = name


class _Firewall:
    platform = 'nftables'


class _Compiler:
    def __init__(self, source, branch_chains, loop_edges):
        self.source_ruleset = _RuleSet(source)
        self.branch_chains = set(branch_chains)
        self.branch_loop_edges = set(loop_edges)
        self.fw = _Firewall()
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(branch_name, action=PolicyAction.Branch):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=2,
        label='2 (global)',
        comment='',
        options={'branch_name': branch_name},
        negations={},
        action=action,
    )


def _run(processor_class, rule, source, branch_chains, loop_edges):
    compiler = _Compiler(source, branch_chains, loop_edges)
    proc = processor_class(name='DecideOnTarget')
    proc.set_context(compiler)
    proc.prev_processor = _Feeder([rule])
    emitted = []
    while proc.process_next():
        while proc.tmp_queue:
            emitted.append(proc.tmp_queue.popleft())
    return compiler, emitted


_PROCESSORS = pytest.mark.parametrize(
    'processor_class', [DecideOnTarget_ipt, DecideOnTarget_nft]
)


@_PROCESSORS
def test_a_rule_set_branching_into_itself_is_left_out(processor_class):
    rule = _rule('Policy_A')
    compiler, emitted = _run(
        processor_class, rule, 'Policy_A', {'Policy_A'}, {('Policy_A', 'Policy_A')}
    )
    assert emitted == []
    assert compiler.messages
    assert 'Too many links' in compiler.messages[0]


@_PROCESSORS
def test_the_jump_that_closes_a_longer_cycle_is_left_out(processor_class):
    rule = _rule('Policy_A')
    compiler, emitted = _run(
        processor_class, rule, 'Policy_B', {'Policy_A'}, {('Policy_B', 'Policy_A')}
    )
    assert emitted == []
    assert 'Policy_B' in compiler.messages[0]


@_PROCESSORS
def test_a_branch_that_closes_nothing_is_emitted(processor_class):
    rule = _rule('Policy_A')
    compiler, emitted = _run(
        processor_class, rule, 'Policy', {'Policy_A'}, {('Policy_A', 'Policy_A')}
    )
    assert len(emitted) == 1
    assert compiler.messages == []
    assert emitted[0].ipt_target == 'Policy_A'


@_PROCESSORS
def test_a_stale_branch_option_on_another_action_is_not_a_loop(processor_class):
    """The action decides first, the way ``PolicyRule::getBranch`` does.

    An editor leaves ``branch_name`` behind when the action is changed, and
    three firewalls of the reference corpus carry one on an ordinary Accept.
    """
    rule = _rule('Policy_A', action=PolicyAction.Accept)
    compiler, emitted = _run(
        processor_class, rule, 'Policy_A', {'Policy_A'}, {('Policy_A', 'Policy_A')}
    )
    assert len(emitted) == 1
    assert compiler.messages == []
    assert emitted[0].ipt_target == 'ACCEPT'
