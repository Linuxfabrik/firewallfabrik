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

"""What Optimize1 leaves on the rule it moves into a temporary chain.

The optimiser turns one rule into a jump rule plus a detail rule in a chain
of its own, and a packet passes both.  A limit left on both is paid twice,
so it belongs on one of them - and on the detail rule, where the whole rule
has matched.  fwbuilder keeps it on the jump
(PolicyCompiler_ipt_optimizer.cpp, optimizeForRuleElement), which matches on
the one element being factored out and nothing else: a sender the rule does
not name then spends the rule's rate, and twenty packets from one left a
source the rule accepts with none.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import Optimize1


class _Feeder(BasicRuleProcessor):
    """Minimal source processor that yields pre-built CompRules."""

    def __init__(self, rules: list[CompRule]) -> None:
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    """The bit of PolicyCompiler_ipt the optimiser reaches for."""

    def __init__(self):
        self.chains = []

    def get_new_tmp_chain_name(self, rule):
        return 'Ctest.0'

    def register_chain(self, chain):
        self.chains.append(chain)

    def insert_upstream_chain(self, this_chain, new_chain):
        pass


def _optimized(options):
    """Return the jump rule and the detail rule Optimize1 produces."""
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )
    # Two elements with more than one object each, so the optimiser has
    # something to split on.
    rule.src = ['10.0.0.1', '10.0.0.2']
    rule.dst = ['10.0.1.1', '10.0.1.2']
    rule.ipt_chain = 'FORWARD'

    proc = Optimize1(name='Optimize1')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    jump, detail = proc.tmp_queue
    return jump, detail


def test_the_limits_are_cleared_on_the_jump_rule():
    """Otherwise a sender the rule does not name spends its rate."""
    jump, _detail = _optimized(
        {
            'limit_value': 8,
            'connlimit_value': 2,
            'hashlimit_value': 20,
        }
    )
    assert jump.get_option('limit_value') == -1
    assert jump.get_option('connlimit_value') == -1
    assert jump.get_option('hashlimit_value') == -1


def test_the_limits_stay_on_the_detail_rule():
    _jump, detail = _optimized(
        {
            'limit_value': 8,
            'connlimit_value': 2,
            'hashlimit_value': 20,
        }
    )
    assert detail.get_option('limit_value') == 8
    assert detail.get_option('connlimit_value') == 2
    assert detail.get_option('hashlimit_value') == 20
