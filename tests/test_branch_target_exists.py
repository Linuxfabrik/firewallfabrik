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

"""A Branch rule that reaches no rule set has to say so.

Only a rule set of this firewall that is not the top one becomes a chain
carrying rules.  Branching anywhere else - into the top rule set, whose
rules live in the built-in chains, or into a rule set of another firewall
object, which fwf does not compile into this script - leaves iptables
with a chain it creates, jumps into and never fills, so the packet
returns and the rule does nothing while the activation reports success.
nftables has reported that since branch support landed there; this is the
iptables half.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import DecideOnTarget


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self, branch_chains):
        self.branch_chains = set(branch_chains)
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _branch_rule(branch_name):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={'branch_name': branch_name},
        negations={},
        action=PolicyAction.Branch,
    )


def _run(rule, branch_chains):
    compiler = _Compiler(branch_chains)
    proc = DecideOnTarget(name='DecideOnTarget')
    proc.set_context(compiler)
    proc.prev_processor = _Feeder([rule])
    while proc.process_next():
        pass
    return compiler


@pytest.mark.parametrize(
    ('branch_name', 'branch_chains'),
    [
        # A rule set of another firewall object.
        ('mail_server_inbound', {'rule2_branch'}),
        # The firewall's own top rule set: its rules are in INPUT, OUTPUT
        # and FORWARD, not in a chain of that name.
        ('Policy', {'rule5_branch'}),
        # No rule set at all is compiled into a chain.
        ('anything', set()),
    ],
)
def test_branch_to_a_chain_nobody_fills_is_reported(branch_name, branch_chains):
    rule = _branch_rule(branch_name)
    compiler = _run(rule, branch_chains)
    assert compiler.messages, f'branching to {branch_name!r} went unreported'
    assert branch_name in compiler.messages[0]


def test_branch_to_a_compiled_rule_set_is_silent():
    rule = _branch_rule('rule2_branch')
    compiler = _run(rule, {'rule2_branch', 'rule5_branch'})
    assert compiler.messages == []
    assert rule.ipt_target == 'rule2_branch'
