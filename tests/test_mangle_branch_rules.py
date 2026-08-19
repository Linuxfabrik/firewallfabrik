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

"""Where a rule branching into a rule set with mangle rules is installed.

A branch rule set holding a rule that tags or classifies compiles into a
chain of the *mangle* table.  A jump to it therefore has to be installed
there too, and `MangleTableCompiler_ipt::keepMangleTableRules` installs one
per built-in chain the branch may need - the rules in it are the
administrator's, so the compiler does not know which hook their targets
require.  `CompilerDriver_ipt::findBranchesInMangleTable` is what marks
such a rule in the first place: it looks into the target rule set and sets
the rule's "branch in mangle table" option when it finds a tagging or
classifying rule there.

Without that, the jump is compiled into the filter table alone, where a
chain of the same name exists and is empty: the branch does nothing and
the traffic class or packet mark is never assigned.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._policy import (
    rule_set_classifies,
    rule_set_has_mangle_rules,
)
from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.platforms.iptables._mangle_compiler import KeepMangleTableRules
from firewallfabrik.platforms.nftables._policy_compiler import (
    KeepMangleTableRules as KeepMangleTableRulesNft,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    source_ruleset = None

    def __init__(self, mangle=(), classifying=()):
        self.mangle_branch_chains = set(mangle)
        self.classifying_branch_chains = set(classifying)
        self.warnings = []

    def warning(self, rule, text):
        self.warnings.append(text)


class _RuleSet:
    def __init__(self, rules):
        self.rules = rules
        self.options = {}


class _Rule:
    def __init__(self, **options):
        self.options = options


def _branch_rule(direction=Direction.Both, target='mymark', **options):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options={'branch_name': target, **options},
        negations={},
        action=PolicyAction.Branch,
        direction=direction,
    )


def _keep(cls, rule, compiler):
    proc = cls(name='keep')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return list(proc.tmp_queue)


def test_a_rule_set_that_tags_makes_a_branch_into_it_a_mangle_branch():
    assert rule_set_has_mangle_rules(_RuleSet([_Rule(tagging=True)]))
    assert rule_set_has_mangle_rules(_RuleSet([_Rule(classification='True')]))
    assert not rule_set_has_mangle_rules(_RuleSet([_Rule(log=True)]))
    assert rule_set_classifies(_RuleSet([_Rule(classification=True)]))
    assert not rule_set_classifies(_RuleSet([_Rule(tagging=True)]))


def test_the_branch_is_installed_in_all_three_chains():
    compiler = _Compiler(mangle={'mymark'})
    out = _keep(KeepMangleTableRules, _branch_rule(), compiler)
    assert [rule.ipt_chain for rule in out] == [
        'PREROUTING',
        'POSTROUTING',
        'FORWARD',
    ]


@pytest.mark.parametrize(
    ('direction', 'chains'),
    [
        (Direction.Inbound, ['PREROUTING', 'FORWARD']),
        (Direction.Outbound, ['POSTROUTING', 'FORWARD']),
    ],
)
def test_the_direction_decides_which_of_the_two_ends_is_used(direction, chains):
    compiler = _Compiler(mangle={'mymark'})
    out = _keep(KeepMangleTableRules, _branch_rule(direction=direction), compiler)
    assert [rule.ipt_chain for rule in out] == chains


def test_the_rules_own_option_is_enough():
    """A `.fwb` may carry it even when the target holds no mangle rule."""
    compiler = _Compiler()
    out = _keep(
        KeepMangleTableRules,
        _branch_rule(ipt_branch_in_mangle=True),
        compiler,
    )
    assert len(out) == 3


def test_iptables_does_not_enter_a_classifying_branch_from_prerouting():
    """xt_CLASSIFY registers for LOCAL_OUT, FORWARD and POST_ROUTING only."""
    compiler = _Compiler(mangle={'classify_2'}, classifying={'classify_2'})
    out = _keep(KeepMangleTableRules, _branch_rule(target='classify_2'), compiler)
    assert [rule.ipt_chain for rule in out] == ['POSTROUTING', 'FORWARD']
    assert compiler.warnings, 'the administrator has to be told'


def test_nftables_has_no_such_restriction():
    """`nft_meta_set_validate` checks the hook for `meta pkttype set` only."""
    compiler = _Compiler(mangle={'classify_2'}, classifying={'classify_2'})
    out = _keep(KeepMangleTableRulesNft, _branch_rule(target='classify_2'), compiler)
    assert [rule.ipt_chain for rule in out] == [
        'prerouting',
        'postrouting',
        'forward',
    ]
    assert not compiler.warnings
