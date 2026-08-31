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

"""The two halves of a rule that tags and classifies never share a chain.

`decideOnChainForClassify` splits such a rule: the mark belongs in
prerouting and the traffic class in postrouting.  Every chain name derived
afterwards is built out of the direction, the rule set, the position and
the subrule suffix, and the first three are the same for both halves - so
`Logging2` built one chain, put the MARK and the CLASSIFY in it, and
`-j CLASSIFY` outside postrouting is EINVAL: the activation stops there
with all three built-in policies already at DROP.

The mark cannot live in `subrule_suffix`, which is what the first fix
used: the four negation expansions run between the split and `Logging2`
and write their own 1/2/3 into that field, so a rule that is negated *and*
classified had both halves back in one chain (`RULE_13_3`).
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import Direction
from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt


class _RuleSet:
    name = 'Policy'


class _Namer:
    get_rule_set_name = Compiler.get_rule_set_name
    rule_set_key = Compiler.rule_set_key
    chain_name = PolicyCompiler_ipt.get_new_chain_name
    tmp_chain_name = PolicyCompiler_ipt.get_new_tmp_chain_name

    def __init__(self):
        self.source_ruleset = _RuleSet()
        self.rule_set_chain = ''
        self.tmp_chain_counters = {}


def _rule(subrule_suffix='', classify_half=False):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=13,
        label='13 (global)',
        comment='',
        options={},
        negations={},
        direction=Direction.Both,
    )
    rule.subrule_suffix = subrule_suffix
    rule.classify_half = classify_half
    return rule


def test_the_tagging_half_keeps_the_plain_name():
    assert _Namer().chain_name(_rule(), None) == 'RULE_13'


def test_the_classifying_half_is_told_apart():
    assert _Namer().chain_name(_rule(classify_half=True), None) == 'RULE_13_c'


def test_a_negation_suffix_does_not_swallow_the_mark():
    """The case `firewall1` rule 13 is: negated, tagged and classified."""
    namer = _Namer()
    tagging = namer.chain_name(_rule(subrule_suffix='3'), None)
    classifying = namer.chain_name(_rule(subrule_suffix='3', classify_half=True), None)

    assert tagging == 'RULE_13_3'
    assert classifying == 'RULE_13_3_c'
    assert tagging != classifying


def test_the_hashed_temporary_chains_of_the_two_halves_differ():
    """The negation expansions build their chains from the same three values.

    Only the policy printer is asked: classification is a policy rule
    option, so a NAT rule has no half to tell apart.
    """
    tagging = _Namer().tmp_chain_name(_rule(subrule_suffix='3'))
    classifying = _Namer().tmp_chain_name(_rule(subrule_suffix='3', classify_half=True))

    assert tagging != classifying


def test_the_mark_does_not_travel_to_the_tagging_half_on_a_clone():
    """`decideOnChainForClassify` clones before it marks, and must."""
    original = _rule()
    clone = original.clone()
    original.classify_half = True

    assert clone.classify_half is False
