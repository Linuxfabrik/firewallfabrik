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

"""A branch rule set is compiled before the one that branches into it.

A NAT branch rule set becomes chains of its own, one per direction,
because prerouting and postrouting are separate hooks - so the rule
jumping into it can only name the chains that rule set really filled.
The driver learns those by compiling the rule set and hands them on as
``branch_ruleset_to_chain_mapping``, which means the order the rule sets
are compiled in decides whether the answer is there when it is read.

Read in declaration order, a branch rule set that branches into one
declared after it finds nothing: iptables then splits the rule into
PREROUTING and POSTROUTING the way Firewall Builder does with no answer
at all, and nftables leaves the rule out - so the translation is silently
missing and the rule set installs nothing, which takes the rule branching
into *it* with it.
"""

import uuid

from firewallfabrik.core.objects import NAT, NATAction, NATRule
from firewallfabrik.driver._compiler_driver import CompilerDriver


def _rule_set(name, top=False):
    rule_set = NAT(id=uuid.uuid4(), name=name, top=top, options={})
    rule_set.rules = []
    return rule_set


def _branch(target_name, position=0):
    rule = NATRule(
        id=uuid.uuid4(),
        position=position,
        comment='',
        options={'branch_name': target_name},
    )
    rule.nat_action = NATAction.Branch
    return rule


class _Driver(CompilerDriver):
    """The base driver, with only what the walk itself reaches."""

    def __init__(self):
        self._imported_rule_sets: set = set()


def _order(rule_sets, loop_edges=()):
    driver = _Driver()
    return [
        rule_set.name
        for rule_set in driver.order_branch_rule_sets(
            session=None, rule_sets=rule_sets, loop_edges=loop_edges
        )
    ]


def test_a_forward_reference_is_compiled_first():
    first = _rule_set('nat_a')
    second = _rule_set('nat_b')
    first.rules = [_branch('nat_b')]

    assert _order([first, second]) == ['nat_b', 'nat_a']


def test_a_chain_of_three_is_ordered_end_first():
    first = _rule_set('nat_a')
    second = _rule_set('nat_b')
    third = _rule_set('nat_c')
    first.rules = [_branch('nat_b')]
    second.rules = [_branch('nat_c')]

    assert _order([first, second, third]) == ['nat_c', 'nat_b', 'nat_a']


def test_a_rule_set_nobody_branches_into_keeps_its_place():
    first = _rule_set('nat_a')
    second = _rule_set('nat_b')

    assert _order([first, second]) == ['nat_a', 'nat_b']


def test_the_jump_that_closes_a_cycle_is_not_ordered_around():
    """The compilers leave that jump out, so the order need not honour it."""
    first = _rule_set('nat_a')
    second = _rule_set('nat_b')
    first.rules = [_branch('nat_b')]
    second.rules = [_branch('nat_a')]

    assert _order([first, second], loop_edges={('nat_b', 'nat_a')}) == [
        'nat_b',
        'nat_a',
    ]


def test_a_cycle_nobody_named_still_terminates():
    first = _rule_set('nat_a')
    second = _rule_set('nat_b')
    first.rules = [_branch('nat_b')]
    second.rules = [_branch('nat_a')]

    assert sorted(_order([first, second])) == ['nat_a', 'nat_b']


def test_a_branch_into_a_rule_set_of_another_firewall_is_not_ordered():
    """Only the rule sets handed in are ordered; anything else is left be."""
    first = _rule_set('nat_a')
    first.rules = [_branch('somewhere_else')]

    assert _order([first]) == ['nat_a']
