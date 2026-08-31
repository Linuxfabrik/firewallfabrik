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

"""The branch graph is walked by id *and* by name.

``CompilerDriver.find_branch_loop_edges`` is what names the jump that
closes a cycle, and ``test_branch_loop.py`` covers what the compilers do
with the answer.  This is the other half: the walk itself.

A Branch rule names its target the way ``PolicyRule::getBranch`` and
``NATRule::getBranch`` read it (fwbuilder Rule.cpp:488 and :920) - by id
where there is one, by name otherwise.  Only the `.fwb` reader resolves an
id, so a firewall stored in fwf's own format carries the name alone, and a
walk that follows ids only sees no jump at all: the cycle is emitted, the
kernel answers "Too many links" and nftables throws the whole ruleset away
without the compiler having said a word.
"""

import uuid

import pytest

from firewallfabrik.core.objects import NAT, NATAction, NATRule, Policy, PolicyAction
from firewallfabrik.core.objects import PolicyRule as PolicyRuleModel
from firewallfabrik.driver._compiler_driver import CompilerDriver


def _rule_set(cls, name, top=False):
    rule_set = cls(id=uuid.uuid4(), name=name, top=top, options={})
    rule_set.rules = []
    return rule_set


def _branch(cls, action_field, action, target_name, position=0):
    rule = cls(
        id=uuid.uuid4(),
        position=position,
        comment='',
        options={'branch_name': target_name},
    )
    setattr(rule, action_field, action)
    return rule


def _policy_branch(target_name, position=0):
    return _branch(
        PolicyRuleModel, 'policy_action', PolicyAction.Branch, target_name, position
    )


def _nat_branch(target_name, position=0):
    return _branch(NATRule, 'nat_action', NATAction.Branch, target_name, position)


class _Driver(CompilerDriver):
    """The base driver, with only what the walk itself reaches.

    ``_imported_rule_sets`` holds the rule sets of *another* firewall that
    this script compiles as well; none of them is here.
    """

    def __init__(self):
        self._imported_rule_sets: set = set()


def _edges(rule_sets):
    return _Driver().find_branch_loop_edges(session=None, rule_sets=rule_sets)


def test_a_name_only_cycle_is_found():
    """The case a `.fwf` firewall carries, and the editor writes."""
    top = _rule_set(Policy, 'Policy', top=True)
    first = _rule_set(Policy, 'branch_a')
    second = _rule_set(Policy, 'branch_b')
    top.rules = [_policy_branch('branch_a')]
    first.rules = [_policy_branch('branch_b')]
    second.rules = [_policy_branch('branch_a')]

    assert _edges([top, first, second]) == {('branch_b', 'branch_a')}


def test_a_rule_set_branching_into_itself_is_found():
    top = _rule_set(Policy, 'Policy', top=True)
    branch = _rule_set(Policy, 'branch_a')
    top.rules = [_policy_branch('branch_a')]
    branch.rules = [_policy_branch('branch_a')]

    assert _edges([top, branch]) == {('branch_a', 'branch_a')}


def test_a_branch_tree_without_a_cycle_names_no_edge():
    top = _rule_set(Policy, 'Policy', top=True)
    first = _rule_set(Policy, 'branch_a')
    second = _rule_set(Policy, 'branch_b')
    top.rules = [_policy_branch('branch_a'), _policy_branch('branch_b', position=1)]
    first.rules = [_policy_branch('branch_b')]

    assert _edges([top, first, second]) == set()


def test_a_nat_cycle_is_found_too():
    """NAT branch chains are jumped into the same way and cycle the same way."""
    top = _rule_set(NAT, 'NAT', top=True)
    first = _rule_set(NAT, 'nat_a')
    second = _rule_set(NAT, 'nat_b')
    top.rules = [_nat_branch('nat_a')]
    first.rules = [_nat_branch('nat_b')]
    second.rules = [_nat_branch('nat_a')]

    assert _edges([top, first, second]) == {('nat_b', 'nat_a')}


def test_a_name_is_looked_up_among_the_rule_sets_of_its_own_kind():
    """``findObjectByName`` is given the type, so a NAT set of the same
    name as a Policy set is not the target of a policy branch."""
    top = _rule_set(Policy, 'Policy', top=True)
    policy_branch = _rule_set(Policy, 'shared_name')
    nat_branch = _rule_set(NAT, 'shared_name')
    top.rules = [_policy_branch('shared_name')]
    policy_branch.rules = [_policy_branch('shared_name')]
    nat_branch.rules = []

    assert _edges([top, policy_branch, nat_branch]) == {('shared_name', 'shared_name')}


@pytest.mark.parametrize(
    ('cls', 'action_field', 'action'),
    [
        (PolicyRuleModel, 'policy_action', PolicyAction.Accept),
        (NATRule, 'nat_action', NATAction.Translate),
    ],
)
def test_a_stale_branch_name_on_another_action_is_not_followed(
    cls, action_field, action
):
    """An editor leaves the option behind when the action is changed."""
    top = _rule_set(Policy, 'Policy', top=True)
    branch = _rule_set(Policy, 'branch_a')
    top.rules = [_policy_branch('branch_a')]
    branch.rules = [_branch(cls, action_field, action, 'branch_a')]

    assert _edges([top, branch]) == set()
