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

"""A group nobody filled empties an element, and an empty element is "any".

That is the whole failure mode: a rule written for the interfaces in a
group, or for the addresses in one, loses its only condition when the
group turns out to be empty and is then installed for every interface and
every address there is.

``EmptyGroupsInRE`` asks the question ahead of the expansion wherever a
pipeline runs it - every element of a policy rule, and the six address and
service elements of a NAT rule.  The two interface elements of a NAT rule
have no such check (Firewall Builder has none either), so the expansion
itself has to notice, and it does: an element the expansion empties is
flagged and ``DropRuleWithEmptyRE`` takes the rule out with a word about
which object emptied it.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import ObjectGroup, PolicyAction


class _Fake:
    """Just enough of a Compiler to call expand_groups_in_element on."""

    session = None


def _rule(**slots) -> CompRule:
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
        **slots,
    )


@pytest.fixture()
def expand(monkeypatch):
    """Return expand_groups_in_element with a group expansion we control."""

    def _inner(rule, slot, members):
        monkeypatch.setattr(
            'firewallfabrik.compiler._compiler.expand_group',
            lambda _session, _obj: list(members),
        )
        Compiler.expand_groups_in_element(_Fake(), rule, slot)

    return _inner


def test_an_empty_group_takes_the_rule_with_it(expand):
    group = ObjectGroup(name='no-interfaces')
    rule = _rule(itf=[group])

    expand(rule, 'itf', [])

    assert rule.itf == []
    assert rule.has_empty_re is True, (
        'an interface element the expansion emptied reads as "any", so the '
        'rule has to be flagged for DropRuleWithEmptyRE'
    )
    assert 'no-interfaces' in rule.empty_re_reason


def test_a_group_with_members_leaves_the_rule_alone(expand):
    group = ObjectGroup(name='two-interfaces')
    members = [ObjectGroup(name='a'), ObjectGroup(name='b')]
    rule = _rule(itf=[group])

    expand(rule, 'itf', members)

    assert [obj.name for obj in rule.itf] == ['a', 'b']
    assert rule.has_empty_re is False


def test_an_element_that_was_any_stays_any(expand):
    rule = _rule(src=[])

    expand(rule, 'src', [])

    assert rule.src == []
    assert rule.has_empty_re is False, (
        '"any" is not an element something emptied, and a rule about any '
        'address is a rule the administrator wrote that way'
    )
