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

"""When a rule the address-family filter drops is worth a word.

An IPv4-only rule leaves the IPv6 pass of a dual-stack firewall with an
empty element, and the rule is dropped there.  That is what the rule says
it wants, and it is still compiled for the family it names, so fwbuilder
says nothing: `DropIPv4Rules` and `DropIPv6Rules` are the
`DropRulesByAddressFamilyAndServiceType` with an empty warning string,
and only `DropIPv6RulesWithWarning` carries one.  Saying it anyway put
one line per rule into the report of every dual-stack firewall - thirteen
on one real firewall of 30 rules - and buried the messages that matter.

Where the other family is not compiled at all the rule really is gone
from the firewall, and then it is said.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import DropRuleWithEmptyRE
from firewallfabrik.core.objects import PolicyAction


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self, other_family_is_compiled):
        self.other_family_is_compiled = other_family_is_compiled
        self.warnings = []

    def warning(self, rule, text):
        self.warnings.append(text)


def _drop(other_family_is_compiled, **flags):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=3,
        label='3 (eth0)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    for key, value in flags.items():
        setattr(rule, key, value)

    compiler = _Compiler(other_family_is_compiled)
    proc = DropRuleWithEmptyRE(name='drop')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return list(proc.tmp_queue), compiler.warnings


def test_a_rule_of_the_other_family_is_dropped_without_a_word():
    out, warnings = _drop(
        True, has_empty_re=True, empty_re_family_only=True, empty_re_reason='...'
    )
    assert out == [], 'the rule still leaves this pass'
    assert warnings == []


def test_but_not_when_the_other_family_is_not_compiled():
    """Then the rule is gone from the firewall, not only from one pass."""
    out, warnings = _drop(
        False,
        has_empty_re=True,
        empty_re_family_only=True,
        empty_re_reason='none of the addresses it names belong to the address '
        'family being compiled',
    )
    assert out == []
    assert len(warnings) == 1
    assert 'address family' in warnings[0]


@pytest.mark.parametrize('other_family_is_compiled', [True, False])
def test_every_other_reason_is_always_said(other_family_is_compiled):
    """An object that resolves to nothing is not the ordinary case."""
    out, warnings = _drop(
        other_family_is_compiled,
        has_empty_re=True,
        empty_re_reason='"block-list" resolves to no address at all',
    )
    assert out == []
    assert len(warnings) == 1
    assert 'resolves to no address' in warnings[0]


def test_a_rule_with_nothing_empty_is_kept():
    out, warnings = _drop(True)
    assert len(out) == 1
    assert warnings == []
