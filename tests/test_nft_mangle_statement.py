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

"""What the nftables printer answers when it cannot build the mark statement.

Setting the mark, the traffic class or the connection mark is the whole
point of such a rule.  A printer that reports the problem and then returns
the parts it happens to have leaves a rule that matches, counts and lets
the packet through unchanged, so every rule and every routing decision
keyed on that mark sees traffic the policy says is marked and finds it is
not.  The iptables ``_print_target`` returns None in the same three cases,
which is what ``test_ipt_target_fallback.py`` pins down.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Compiler:
    def __init__(self) -> None:
        self.ipv6_policy = False
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _statement(options, ipt_target=''):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Continue,
    )
    rule.ipt_target = ipt_target
    printer = PrintRule_nft()
    printer.compiler = _Compiler()
    return printer, printer._print_mangle_statement(rule)


@pytest.mark.parametrize(
    ('options', 'ipt_target', 'what'),
    [
        ({'tagging': True}, '', 'a marking rule with no Tag Service'),
        ({'classification': True}, '', 'a classifying rule with no traffic class'),
        (
            {'classification': True, 'classify_str': 'not a class'},
            '',
            'a traffic class nftables and iptables read differently',
        ),
        ({}, 'CONNMARK', 'a connection-marking rule with no operation'),
    ],
)
def test_a_statement_that_cannot_be_built_leaves_the_rule_out(
    options, ipt_target, what
):
    printer, result = _statement(options, ipt_target)
    assert result is None, what
    assert printer.compiler.messages, f'{what}: said nothing'


def test_a_rule_that_marks_nothing_still_has_no_statement():
    """'' is why the failure branches cannot answer with it."""
    _printer, result = _statement({}, '')
    assert result == ''


def test_a_traffic_class_is_written_out():
    _printer, result = _statement({'classification': True, 'classify_str': '1:11'})
    assert result == 'meta priority set 1:11'
