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

"""What the nftables printer answers when it cannot build the verdict.

The counterpart of ``test_ipt_target_fallback.py``.  An empty string is a
verdict of its own here: ``.CONTINUE``, a LOG rule and a connection-marking
rule all end without one on purpose.  A branch whose chain does not exist
and a Custom action must therefore answer ``None``, or the caller keeps the
rule and writes it out with all of its matches and a bare ``counter`` - a
rule that counts the packets and hands the decision to whatever comes next,
while the activation reports success.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Compiler:
    def __init__(self) -> None:
        self.ipv6_policy = False
        self.branch_chains: set[str] = {'mail_in'}
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _verdict(action, ipt_target=''):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=action,
    )
    rule.ipt_target = ipt_target
    printer = PrintRule_nft()
    printer.compiler = _Compiler()
    return printer, printer._print_verdict(rule)


@pytest.mark.parametrize(
    ('action', 'ipt_target', 'what'),
    [
        (PolicyAction.Custom, '.CUSTOM', 'a custom action with no nftables meaning'),
        (PolicyAction.Branch, 'Policy', 'a branch into a hooked chain'),
        (PolicyAction.Branch, '', 'a branch naming no rule set'),
        (PolicyAction.Modify, '', 'an action nftables has no verdict for'),
    ],
)
def test_a_verdict_that_cannot_be_built_leaves_the_rule_out(action, ipt_target, what):
    printer, result = _verdict(action, ipt_target)
    assert result is None, what
    if ipt_target == 'Policy':
        assert printer.compiler.messages, f'{what}: said nothing'


@pytest.mark.parametrize(
    ('action', 'ipt_target', 'what'),
    [
        (
            PolicyAction.Continue,
            '.CONTINUE',
            'a rule that deliberately decides nothing',
        ),
        (
            PolicyAction.Continue,
            'LOG',
            'a log rule, whose verdict is the log statement',
        ),
        (PolicyAction.Continue, 'CONNMARK', 'a connection-marking rule'),
    ],
)
def test_no_verdict_is_still_a_valid_answer(action, ipt_target, what):
    """These are why the failure branches cannot answer with ''."""
    _printer, result = _verdict(action, ipt_target)
    assert result == '', what


def test_a_branch_into_a_declared_chain_jumps():
    _printer, result = _verdict(PolicyAction.Branch, 'mail_in')
    assert result == 'jump mail_in'
