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

"""What the iptables printer answers when it cannot build the ``-j`` part.

An empty string is a target of its own here: ``.CONTINUE`` is a rule that
deliberately carries no ``-j``.  A branch that has reported a problem must
therefore answer ``None``, or the caller keeps the rule and writes it out
with all of its matches and no target - which iptables accepts as a plain
packet counter, so the activation script runs to the end and nothing tells
the administrator that the marking, the traffic class or the custom action
was dropped.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._print_rule import PrintRule
from firewallfabrik.platforms.iptables._utils import DEFAULT_IPTABLES_VERSION


class _Compiler:
    def __init__(self) -> None:
        self.ipv6_policy = False
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _target(options, ipt_target=''):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )
    rule.ipt_target = ipt_target
    printer = PrintRule()
    printer.compiler = _Compiler()
    printer.version = DEFAULT_IPTABLES_VERSION
    return printer, printer._print_target(rule)


@pytest.mark.parametrize(
    ('options', 'ipt_target', 'what'),
    [
        ({'tagging': True}, '', 'a marking rule with no Tag Service'),
        ({'classification': True}, '', 'a classifying rule with no traffic class'),
        ({}, '.CUSTOM', 'a custom action with no target to run'),
    ],
)
def test_a_target_that_cannot_be_built_leaves_the_rule_out(options, ipt_target, what):
    printer, result = _target(options, ipt_target)
    assert result is None, what
    assert printer.compiler.messages, f'{what}: said nothing'


def test_continue_still_means_no_target_rather_than_no_rule():
    """`.CONTINUE` is why the failure branches cannot answer with ''."""
    _printer, result = _target({}, '.CONTINUE')
    assert result == ''
