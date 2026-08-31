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

"""A rule of a NAT type does not always end in the NAT target.

The negation expansions split a NAT rule into a jump into a temporary
chain and the rule inside it that carries the translation, and both keep
the rule type.  Only the second one may carry the target's own options:
`-j <chain> --random` is an option the jump does not have, iptables
answers "unknown option" and the activation script stops with the built-in
policies already at DROP.

Every branch of `_print_target_args` asks for its target for that reason;
the masquerading one did not.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import NATRuleType
from firewallfabrik.platforms.iptables._nat_print_rule import NATPrintRule


class _Compiler:
    def __init__(self):
        self.messages: list[str] = []

    @staticmethod
    def get_first_tsrc(_rule):
        return None

    get_first_tdst = get_first_tsrc
    get_first_tsrv = get_first_tsrc

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    error = warning


class _Printer:
    """The target-argument half of the NAT print rule, and its two helpers."""

    _print_target_args = NATPrintRule._print_target_args
    _print_nat_placement = NATPrintRule._print_nat_placement

    def __init__(self):
        self.compiler = _Compiler()
        self.version = '1.8'


def _rule(rule_type, target):
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=1,
        label='1 (NAT)',
        comment='',
        options={'ipt_nat_random': True, 'ipt_nat_persistent': True},
        negations={},
    )
    rule.nat_rule_type = rule_type
    rule.ipt_target = target
    return rule


def test_a_masquerading_rule_keeps_its_random_option():
    printer = _Printer()

    assert (
        printer._print_target_args(_rule(NATRuleType.Masq, 'MASQUERADE')) == '--random'
    )
    assert 'Persistent' in printer.compiler.messages[0]


@pytest.mark.parametrize(
    'rule_type',
    [NATRuleType.Masq, NATRuleType.SNAT, NATRuleType.DNAT, NATRuleType.Redirect],
)
def test_the_jump_into_a_temporary_chain_carries_no_target_option(rule_type):
    printer = _Printer()

    assert printer._print_target_args(_rule(rule_type, 'C0123456789ab.0')) == ''
    assert printer.compiler.messages == []
