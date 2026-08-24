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

"""Where the netlink group of a logging rule comes from.

The rule options dialog has a "Netlink group" spin box next to the
firewall-wide one, and Firewall Builder registers it under the same key
(``libgui/RuleOptionsDialog.cpp:148``).  Its print rule asks the rule
first and falls back to the firewall setting
(``iptlib/PolicyCompiler_PrintRule.cpp:725`` for NFLOG and ``:741`` for
ULOG); both fwf print rules read the firewall setting alone, so the value
set on the rule was stored, shown in the rule summary and never used.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.linux._netfilter import get_log_netlink_group


class _Firewall:
    def __init__(self, value) -> None:
        self.value = value

    def get_option(self, key, default=None):
        assert key == 'ulog_nlgroup'
        return self.value


class _Compiler:
    def __init__(self, firewall_value) -> None:
        self.fw = _Firewall(firewall_value)
        self.warnings: list[str] = []

    def warning(self, _rule, msg: str) -> None:
        self.warnings.append(msg)


def _rule(rule_value=None):
    options = {} if rule_value is None else {'ulog_nlgroup': rule_value}
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )


def test_the_rule_wins_over_the_firewall_setting():
    assert get_log_netlink_group(_Compiler('1'), _rule('7')) == '7'


@pytest.mark.parametrize('rule_value', [None, '', '   '])
def test_the_firewall_setting_is_the_fallback(rule_value):
    assert get_log_netlink_group(_Compiler('3'), _rule(rule_value)) == '3'


def test_neither_set_answers_empty():
    assert get_log_netlink_group(_Compiler(''), _rule()) == ''


def test_a_stored_number_is_read_as_a_number():
    """A .fwb writes every option as text, a .fwf may keep the int."""
    assert get_log_netlink_group(_Compiler(1), _rule(7)) == '7'


@pytest.mark.parametrize('value', ['65536', '70000', '-2', 'abc'])
def test_a_group_outside_the_group_space_is_reported_and_left_out(value):
    """iptables refuses it, nftables reads it modulo 65536.

    ``nft add rule ip t c log group 70000`` lists back as ``log group
    4464`` (nft 1.1.6), so the messages go to a group nothing is
    listening on; ``iptables -j NFLOG --nflog-group 70000`` answers "bad
    value for option \"--nflog-group\", or out of range (0-65535)"
    (1.8.11) and the activation script stops there.  Answering with the
    default group is what the log level two lines away in the print rules
    does for a level neither tool knows.
    """
    compiler = _Compiler('1')
    assert get_log_netlink_group(compiler, _rule(value)) == ''
    assert compiler.warnings


@pytest.mark.parametrize('value', ['0', '1', '32', '65535'])
def test_a_group_both_tools_take(value):
    compiler = _Compiler('1')
    assert get_log_netlink_group(compiler, _rule(value)) == value
    assert compiler.warnings == []


def test_the_firewall_setting_is_asked_the_same_question():
    compiler = _Compiler('70000')
    assert get_log_netlink_group(compiler, _rule()) == ''
    assert compiler.warnings
