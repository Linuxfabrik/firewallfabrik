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

"""An iptables that has no ``--kerneltz`` matches the wrong hours, and says so.

``xt_time`` compares against UTC unless the rule carries
``XT_TIME_LOCAL_TZ`` (net/netfilter/xt_time.c), and the option that sets it
first ships in iptables 1.4.11 (netfilter ``extensions/libxt_time.c``).
Dropping it in silence leaves a rule that fires at different hours than the
editor shows - the same shape as the calendar window the compiler already
warns about below 1.4.0.

Firewall Builder never meets the case, because its editor greys the
checkbox out below 1.4.11 (``iptAdvancedDialog::loadFWObject``); a data
file written by another tool or by hand carries whatever it carries.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._print_rule import PrintRule

# 09:00 to 17:00 on Monday to Friday.
_INTERVAL_DATA = {
    'from_hour': 9,
    'from_minute': 0,
    'to_hour': 17,
    'to_minute': 0,
    'days_of_week': '1,2,3,4,5',
}


class _Interval:
    name = 'office hours'
    data = _INTERVAL_DATA


class _Firewall:
    def get_option(self, key):
        return key == 'use_kerneltz'


class _Compiler:
    def __init__(self):
        self.fw = _Firewall()
        self.messages: list[str] = []

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _run(version):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    rule.when = [_Interval()]
    printer = PrintRule()
    printer.compiler = _Compiler()
    printer.version = version
    return printer._print_time_interval(rule), printer.compiler.messages


@pytest.mark.parametrize('version', ['1.4.11', '1.8.11', '1.8'])
def test_a_release_that_has_the_option_writes_it(version):
    match, messages = _run(version)
    assert '--kerneltz' in match
    assert messages == []


@pytest.mark.parametrize('version', ['1.4.10', '1.4.0', '1.2.9'])
def test_a_release_without_it_says_the_rule_matches_in_utc(version):
    match, messages = _run(version)
    assert '--kerneltz' not in match
    assert messages, f'iptables {version} dropped --kerneltz without a word'
    assert 'UTC' in messages[0]


def test_the_rest_of_the_match_is_unchanged():
    match, _ = _run('1.4.10')
    assert '--timestart 09:00' in match
    assert '--timestop 17:00' in match
    assert '--weekdays Mon,Tue,Wed,Thu,Fri' in match
