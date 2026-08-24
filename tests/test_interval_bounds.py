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

"""A time object naming an hour or a weekday there is not.

The editor bounds both, so this is the same class as a port range that
runs backwards: a data file written by an older release, another tool or
by hand carries whatever it carries, and nothing between the file and the
generated rule asked.

What the two packet filters do with such a value:

* iptables refuses a time of day past 23:59 ("invalid time ... within the
  boundaries", netfilter extensions/libxt_time.c: time_parse_minutes) and
  the activation script stops there with every chain already at DROP; the
  kernel refuses the same window a second time
  (net/netfilter/xt_time.c: time_mt_check, -EDOM).
* iptables takes a weekday number without a bound while the kernel keeps
  the mask in a ``__u8``
  (include/uapi/linux/netfilter/xt_time.h: weekdays_match), so an eighth
  day silently becomes no day at all and the rule stops matching.
* nftables refuses the whole ruleset over either: its weekday vocabulary
  is Sunday to Saturday and nothing else (nftables src/meta.c:
  day_type_tbl, and ``meta day 7 drop`` is a ``;fail`` line in its own
  tests/py/any/meta.t), and ``meta hour "24:00" drop`` is another.

Before this check the day list also reached ``DOW_NAMES_SHORT[d]`` /
``DOW_NAMES_FULL[d]`` in the two print rules, so an eighth day ended the
compile with a ``KeyError`` and no script at all.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._interval_helpers import (
    DOW_NAMES_FULL,
    DOW_NAMES_SHORT,
    interval_problem,
    parse_interval_data,
)
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import VerifyTimeIntervals
from firewallfabrik.core.objects import Interval, PolicyAction

WHOLE_WEEK = '0,1,2,3,4,5,6'


@pytest.mark.parametrize(
    'data',
    [
        # An eighth day, and a day number the other side of the week.
        {'days_of_week': '1,2,8'},
        {'days_of_week': '7'},
        {'days_of_week': '-1'},
        {'days_of_week': 'Monday'},
        # A time of day neither tool can read.
        {'days_of_week': WHOLE_WEEK, 'from_hour': '25', 'to_hour': '23'},
        {'days_of_week': WHOLE_WEEK, 'from_hour': '0', 'to_hour': '24'},
        {'days_of_week': WHOLE_WEEK, 'from_minute': '60'},
        {'days_of_week': WHOLE_WEEK, 'to_minute': '99'},
        # The spelling the FirewallFabrik editor writes.
        {'days_of_week': WHOLE_WEEK, 'from_time': '25:00'},
        {'days_of_week': WHOLE_WEEK, 'to_time': '12:70'},
        {'days_of_week': WHOLE_WEEK, 'from_time': 'ab:cd'},
    ],
)
def test_a_window_neither_tool_can_carry_is_reported(data):
    assert interval_problem(data)


@pytest.mark.parametrize(
    'data',
    [
        {},
        {'days_of_week': WHOLE_WEEK},
        {'days_of_week': '1,2,3,4,5', 'from_hour': '9', 'to_hour': '17'},
        # -1 is how Firewall Builder stores "not set", on every field.
        {'from_hour': '-1', 'from_minute': '-1', 'to_hour': '-1', 'to_minute': '-1'},
        {'days_of_week': '6,0', 'from_time': '00:00', 'to_time': '23:59'},
        # An empty entry in the list is not a day.
        {'days_of_week': '1,,2'},
    ],
)
def test_a_window_both_tools_take(data):
    assert not interval_problem(data)


def test_every_day_the_check_lets_through_has_a_name_in_both_tables():
    """The print rules index those two tables with the day number."""
    for day in range(-2, 10):
        if interval_problem({'days_of_week': str(day)}):
            continue
        assert day in DOW_NAMES_SHORT
        assert day in DOW_NAMES_FULL


def test_parsing_a_broken_window_does_not_end_the_compile():
    """``parse_interval_data`` runs before the check and must not raise."""
    assert parse_interval_data({'from_time': 'ab:cd', 'days_of_week': 'x,1'})


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(interval_data):
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
    interval = Interval(id=uuid.uuid4(), name='broken hours')
    interval.data = interval_data
    rule.when = [interval]
    return rule


def _run(rule):
    proc = VerifyTimeIntervals(name='VerifyTimeIntervals')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return proc


def test_the_rule_is_left_out_and_the_time_object_is_named():
    proc = _run(_rule({'days_of_week': '1,2,8'}))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages
    assert 'broken hours' in proc.compiler.messages[0]


def test_an_ordinary_window_passes_through():
    proc = _run(_rule({'days_of_week': '1,2,3,4,5', 'from_hour': '9', 'to_hour': '17'}))
    assert len(proc.tmp_queue) == 1
    assert proc.compiler.messages == []
