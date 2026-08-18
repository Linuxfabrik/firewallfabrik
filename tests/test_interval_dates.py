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

"""A time object that pins a calendar window keeps it.

Firewall Builder writes the window out as ``-m time --datestart`` /
``--datestop`` from iptables 1.4.0 on, and drops the daily window while
it does (fwbuilder iptlib/PolicyCompiler_PrintRule.cpp:1387).  Without
it a rule written to stop at the end of the year runs for good.

The reference values come from the Firewall Builder gold output for
``firewall61-1.4``, whose time object "test time 2" is
2008-03-13 01:01 to 2010-01-01 02:02.
"""

import pytest

from firewallfabrik.compiler._interval_helpers import (
    Date,
    date_problem,
    is_any_interval,
    parse_interval_dates,
)
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

TEST_TIME_2 = {
    'from_year': 2008,
    'from_month': 3,
    'from_day': 13,
    'from_hour': 1,
    'from_minute': 1,
    'to_year': 2010,
    'to_month': 1,
    'to_day': 1,
    'to_hour': 2,
    'to_minute': 2,
    'days_of_week': '0,1',
}


def test_the_window_is_read_off_the_object():
    start, stop = parse_interval_dates(TEST_TIME_2)
    assert start.iso() == '2008-03-13T01:01:00'
    assert stop.iso() == '2010-01-01T02:02:00'


def test_a_date_needs_day_month_and_year():
    # An Interval whose calendar part was never filled in stores -1
    # everywhere, which is not a window.
    data = dict(TEST_TIME_2, from_day=-1, to_month=-1)
    assert parse_interval_dates(data) == (None, None)


def test_an_interval_with_only_an_end_date_is_not_any():
    data = {
        'from_hour': 0,
        'from_minute': 0,
        'to_hour': 23,
        'to_minute': 59,
        'days_of_week': '0,1,2,3,4,5,6',
        'to_year': 2030,
        'to_month': 12,
        'to_day': 31,
    }
    assert not is_any_interval(data)


@pytest.mark.parametrize(
    'date',
    [
        # The Firewall Builder regression suite stores this one.
        Date(2935093, 2, 28, 0, 0),
        Date(1969, 12, 31, 0, 0),
        Date(2008, 13, 1, 0, 0),
        Date(2008, 1, 32, 0, 0),
    ],
)
def test_a_date_no_packet_filter_can_express_is_named(date):
    assert date_problem(date)


def test_a_date_both_tools_take_is_not_a_problem():
    assert date_problem(Date(2008, 3, 13, 1, 1)) == ''


def test_the_utc_epoch_matches_the_iso_form():
    # iptables sets TZ=UTC before it converts the option, so the number
    # in the rule is the UTC one whatever the compiling host runs in.
    start, stop = parse_interval_dates(TEST_TIME_2)
    assert (start.epoch(), stop.epoch()) == (1205370060, 1262311320)


@pytest.mark.parametrize(
    ('epoch', 'expected'),
    [
        (0, '"1970-01-01 00:00:00"'),
        (2147483647, '"2038-01-19 03:14:07"'),
    ],
)
def test_the_open_end_matches_what_iptables_translate_writes(epoch, expected):
    # netfilter extensions/libxt_time.txlate fills exactly these in for a
    # rule that names only one of the two dates.
    assert PrintRule_nft._time_literal(epoch, kerneltz=True) == expected
