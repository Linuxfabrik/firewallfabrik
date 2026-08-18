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

"""An Interval without ``days_of_week`` still names its weekdays.

Firewall Builder wrote the weekdays as a first/last pair before it grew
the explicit list, and ``Interval::getDaysOfWeek`` still falls back to
that pair whenever the list is empty (fwbuilder
libfwbuilder/src/fwbuilder/Interval.cpp: constructDaysOfWeek).  Reading
the empty list as "every day" drops the restriction from every rule of
such a file.
"""

import pytest

from firewallfabrik.compiler._interval_helpers import (
    is_any_interval,
    parse_interval_data,
)

ALL_DAYS = [0, 1, 2, 3, 4, 5, 6]


@pytest.mark.parametrize(
    ('from_weekday', 'to_weekday', 'expected'),
    [
        # Monday to Friday, the case the whole option exists for.
        (1, 5, [1, 2, 3, 4, 5]),
        # The pair is a range that wraps: Saturday to Sunday is two days.
        (6, 0, [0, 6]),
        # One day only.
        (3, 3, [3]),
        # An unset end means Saturday, an unset start means Sunday - what
        # constructDaysOfWeek() does with -1.
        (3, -1, [3, 4, 5, 6]),
        (-1, 4, [0, 1, 2, 3, 4]),
        # Both unset is the whole week, the answer this code always gave.
        (-1, -1, ALL_DAYS),
    ],
)
def test_weekday_pair_without_a_day_list(from_weekday, to_weekday, expected):
    data = {'from_weekday': from_weekday, 'to_weekday': to_weekday}
    assert parse_interval_data(data)[4] == expected


def test_the_day_list_wins_over_the_pair():
    data = {'days_of_week': '1,2', 'from_weekday': 6, 'to_weekday': 0}
    assert parse_interval_data(data)[4] == [1, 2]


def test_a_weekday_pair_is_not_any():
    data = {
        'from_hour': 0,
        'from_minute': 0,
        'to_hour': 23,
        'to_minute': 59,
        'from_weekday': 1,
        'to_weekday': 5,
    }
    assert not is_any_interval(data)
