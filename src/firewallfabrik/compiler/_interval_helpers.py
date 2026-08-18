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

"""Shared helpers for parsing Interval object data.

Used by both iptables and nftables compilers to extract time-of-day
and day-of-week constraints from Interval objects.
"""

from __future__ import annotations

# Day-of-week names following fwbuilder convention (0=Sun).
DOW_NAMES_FULL = {
    0: 'Sunday',
    1: 'Monday',
    2: 'Tuesday',
    3: 'Wednesday',
    4: 'Thursday',
    5: 'Friday',
    6: 'Saturday',
}

DOW_NAMES_SHORT = {
    0: 'Sun',
    1: 'Mon',
    2: 'Tue',
    3: 'Wed',
    4: 'Thu',
    5: 'Fri',
    6: 'Sat',
}


def parse_interval_data(
    data: dict,
) -> tuple[int, int, int, int, list[int]]:
    """Extract time-of-day and day-of-week from Interval.data.

    Handles both legacy (.fwb) and new (.fwf dialog) data formats:

    - Legacy: ``from_hour``, ``from_minute``, ``to_hour``, ``to_minute``
    - New:    ``from_time`` ("HH:mm"), ``to_time`` ("HH:mm")

    Returns:
        ``(start_h, start_m, end_h, end_m, days)`` where *days* is a
        sorted list of int day indices (0=Sun convention).
    """
    # -- Time --
    from_time = data.get('from_time', '')
    to_time = data.get('to_time', '')

    if from_time:
        parts = from_time.split(':')
        start_h = int(parts[0])
        start_m = int(parts[1]) if len(parts) > 1 else 0
    else:
        start_h = _safe_int(data.get('from_hour', -1))
        start_m = _safe_int(data.get('from_minute', -1))

    if to_time:
        parts = to_time.split(':')
        end_h = int(parts[0])
        end_m = int(parts[1]) if len(parts) > 1 else 0
    else:
        end_h = _safe_int(data.get('to_hour', -1))
        end_m = _safe_int(data.get('to_minute', -1))

    # Normalise unset values (fwbuilder stores -1 for "not set")
    if start_h < 0:
        start_h = 0
    if start_m < 0:
        start_m = 0
    if end_h < 0:
        end_h = 23
    if end_m < 0:
        end_m = 59

    # -- Days of week --
    days_str = data.get('days_of_week', '')
    if days_str:
        days = sorted(int(d) for d in days_str.split(',') if d.strip())
    else:
        days = _days_from_weekday_range(
            _safe_int(data.get('from_weekday', -1)),
            _safe_int(data.get('to_weekday', -1)),
        )

    return start_h, start_m, end_h, end_m, days


def _days_from_weekday_range(from_weekday: int, to_weekday: int) -> list[int]:
    """Return the day list an Interval without ``days_of_week`` stands for.

    Firewall Builder wrote the weekdays as a first/last pair before it
    grew the explicit list, and ``Interval::getDaysOfWeek``
    (fwbuilder libfwbuilder/src/fwbuilder/Interval.cpp) still falls back
    to ``constructDaysOfWeek(from_weekday, to_weekday)`` whenever the list
    is empty.  Reading the empty list as "every day" instead drops the
    restriction from every rule of such a file: a rule written for
    Monday to Friday then fires at the weekend too.

    The pair is a range that wraps, so Saturday to Sunday is two days and
    not six.  An unset end means Saturday and an unset start means Sunday,
    which is what the C++ does with -1; both unset gives the whole week,
    the same answer as before.
    """
    if from_weekday == -1 and to_weekday == -1:
        return list(range(7))
    start = min(max(from_weekday, 0), 6)
    end = 6 if to_weekday < 0 else min(to_weekday, 6)
    days = [start]
    while days[-1] != end:
        days.append((days[-1] + 1) % 7)
    return sorted(days)


def is_any_interval(data: dict) -> bool:
    """Return True if the interval data represents "Any" (no constraint).

    An interval is "Any" when it covers the full day (00:00-23:59) on
    all seven days of the week.
    """
    start_h, start_m, end_h, end_m, days = parse_interval_data(data)
    return (
        start_h == 0
        and start_m == 0
        and end_h == 23
        and end_m == 59
        and sorted(days) == list(range(7))
    )


def _safe_int(value, default: int = -1) -> int:
    """Convert a value to int, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
