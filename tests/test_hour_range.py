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

"""Tests for the nftables ``meta hour`` match of a time-of-day window.

The reference is the iptables time match, which compares the two ends of
the window the other way round once the start is behind the stop, so that
a window running past midnight matches the night (netfilter kernel
net/netfilter/xt_time.c: time_mt).
"""

import pytest

from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

HOUR = 3600


@pytest.fixture()
def print_rule():
    return PrintRule_nft()


def test_window_inside_one_day(print_rule):
    assert (
        print_rule._print_hour_range(9 * HOUR, 17 * HOUR, kerneltz=False)
        == 'meta hour 32400-61200'
    )


def test_window_past_midnight_excludes_the_gap(print_rule):
    # 22:00 to 06:00 matches the night, so only 06:00:01 to 21:59:59 is out.
    assert (
        print_rule._print_hour_range(22 * HOUR, 6 * HOUR, kerneltz=False)
        == 'meta hour != 21601-79199'
    )


def test_window_covering_the_whole_day_needs_no_match(print_rule):
    # The iptables match never rejects a packet when the two ends meet.
    assert print_rule._print_hour_range(HOUR, HOUR, kerneltz=False) == ''
    assert print_rule._print_hour_range(HOUR, HOUR - 1, kerneltz=False) == ''


def test_kernel_timezone_uses_time_literals(print_rule):
    assert (
        print_rule._print_hour_range(9 * HOUR, 17 * HOUR, kerneltz=True)
        == 'meta hour "09:00:00"-"17:00:00"'
    )
    assert (
        print_rule._print_hour_range(22 * HOUR, 6 * HOUR, kerneltz=True)
        == 'meta hour != "06:00:01"-"21:59:59"'
    )
