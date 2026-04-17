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

"""Tests for :func:`firewallfabrik.core.objects.range_to_cidr`."""

import pytest

from firewallfabrik.core.objects import range_to_cidr


@pytest.mark.parametrize(
    ('start', 'end', 'expected'),
    [
        # IPv4 exact CIDR
        ('0.0.0.0', '255.255.255.255', '0.0.0.0/0'),  # nosec B104 — test value
        ('10.0.0.0', '10.255.255.255', '10.0.0.0/8'),
        ('172.16.0.0', '172.31.255.255', '172.16.0.0/12'),
        ('172.16.0.0', '172.19.255.255', '172.16.0.0/14'),
        (
            '172.16.0.0',
            '172.20.255.255',
            None,
        ),  # crosses /14 boundary, not a single CIDR
        ('192.168.0.0', '192.168.255.255', '192.168.0.0/16'),
        ('192.168.4.0', '192.168.4.255', '192.168.4.0/24'),
        ('192.168.4.0', '192.168.4.127', '192.168.4.0/25'),
        ('192.168.4.128', '192.168.4.255', '192.168.4.128/25'),
        # IPv4 single host
        ('192.168.1.1', '192.168.1.1', '192.168.1.1/32'),
        # IPv4 non-CIDR ranges
        ('192.168.4.10', '192.168.4.50', None),
        ('192.168.4.1', '192.168.4.255', None),  # starts mid-subnet
        ('192.168.4.0', '192.168.4.254', None),  # doesn't cover full /24
        # IPv6 exact CIDR
        ('::', '::', '::/128'),
        ('2001:db8::', '2001:db8::ffff:ffff:ffff:ffff', '2001:db8::/64'),
        ('2001:db8:0:1::', '2001:db8:0:1:ffff:ffff:ffff:ffff', '2001:db8:0:1::/64'),
        # IPv6 non-CIDR
        ('2001:db8::1', '2001:db8::ffff', None),
        # Mixed family / invalid / edge cases
        ('192.168.1.1', '2001:db8::1', None),
        ('not-an-ip', '192.168.1.1', None),
        ('192.168.1.1', 'not-an-ip', None),
        ('', '', None),
        ('192.168.1.1', '', None),
        ('', '192.168.1.1', None),
        # Reversed range (end < start)
        ('192.168.1.100', '192.168.1.1', None),
    ],
)
def test_range_to_cidr(start, end, expected):
    assert range_to_cidr(start, end) == expected
