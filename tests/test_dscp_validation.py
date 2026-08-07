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

"""Tests for the DSCP value both compilers validate before emitting a rule.

The values are the ones the real tools accept: iptables bounds --dscp by
XT_DSCP_MAX and matches --dscp-class against dscp_helper.c, nftables
rejects a code point above 63 with "exceeds valid range 0-63".
"""

import pytest

from firewallfabrik.core.objects import is_valid_dscp


@pytest.mark.parametrize(
    'value',
    [
        '0',
        '0x2e',
        '46',
        '63',
        'AF41',
        'af41',
        'BE',
        'cs7',
        'EF',
    ],
)
def test_accepted_values(value):
    assert is_valid_dscp(value)


@pytest.mark.parametrize(
    ('value', 'reason'),
    [
        ('', 'empty'),
        ('64', 'first code point out of range'),
        ('184', 'EF written as the whole traffic class byte'),
        ('0xb8', 'the same, in hex'),
        ('255', 'a full byte'),
        ('-1', 'negative'),
        ('AF4', 'class name missing its drop precedence'),
        ('CS8', 'there is no class selector 8'),
        ('lowest', 'not a class name at all'),
    ],
)
def test_rejected_values(value, reason):
    assert not is_valid_dscp(value), reason
