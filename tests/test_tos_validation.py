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

"""The ToS value the compiler checks before it reaches the command line.

``--tos`` takes a number from 0 to 255, optionally followed by "/" and a
mask, in any base C reads, or one of five symbolic names compared without
regard to case (netfilter libxtables/xtoptions.c, ``xtopt_parse_tosmask``
and ``tos_parse_numeric``; extensions/tos_values.c for the names).  Every
case below was offered to iptables 1.8.11 in a private network namespace
and answered the way the table says.

The check matters twice over: iptables answers an unreadable value by
stopping the activation script with every built-in policy already at DROP,
and the value is free text from the service editor that reaches the
generated script unquoted.
"""

import pytest

from firewallfabrik.core.objects import is_valid_tos


@pytest.mark.parametrize(
    ('value', 'why'),
    [
        ('0', 'the whole byte at zero'),
        ('16', 'decimal'),
        ('0x10', 'hex'),
        ('020', 'octal, which strtoul reads as base 0'),
        ('255', 'the top of the byte, above the DSCP ceiling of 63'),
        ('16/0xff', 'a value and a mask'),
        ('0/0', 'both at zero'),
        ('Minimize-Delay', 'a symbolic name'),
        ('minimize-delay', 'the comparison ignores case'),
        ('Maximize-Throughput', ''),
        ('Maximize-Reliability', ''),
        ('Minimize-Cost', ''),
        ('Normal-Service', ''),
    ],
)
def test_accepted_values(value, why):
    assert is_valid_tos(value), why


@pytest.mark.parametrize(
    ('value', 'why'),
    [
        ('', 'empty'),
        ('256', 'one above the byte'),
        ('16/256', 'the mask is bounded too'),
        ('-1', 'negative'),
        ('0xzz', 'not a number'),
        ('AF41', 'a DiffServ class is not a ToS name'),
        ('lowdelay', 'not one of the five names'),
        ('16/32/64', 'only one mask'),
        ('16 -j ACCEPT', 'a space ends the argument in the generated script'),
        ('$(id)', 'command substitution, run as root at activation time'),
        ('16;reboot', 'a second command'),
        ('`id`', 'the older spelling of the same thing'),
    ],
)
def test_rejected_values(value, why):
    assert not is_valid_tos(value), why
