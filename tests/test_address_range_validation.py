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

"""An address range whose end is below its start.

The two packet filters disagree about how bad that is, and both answers
are bad.  iptables takes the command and warns "xt_iprange: range
10.0.0.9-10.0.0.1 is reversed and will never match", so the rule is
installed and dead - fail-open on a Deny.  nftables answers "Range
negative size" and refuses the *whole* ruleset, so the firewall never
gets the new policy at all.  Both offered to iptables 1.8.11 and nft
1.1.6 first.

Firewall Builder corrects the value in its editor
(``AddressRangeDialog::applyChanges`` moves the end up to the start) and
so does the FirewallFabrik editor; a data file written elsewhere carries
whatever it carries.
"""

import uuid

import pytest

from firewallfabrik.compiler.processors._generic import address_range_problem
from firewallfabrik.core.objects import AddressRange, IPv4


def _range(start, end):
    obj = AddressRange(id=uuid.uuid4(), name='probe')
    obj.start_address = {'address': start}
    obj.end_address = {'address': end}
    return obj


@pytest.mark.parametrize(
    ('start', 'end'),
    [
        ('192.168.1.200', '192.168.1.100'),
        ('10.0.0.9', '10.0.0.1'),
        ('2001:db8::9', '2001:db8::1'),
    ],
)
def test_a_range_that_runs_backwards_is_reported(start, end):
    assert address_range_problem(_range(start, end))


@pytest.mark.parametrize(
    ('start', 'end'),
    [
        ('192.168.1.100', '192.168.1.200'),
        # A range of one address is a range.
        ('192.168.1.100', '192.168.1.100'),
        ('2001:db8::1', '2001:db8::9'),
    ],
)
def test_a_range_both_tools_take(start, end):
    assert not address_range_problem(_range(start, end))


@pytest.mark.parametrize(
    ('start', 'end'),
    [
        # Half a range is not the question this check asks; the object is
        # dropped for having no address at all.
        ('192.168.1.100', ''),
        ('', '192.168.1.100'),
        # Two families is a different message.
        ('192.168.1.100', '2001:db8::1'),
        # Not an address at all.
        ('not-an-address', '192.168.1.100'),
    ],
)
def test_something_that_is_not_a_reversed_range(start, end):
    assert not address_range_problem(_range(start, end))


def test_only_an_address_range_is_asked():
    obj = IPv4(id=uuid.uuid4(), name='probe')
    obj.inet_addr_mask = {'address': '192.168.1.1', 'netmask': '255.255.255.255'}
    assert not address_range_problem(obj)
