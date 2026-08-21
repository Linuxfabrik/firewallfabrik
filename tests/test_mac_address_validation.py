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

"""The MAC address a physAddress carries, on its way into both grammars.

Nothing checked it - not here and not in Firewall Builder, whose
``physAddress`` stores the string unread - and it reaches
``-m mac --mac-source`` and ``ether saddr`` as it was typed.  iptables
answers "Invalid MAC address specified." and stops the activation script
with every chain already at DROP; nftables answers a syntax error and
refuses the whole ruleset.  On iptables the value is a bare shell word on
top, so a semicolon starts a second command, as root, at that moment.

The two tools also disagree on one spelling: nftables reads
``aa-bb-cc-dd-ee-ff`` and prints it back with colons, iptables refuses it.
Both spellings mean the same address, so it is written out with colons.

Every case here was offered to iptables 1.8.11 and nft 1.1.6 first.
"""

import uuid

import pytest

from firewallfabrik.compiler.processors._generic import mac_address_problem
from firewallfabrik.core.objects import IPv4, PhysAddress, normalize_mac_address


def _mac(value):
    obj = PhysAddress(id=uuid.uuid4(), name='probe')
    obj.inet_addr_mask = {'address': value}
    return obj


@pytest.mark.parametrize(
    ('written', 'emitted'),
    [
        ('aa:bb:cc:dd:ee:ff', 'aa:bb:cc:dd:ee:ff'),
        ('AA:BB:CC:DD:EE:FF', 'aa:bb:cc:dd:ee:ff'),
        # One digit per group is the ``{1,2}`` of nft's scanner and the
        # ``end - arg > 2`` of xtopt_parse_ethermac; both tools take it.
        ('a:b:c:d:e:f', '0a:0b:0c:0d:0e:0f'),
        ('1:2:3:4:5:6', '01:02:03:04:05:06'),
        ('0:0:0:0:0:0', '00:00:00:00:00:00'),
        # The spelling only nftables reads, written out as both take it.
        ('aa-bb-cc-dd-ee-ff', 'aa:bb:cc:dd:ee:ff'),
        ('AA-BB-CC-DD-EE-FF', 'aa:bb:cc:dd:ee:ff'),
        # Surrounding blanks would end the shell word early.
        (' aa:bb:cc:dd:ee:ff ', 'aa:bb:cc:dd:ee:ff'),
    ],
)
def test_a_mac_both_tools_take(written, emitted):
    assert normalize_mac_address(written) == emitted
    assert not mac_address_problem(_mac(written))


@pytest.mark.parametrize(
    'written',
    [
        # Too few and too many groups.
        'aa:bb:cc:dd:ee',
        'aa:bb:cc:dd:ee:ff:00',
        # Three digits in a group.
        'aa:bb:cc:dd:ee:fff',
        # Not hex.
        'aa:bb:cc:dd:ee:gg',
        # No separator at all.
        'aabbccddeeff',
        # Mixed separators.
        'aa:bb-cc:dd-ee:ff',
        # iptables reads strtoul, so it takes both of these and nftables
        # refuses them - a value only one platform takes is the
        # portability bug this check is here to stop.
        ':::::',
        '-1:2:3:4:5:6',
        # The shell, not the packet filter.
        'aa:bb:cc:dd:ee:ff;reboot',
        'a;reboot',
        '$(id)',
    ],
)
def test_a_mac_neither_tool_should_be_offered(written):
    assert normalize_mac_address(written) == ''
    assert mac_address_problem(_mac(written))


def test_an_object_with_no_mac_is_not_this_check_s_business():
    """The print rules have reported and dropped that one since forever.

    A Host that simply carries no physAddress must not lose its rule here.
    """
    assert not mac_address_problem(_mac(''))
    address = IPv4(id=uuid.uuid4(), name='probe')
    address.inet_addr_mask = {'address': '192.168.1.1', 'netmask': '255.255.255.255'}
    assert not mac_address_problem(address)
