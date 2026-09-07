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

"""The nftables spelling of iptables' ``-m tos --tos``.

The kernel matches ``(dsfield & mask) == value`` - the ToS byte of an IPv4
header, the traffic class of an IPv6 one (net/netfilter/xt_dscp.c,
``tos_mt``).  nftables has no name for that byte because it names its two
halves instead: ``dscp`` is its top six bits and ``ecn`` its bottom two
(nftables src/proto.c; ``XT_DSCP_SHIFT`` is the same 2).  So the one
iptables match becomes one nftables match per half, and both halves have
to be there or the rule says less than it was written to say.

Where the mask comes from is the half that is easy to get wrong: a number
without one is matched under the *whole* byte, a symbolic name under 0x3F
(netfilter libxtables/xtoptions.c, ``tos_parse_numeric`` with ``UINT8_MAX``
against the ``.max`` of ``tos_mt_opts``).

Every expected form below was loaded into nft 1.1.7 in a private network
namespace and listed back; ``ip dscp & 0x0f 0x04 ip ecn 0x00`` linearises
to ``((tos & 0xfc) >> 2) & 0x0f == 0x04`` and ``(tos & 0x03) == 0x00``,
which is ``(tos & 0x3f) == 0x10``.
"""

import pytest

from firewallfabrik.core.objects import parse_tos
from firewallfabrik.platforms.nftables._print_rule import print_tos_matches


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('0x10', (0x10, 0xFF)),
        ('16', (0x10, 0xFF)),
        ('020', (0x10, 0xFF)),
        ('0x10/0xfc', (0x10, 0xFC)),
        ('Minimize-Delay', (0x10, 0x3F)),
        ('minimize-delay', (0x10, 0x3F)),
        ('Maximize-Throughput', (0x08, 0x3F)),
        ('Maximize-Reliability', (0x04, 0x3F)),
        ('Minimize-Cost', (0x02, 0x3F)),
        ('Normal-Service', (0x00, 0x3F)),
        ('bogus', None),
        ('256', None),
        ('1/2/3', None),
    ],
)
def test_parse_tos(value, expected):
    """The value/mask pair netfilter reads out of the text."""
    assert parse_tos(value) == expected


@pytest.mark.parametrize(
    ('value', 'ipv6', 'expected'),
    [
        # The whole byte: both halves are pinned.
        ('0x10', False, ['ip dscp 0x04', 'ip ecn 0x00']),
        ('0x10', True, ['ip6 dscp 0x04', 'ip6 ecn 0x00']),
        # EF written as the whole ToS byte, which is how it is usually
        # typed; 0xb8 >> 2 is 0x2e, and nft lists that back as `ef`.
        ('0xb8', False, ['ip dscp 0x2e', 'ip ecn 0x00']),
        # A mask that stops at the DSCP boundary leaves ECN unconstrained.
        ('0x10/0xfc', False, ['ip dscp 0x04']),
        # ... and one that covers only ECN leaves DSCP unconstrained.
        ('0x03/0x03', False, ['ip ecn 0x03']),
        # A symbolic name is matched under 0x3F, so four DSCP bits and
        # both ECN bits - not the whole byte.
        ('Minimize-Delay', False, ['ip dscp & 0x0f 0x04', 'ip ecn 0x00']),
        ('Minimize-Cost', True, ['ip6 dscp & 0x0f 0x00', 'ip6 ecn 0x02']),
        # A mask reaching into both halves needs one match of each.
        ('0x10/0x1e', False, ['ip dscp & 0x07 0x04', 'ip ecn & 0x02 0x00']),
        # A mask of zero matches every packet, which is what iptables does
        # with it too, so it is no match at all.
        ('0/0', False, []),
    ],
)
def test_print_tos_matches(value, ipv6, expected):
    """The matches the printer builds for a usable ToS value."""
    assert print_tos_matches(value, ipv6) == expected


@pytest.mark.parametrize(
    ('value', 'why'),
    [
        ('bogus', 'netfilter reads no such value'),
        ('300', 'above the byte'),
        (
            '0x20/0x03',
            'the value sets a bit the mask does not cover, so '
            '(dsfield & mask) == value is false for every packet - and the '
            'two halves cannot say that, because each compares only the '
            'bits it owns',
        ),
        ('0xff/0x0f', 'same, with the bits the other way round'),
    ],
)
def test_print_tos_matches_refuses(value, why):
    """A value no packet can match is refused, not split."""
    assert print_tos_matches(value, False) is None, why
    assert print_tos_matches(value, True) is None, why
