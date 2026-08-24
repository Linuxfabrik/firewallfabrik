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

"""Packet mark statements, checked against the netfilter translator.

``tests/fixtures`` cannot reach these: a rule names its Tag Service through
``options['tagobject_id']``, which holds a database id, and the YAML reader
copies the options verbatim without resolving a reference path.  The
expected values below are what ``iptables-translate`` itself produces, so
they can be reproduced with

    iptables-translate -t mangle -A OUTPUT -j MARK --set-mark 0x40/0x32
"""

import pytest

from firewallfabrik.core.objects import is_valid_packet_mark
from firewallfabrik.platforms.nftables._print_rule import (
    print_connmark,
    print_mark_set,
)


@pytest.mark.parametrize(
    ('tag_code', 'expected'),
    [
        # No mask: the whole mark is replaced.
        ('0x40', 'meta mark set 0x40'),
        ('16', 'meta mark set 16'),
        # With a mask, --set-mark clears value|mask, not mask alone
        # (netfilter extensions/libxt_MARK.c, mark_tg_parse: O_SET_MARK
        # assigns info->mask = cb->val.mark | cb->val.mask).  0x40 | 0x32
        # is 0x72, so the bits kept are ~0x72 = 0xffffff8d.
        ('0x40/0x32', 'meta mark set mark and 0xffffff8d xor 0x40'),
        ('0x10/0xff', 'meta mark set mark and 0xffffff00 xor 0x10'),
        # Value and mask equal.  netfilter's translator takes its `mark ==
        # mask` shortcut here and writes `mark or 0x40`; the long form says
        # the same thing, (m & ~0x40) ^ 0x40 sets the bit and keeps the rest.
        ('0x40/0x40', 'meta mark set mark and 0xffffffbf xor 0x40'),
        # The leading-zero octal spelling both tools take.  iptables reads
        # `--set-mark 020/010` with base 0 and stores `--set-xmark
        # 0x10/0x18` (verified against 1.8.11), so the bits kept are
        # ~0x18 = 0xffffffe7 - the same answer as the decimal `16/8`.
        # Python's `int(s, 0)` refuses that spelling, which used to send
        # this value down the fallback below and throw the mask away.
        ('020/010', 'meta mark set mark and 0xffffffe7 xor 020'),
        ('16/8', 'meta mark set mark and 0xffffffe7 xor 16'),
        # Not a number: fall back to assigning the value as it stands.
        ('0x40/nonsense', 'meta mark set 0x40'),
    ],
)
def test_print_mark_set(tag_code, expected):
    assert print_mark_set(tag_code) == expected


def test_the_octal_spelling_the_validator_accepts_keeps_its_mask():
    """A value the editor takes must not lose half its meaning here.

    ``is_valid_packet_mark`` reads both halves the way C reads a number
    with base 0, so ``020/010`` passes it; assigning the value alone
    would replace the whole mark instead of the three bits the mask
    names, and a packet already carrying another mark would lose it on
    nftables and keep it on iptables.
    """
    assert is_valid_packet_mark('020/010')
    assert print_mark_set('020/010') == print_mark_set('16/8').replace('16', '020')


def test_print_connmark():
    assert print_connmark('--save-mark') == 'ct mark set mark'
    assert print_connmark('--restore-mark') == 'meta mark set ct mark'
