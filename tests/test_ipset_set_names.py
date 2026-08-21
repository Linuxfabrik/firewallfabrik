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

"""The name an address table gets when it is matched through ipset.

Two things bound it and only one of them was asked.

**Length.** ipset stores a name in ``IPSET_MAXNAMELEN`` bytes (32, see
``include/libipset/linux_ip_set.h``), so 31 characters is the longest one
``check_setname`` takes.  But the set the rules match on is a ``setlist``
and the shell function that fills it creates ``<name>:ip`` and
``<name>:net`` beside it, so four more characters have to fit as well -
and those two ``ipset -N`` calls do not stop the script when they fail,
so the setlist ends up empty and every rule matching the table matches
nothing.

**Alphabet.** ipset checks no characters at all, but the name is a bare
shell word in ``-m set --match-set <name> src`` and a double-quoted one
in the ``reload_address_table`` call.  Firewall Builder replaces six
characters (``normalizeSetName``); everything else went through, which is
the same hole the chain names and interface names had.
"""

import pytest

from firewallfabrik.platforms.iptables._utils import (
    IPSET_MAX_NAME_LENGTH,
    normalize_set_name,
)

# ``:net`` is the longest suffix the shell function appends.
_LONGEST_SUFFIX = ':net'


@pytest.mark.parametrize('ipv6', [False, True])
@pytest.mark.parametrize(
    'name',
    [
        'block-hosts',
        'a-name-that-is-far-too-long-for-ipset-to-carry',
        'x' * IPSET_MAX_NAME_LENGTH,
        'x' * (IPSET_MAX_NAME_LENGTH - 1),
    ],
)
def test_the_subsets_fit_too(name, ipv6):
    assert (
        len(normalize_set_name(name, ipv6) + _LONGEST_SUFFIX) <= IPSET_MAX_NAME_LENGTH
    )


@pytest.mark.parametrize(
    'name',
    [
        'a;reboot',
        'a`id`',
        'a$(id)',
        'two words',
        'a|b',
        'a&b',
        'a*b',
        'a>b',
        "a'b",
        'a"b',
        'a\\b',
    ],
)
def test_a_name_the_shell_would_read_as_syntax(name):
    """Nothing outside the alphabet survives into the command."""
    assert set(normalize_set_name(name)) <= set(
        '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.:-'
    )


def test_the_two_families_get_different_names():
    """A set carries one family, so a dual-stack table needs one each."""
    assert normalize_set_name('block-hosts') != normalize_set_name(
        'block-hosts', ipv6=True
    )


def test_an_ordinary_name_is_left_alone():
    """The rule and the loader have to agree, so the transform is stable."""
    assert normalize_set_name('block-hosts') == 'block-hosts'
    assert normalize_set_name('block-hosts', ipv6=True) == 'block-hosts_v6'
