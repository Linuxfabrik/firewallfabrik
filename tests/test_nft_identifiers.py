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

#
# Author:  Linuxfabrik GmbH, Zurich, Switzerland
# Contact: info (at) linuxfabrik (dot) ch
#          https://www.linuxfabrik.ch/
# License: The Unlicense, see LICENSE file.

"""Names of nftables objects.

The interesting part of this module is not the unit tests but
``test_keywords_are_still_rejected`` / ``test_renamed_keywords_are_accepted``,
which ask the installed ``nft`` whether ``NFT_KEYWORDS`` is still true.  They
are skipped where the installed ``nft`` cannot be asked - it needs a private
network namespace, which not every machine grants - so the suite keeps
running without them.  See ``tests/nft_probe.py``.
"""

import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.nftables._identifiers import (
    NFT_KEYWORDS,
    NFT_NAME_MAXLEN,
    is_valid_nft_identifier,
    nft_object_name,
    nft_quote,
)
from tests.nft_probe import CAN_ASK_NFT, SKIP_REASON


def _name_accepted(name: str) -> bool:
    """Ask nft whether *name* can name a table, chain, set or counter.

    All four are asked because a keyword may belong to one context only:
    ``bytes``, ``name`` and ``packets`` are keywords of the counter scan
    state and pass as a chain name.  Plain ``nft --check`` cannot initialise
    its cache without CAP_NET_ADMIN, so the check runs in a private network
    namespace.
    """
    declarations = (
        f'table inet {name} {{\n}}\n',
        f'table inet t {{\n    chain {name} {{\n    }}\n}}\n',
        f'table inet t {{\n    set {name} {{\n        type ipv4_addr\n    }}\n}}\n',
        f'table inet t {{\n    counter {name} {{\n    }}\n}}\n',
    )
    for ruleset in declarations:
        proc = subprocess.run(  # nosec B603 B607
            ['unshare', '-rn', 'nft', '--check', '-f', '-'],
            input=ruleset,
            capture_output=True,
            text=True,
            check=False,
        )
        if 'syntax error' in proc.stderr:
            return False
    return True


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('log', 'log_'),  # keyword
        ('drop', 'drop_'),  # keyword
        ('counter', 'counter_'),  # keyword
        ('outside', 'outside'),  # ordinary name, untouched
        ('Log', 'Log'),  # keywords are lower case only
        ('log_dmz', 'log_dmz'),  # only the whole name collides
        ('6bone.net', '_6bone.net'),  # would lex as a number
        ('-vpn', '_-vpn'),  # "-" is not a first character
        ('web servers', 'web_servers'),  # space is not in the alphabet
        ('a/b', 'a_b'),  # "/" would be legal but reads as a path
        ('', '_unnamed'),  # nothing left to name it after
        ('!!!', '___'),  # every character replaced
    ],
)
def test_nft_object_name(name, expected):
    assert nft_object_name(name) == expected


def test_nft_object_name_truncates():
    assert len(nft_object_name('x' * 400)) == NFT_NAME_MAXLEN


def test_nft_object_name_is_idempotent():
    for name in ('log', '6bone.net', '-vpn', 'web servers', ''):
        once = nft_object_name(name)
        assert nft_object_name(once) == once


def test_nft_object_name_always_returns_a_valid_identifier():
    for name in (*NFT_KEYWORDS, '', '-', '.', '9lives', 'a b c', 'x' * 400):
        assert is_valid_nft_identifier(nft_object_name(name))


def test_is_valid_nft_identifier():
    assert is_valid_nft_identifier('outside')
    assert not is_valid_nft_identifier('log')
    assert not is_valid_nft_identifier('')
    assert not is_valid_nft_identifier('6bone.net')
    assert not is_valid_nft_identifier('web servers')
    assert not is_valid_nft_identifier('x' * (NFT_NAME_MAXLEN + 1))


def test_nft_quote():
    assert nft_quote('plain') == '"plain"'
    assert nft_quote('say "hi"') == '"say \'hi\'"'


def test_no_keyword_carries_an_underscore():
    """The invariant the rename rests on.

    ``_`` is reserved to the first-character class of the scanner's
    ``string`` production, so no keyword can contain one and a name ending
    in ``_`` can never collide with one.
    """
    assert not [k for k in NFT_KEYWORDS if '_' in k or k != k.lower()]


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_keywords_are_still_rejected():
    """Every name in the list really is one nft refuses."""
    accepted = [k for k in sorted(NFT_KEYWORDS) if _name_accepted(k)]
    assert not accepted, f'no longer nft keywords: {accepted}'


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_renamed_keywords_are_accepted():
    """And the rename really does produce something nft takes."""
    rejected = [
        k for k in sorted(NFT_KEYWORDS) if not _name_accepted(nft_object_name(k))
    ]
    assert not rejected, f'rename does not help for: {rejected}'
