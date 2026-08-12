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

"""The rate limit an nftables rule carries, against the netfilter translator.

The editor's "Limit matching rate" is a ceiling: the rule matches while the
traffic stays below it.  iptables says that with ``--hashlimit <n>``, the old
spelling of ``--hashlimit-upto``, and nftables with a plain ``limit rate``.
``limit rate over`` is the opposite and belongs to ``--hashlimit-above``,
which the editor cannot ask for.  Both mappings sit side by side in the gold
the netfilter tree ships, and can be reproduced with

    iptables-translate -A OUTPUT -m hashlimit --hashlimit-upto 300 \\
        --hashlimit-burst 15 --hashlimit-name https
    iptables-translate -A OUTPUT -m hashlimit --hashlimit-above 20kb/s \\
        --hashlimit-name https
"""

import pytest

from firewallfabrik.platforms.linux._netfilter import normalize_hashlimit_mode
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Rule:
    """The bit of a rule the rate printer reads."""

    def __init__(self, **options):
        self._options = options

    def get_option(self, key, default=None):
        return self._options.get(key, default)


class _Compiler:
    """The bit of PolicyCompiler_nft the rate printer reaches for."""

    def __init__(self):
        self.errors = []

    def error(self, rule, message):
        self.errors.append(message)


def _printer():
    printer = PrintRule_nft(name='PrintRule_nft')
    printer.compiler = _Compiler()
    return printer


@pytest.mark.parametrize(
    ('options', 'expected'),
    [
        # The plain case: a ceiling, so no `over`.
        ({}, 'limit rate 300/second'),
        # The suffix the editor stores is passed through as it stands.
        ({'hashlimit_suffix': '/hour'}, 'limit rate 300/hour'),
        # A burst is a packet count, unlike the byte burst `--hashlimit-burst`
        # takes for a byte rate.
        ({'hashlimit_burst': 15}, 'limit rate 300/second burst 15 packets'),
        ({'hashlimit_burst': 0}, 'limit rate 300/second'),
    ],
)
def test_hashlimit_rate_is_a_ceiling(options, expected):
    assert _printer()._hashlimit_rate(_Rule(**options), 300) == expected


def test_hashlimit_rate_never_says_over():
    """`over` inverts the match and would let exactly the excess through."""
    rate = _printer()._hashlimit_rate(_Rule(hashlimit_burst=2), 1)
    assert 'over' not in rate


def test_the_v2_1_spellings_of_the_key_are_normalised():
    """netfilter takes only the short ones.

    Firewall Builder 2.1 stored one string for the key, and an imported
    file can still carry it.  ``--hashlimit-mode destip`` is answered with
    "Bad value for --hashlimit-mode" by the real iptables, and the nftables
    side read the token as unknown and dropped the key altogether, which
    turned a per-destination limit into a limit for the rule as a whole.
    """
    assert normalize_hashlimit_mode('destip') == 'dstip'
    assert normalize_hashlimit_mode('destport') == 'dstport'
    assert normalize_hashlimit_mode('sourceip') == 'srcip'
    assert normalize_hashlimit_mode(' DstIP ') == 'dstip'
    # Anything already spelled the way netfilter wants it is left alone.
    assert normalize_hashlimit_mode('srcport') == 'srcport'


@pytest.mark.parametrize(
    ('suffix', 'expected'),
    [
        # iptables takes any prefix of a unit name, nftables the full word
        # alone, so what an imported file carries has to be written out.
        ('/sec', 'limit rate 300/second'),
        ('/min', 'limit rate 300/minute'),
        ('/h', 'limit rate 300/hour'),
        ('/d', 'limit rate 300/day'),
        ('/second', 'limit rate 300/second'),
        ('', 'limit rate 300/second'),
    ],
)
def test_a_short_rate_unit_is_written_out(suffix, expected):
    printer = _printer()
    assert printer._hashlimit_rate(_Rule(hashlimit_suffix=suffix), 300) == expected
    assert printer.compiler.errors == []


def test_a_unit_that_names_nothing_is_reported():
    """Passing it on would be a syntax error and cost the whole ruleset."""
    printer = _printer()
    assert (
        printer._hashlimit_rate(_Rule(hashlimit_suffix='/fortnight'), 300)
        == 'limit rate 300/second'
    )
    assert any('not a unit' in message for message in printer.compiler.errors)
