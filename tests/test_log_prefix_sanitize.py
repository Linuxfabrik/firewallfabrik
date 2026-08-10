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

"""Tests for the log prefix both compilers hand to a grammar of their own.

A log prefix is free text and the macros splice object names into it, so it
has to pass the nftables parser and, on iptables, the shell that runs the
generated script.  Each character checked here is syntax in at least one of
the two: nftables reads ``$name`` as a variable and refuses the whole
ruleset over it (netfilter nftables src/preprocess.c), and the shell reads
``$``, a backtick and a backslash inside the double-quoted argument the
prefix ends up in.
"""

import pytest

from firewallfabrik.platforms.linux._netfilter import sanitize_log_prefix


@pytest.mark.parametrize(
    ('prefix', 'expected'),
    [
        # A prefix that needs nothing done to it is returned unchanged.
        ('RULE 0 -- ACCEPT ', 'RULE 0 -- ACCEPT '),
        ('rule/set:name ', 'rule/set:name '),
        # nftables has no escape for a double quote, so it becomes one both
        # platforms can carry.
        ('SSH "DENIED" ', "SSH 'DENIED' "),
        # A variable reference for the nftables preprocessor and for the
        # shell alike.
        ('RULE 0 -- $service ', 'RULE 0 -- service '),
        # Command substitution in the iptables script.
        ('RULE 0 -- `id` ', 'RULE 0 -- id '),
        ('RULE 0 -- $(id) ', 'RULE 0 -- (id) '),
        # The shell's escape character.
        ('RULE 0 -- a\\b ', 'RULE 0 -- ab '),
        # A rule line and a shell command line both end at a newline.
        ('RULE 0\n-- ACCEPT ', 'RULE 0-- ACCEPT '),
        ('RULE 0\t-- ACCEPT ', 'RULE 0-- ACCEPT '),
    ],
)
def test_sanitize(prefix, expected):
    assert sanitize_log_prefix(prefix) == expected


def test_nothing_survives_that_the_shell_would_act_on():
    """No character the shell expands is left in a sanitised prefix."""
    cleaned = sanitize_log_prefix('a$b`c\\d"e ')
    assert not set(cleaned) & set('$`\\"')
