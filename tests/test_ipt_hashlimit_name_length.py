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

"""How long the name of a rate limit table may be.

The match carries the name in a fixed field and `xtopt_parse_string`
(netfilter libxtables/xtoptions.c) stores the first bytes of anything
longer without a word.  The same mechanism was measured on a prefix, where
it is easier to see, in a private network namespace with iptables 1.8.11:

    iptables -A INPUT -j LOG \\
        --log-prefix 0123456789012345678901234567890123456789
    iptables -S INPUT
        -A INPUT -j LOG --log-prefix 01234567890123456789012345678

The field is `char name[IFNAMSIZ]` in revisions 0 and 1 of the match and
`char name[NAME_MAX]` in revisions 2 and 3 (netfilter
include/linux/netfilter/xt_hashlimit.h), and "dstlimit" is revision 0 under
its old name.  The cut matters because the kernel looks a hash table up by
its name alone (net/netfilter/xt_hashlimit.c, htable_find_get): two rules
whose names agree up to the cut count into one table at the rate of
whichever rule came first.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._print_rule import (
    MAX_HASHLIMIT_NAME_V1,
    MAX_HASHLIMIT_NAME_V2,
    PrintRule,
)


class _Compiler:
    def __init__(self):
        self.ipv6_policy = False
        self.muted_now = False
        self.hashlimit_tables = {}
        self.errors = []
        self.warnings = []

    def error(self, rule, message):
        self.errors.append(message)

    def warning(self, rule, message):
        self.warnings.append(message)


def _printer(version='1.8.11'):
    printer = PrintRule(name='PrintRule')
    printer.compiler = _Compiler()
    printer.version = version
    return printer


def _rule(position=1, **options):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=position,
        label=f'{position} (global)',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )


@pytest.mark.parametrize(
    ('version', 'options', 'ceiling'),
    [
        # Revision 2 and up: NAME_MAX - 1.
        ('1.8.11', {}, MAX_HASHLIMIT_NAME_V2),
        # Before 1.6.1 only revision 1 exists: IFNAMSIZ - 1.
        ('1.4.20', {}, MAX_HASHLIMIT_NAME_V1),
        # The "dstlimit" spelling is revision 0 under its old name, whatever
        # release is pinned.  It counts per destination and knows no other
        # key, so the mode goes with it.
        (
            '1.3.7',
            {'hashlimit_dstlimit': True, 'hashlimit_dstip': True},
            MAX_HASHLIMIT_NAME_V1,
        ),
    ],
)
def test_a_name_longer_than_the_field_is_cut_and_reported(version, options, ceiling):
    printer = _printer(version=version)
    name = 'n' * (ceiling + 5)
    out = printer._print_hashlimit(
        _rule(hashlimit_value=10, hashlimit_name=name, **options)
    )
    assert out is not None
    assert f'-name {"n" * ceiling} ' in out
    assert 'n' * (ceiling + 1) not in out
    assert any('has been truncated' in message for message in printer.compiler.warnings)


def test_a_name_that_fits_is_left_alone():
    printer = _printer()
    name = 'n' * MAX_HASHLIMIT_NAME_V2
    out = printer._print_hashlimit(_rule(hashlimit_value=10, hashlimit_name=name))
    assert f'--hashlimit-name {name}' in out
    assert printer.compiler.warnings == []


def test_two_names_that_differ_only_past_the_cut_are_reported_as_one_table():
    """The collision the truncation creates has to reach the report.

    `_check_hashlimit_table` compares what the command carries, so it only
    sees this once the name is cut before it is registered.
    """
    printer = _printer(version='1.4.20')
    base = 'htable_rule_1'
    printer._print_hashlimit(
        _rule(position=1, hashlimit_value=10, hashlimit_name=f'{base}00')
    )
    printer._print_hashlimit(
        _rule(position=2, hashlimit_value=99, hashlimit_name=f'{base}000')
    )
    assert any(
        'is already in use by another rule' in message
        for message in printer.compiler.warnings
    )
