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

"""An address table is read per address family, and that is not "empty".

``AddressTable::loadFromSource`` (libfwbuilder) keeps only the lines of
the family being compiled - `if (ipv6 && buf.find(":"))` and its IPv4
mirror - so a table of IPv6 prefixes resolves to nothing in the IPv4
pass.  Reading that as an empty group makes the one obvious way to write
a dual-stack rule, one table per family, refuse to compile: the IPv4 pass
aborts over the IPv6 table and the IPv6 pass over the IPv4 one, and
"Ignore rules with empty groups" is off by default.

The table of the other family is taken out of the element the way the
address-family filter takes out an address of the wrong family, and a
rule left with nothing goes with it - the other pass has that rule.
"""

import uuid

import pytest

from firewallfabrik.compiler._compiler import _address_table_entry
from firewallfabrik.compiler.processors._generic import EmptyGroupsInRE
from firewallfabrik.core.objects import AddressTable


@pytest.mark.parametrize(
    ('line', 'expected'),
    [
        ('192.0.2.0/24', '192.0.2.0/24'),
        ('  2001:db8::/32  ', '2001:db8::/32'),
        ('# a comment', ''),
        ('', ''),
        ('198.51.100.7 the office', '198.51.100.7'),
    ],
)
def test_what_a_line_of_the_file_names(line, expected):
    assert _address_table_entry(line) == expected


class _Compiler:
    def __init__(self, families, ipv6: bool) -> None:
        self._families = families
        self.ipv6_policy = ipv6

    def address_table_families(self, _obj):
        return self._families


def _asks(families, ipv6: bool) -> bool:
    processor = EmptyGroupsInRE('p', 'src')
    processor.compiler = _Compiler(families, ipv6)
    table = AddressTable(id=uuid.uuid4(), name='t', data={'filename': 't'})
    return processor._holds_the_other_family(table)


def test_a_v6_table_does_not_apply_to_the_v4_pass():
    assert _asks((False, True), ipv6=False)


def test_a_v4_table_does_not_apply_to_the_v6_pass():
    assert _asks((True, False), ipv6=True)


def test_a_table_of_this_family_is_not_the_other_one():
    assert not _asks((True, False), ipv6=False)
    assert not _asks((False, True), ipv6=True)


def test_a_dual_stack_table_belongs_to_both_passes():
    assert not _asks((True, True), ipv6=False)
    assert not _asks((True, True), ipv6=True)


def test_a_table_with_no_addresses_at_all_is_empty():
    """A missing file and a file of comments both answer (False, False).

    Those are the cases the empty-group report exists for, so they must
    not take the other-family exit.
    """
    assert not _asks((False, False), ipv6=False)
    assert not _asks((False, False), ipv6=True)
