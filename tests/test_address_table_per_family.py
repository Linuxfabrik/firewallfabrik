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

"""A compile-time MultiAddress is read per address family, and that is not "empty".

Two kinds of object have members that are read per address family.
``AddressTable::loadFromSource`` (libfwbuilder) keeps only the lines of
the family being compiled - `if (ipv6 && buf.find(":"))` and its IPv4
mirror - and ``DNSName::loadFromSource`` looks the name up for one family
at a time.  So a table of IPv6 prefixes, and a host with an A record and
no AAAA, both come back empty in the other family's pass.

Reading that as an empty group, or as a failed DNS lookup, makes a
dual-stack rule set impossible: the IPv4 pass aborts over the IPv6 table
and the IPv6 pass over the IPv4 one, "Ignore rules with empty groups" is
off by default, and a single-stack host in any rule ends the compile with
"cannot resolve" about a name that resolves perfectly well.

Such an object is taken out of the element the way the address-family
filter takes out an address of the wrong family, and a rule left with
nothing goes with it - the other pass has that rule.  A name that
resolves in *neither* family is still an abort: that one really is gone.
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

    def multi_address_families(self, _obj):
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


class _LookupCompiler:
    """A compiler whose DNS is a dict, so the test asks no resolver."""

    def __init__(self, answers: dict, ipv6: bool = False) -> None:
        self._answers = answers
        self.ipv6_policy = ipv6
        self._dns_lookup_cache: dict = {}
        self.aborted: list[str] = []

    def abort(self, message: str) -> None:
        self.aborted.append(message)


def _dns_compiler(answers: dict, ipv6: bool = False):
    import socket

    from firewallfabrik.compiler._compiler import Compiler

    compiler = _LookupCompiler(answers, ipv6)
    compiler._dns_lookup = Compiler._dns_lookup.__get__(compiler)
    compiler.dns_name_families = Compiler.dns_name_families.__get__(compiler)
    compiler._resolve_dns_name = Compiler._resolve_dns_name.__get__(compiler)

    def getaddrinfo(name, _port, af, _socktype):
        got = answers.get((name, af))
        if not got:
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
        return [(af, None, None, '', (ip, 0)) for ip in got]

    return compiler, getaddrinfo


def _resolve(answers: dict, ipv6: bool):
    import socket
    from unittest import mock

    from firewallfabrik.core.objects import DNSName

    compiler, fake = _dns_compiler(answers, ipv6)
    name = DNSName(id=uuid.uuid4(), name='h.example.com', data={'dnsrec': ''})
    with mock.patch.object(socket, 'getaddrinfo', fake):
        resolved = compiler._resolve_dns_name(name)
        families = compiler.dns_name_families(name)
    return resolved, families, compiler.aborted


def test_a_host_with_only_an_a_record_is_not_a_failed_lookup():
    """The IPv6 pass gets nothing from it, and that is not an error.

    Saying "cannot resolve" about a name that resolves ends the compile
    over a host that is simply IPv4-only, which is most of them.
    """
    answers = {('h.example.com', 2): ['198.51.100.7']}  # AF_INET only
    resolved, families, aborted = _resolve(answers, ipv6=True)
    assert resolved == []
    assert aborted == []
    assert families == (True, False)


def test_the_same_host_still_resolves_in_its_own_pass():
    answers = {('h.example.com', 2): ['198.51.100.7']}
    resolved, _families, aborted = _resolve(answers, ipv6=False)
    assert [a.get_address() for a in resolved] == ['198.51.100.7']
    assert aborted == []


def test_a_name_that_resolves_in_neither_family_still_aborts():
    resolved, families, aborted = _resolve({}, ipv6=False)
    assert resolved == []
    assert families == (False, False)
    assert len(aborted) == 1
    assert 'cannot resolve' in aborted[0]
