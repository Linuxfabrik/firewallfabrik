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

"""Where a DNS Name and an Address Table keep what they resolve from.

Firewall Builder writes it as an XML attribute - ``DNSName dnsrec=`` and
``AddressTable filename=`` - and the `.fwb` reader copies attributes it
does not know by name into ``data``, so that is what an imported file
carries and what the compilers read.  The two editors wrote the value
under ``source_name`` instead, which no compiler reads: a DNS Name created
in FirewallFabrik resolved its own *object* name (`Compiler._resolve_dns`
falls back to it), and an Address Table came out with no file at all,
which is a set no packet is in.

`MultiAddress.get_source_name` is the one answer both spellings go
through, after `MultiAddress::getSourceName`.
"""

import uuid
from pathlib import Path

import pytest

from firewallfabrik.core.objects import AddressTable, DNSName


def _obj(cls, name, data):
    made = cls(id=uuid.uuid4(), name=name)
    made.data = data
    return made


@pytest.mark.parametrize(
    ('cls', 'key', 'value'),
    [
        (DNSName, 'dnsrec', 'www.example.com'),
        (AddressTable, 'filename', 'block-hosts.tbl'),
    ],
)
def test_the_spelling_an_imported_file_carries(cls, key, value):
    assert _obj(cls, 'object name', {key: value}).get_source_name() == value


@pytest.mark.parametrize('cls', [DNSName, AddressTable])
def test_the_spelling_the_editors_used_to_write(cls):
    """Files already written that way have to keep working."""
    assert _obj(cls, 'object name', {'source_name': 'kept'}).get_source_name() == 'kept'


@pytest.mark.parametrize('cls', [DNSName, AddressTable])
def test_nothing_stored_is_not_the_object_name(cls):
    """The caller decides what to fall back to; the model does not guess."""
    assert _obj(cls, 'object name', {}).get_source_name() == ''


@pytest.mark.parametrize(
    ('cls', 'key'),
    [(DNSName, 'dnsrec'), (AddressTable, 'filename')],
)
def test_writing_it_settles_on_one_spelling(cls, key):
    """Leaving the old key behind would make the two disagree on the next edit."""
    obj = _obj(cls, 'object name', {'source_name': 'old', 'run_time': True})
    data = obj.set_source_name('new')

    assert data[key] == 'new'
    assert 'source_name' not in data
    assert data['run_time'] is True
    # The object is not touched until the caller assigns the answer, which
    # is what lets the editor compare it against what was there before.
    assert obj.data == {'source_name': 'old', 'run_time': True}


def test_the_editors_and_the_compilers_use_the_same_key():
    """The bug was one module writing a key the other never read.

    Read as text: importing a dialog pulls in the whole GUI package, which
    needs a Qt display this suite does not have.
    """
    gui = Path(__file__).resolve().parents[1] / 'src' / 'firewallfabrik' / 'gui'

    for name in ('address_table_dialog.py', 'dns_name_dialog.py'):
        source = (gui / name).read_text()
        assert "data['source_name']" not in source
        assert 'get_source_name()' in source
        assert 'set_source_name(' in source


@pytest.mark.parametrize('cls', [DNSName, AddressTable])
@pytest.mark.parametrize(
    ('stored', 'expected'),
    [
        (True, True),
        (False, False),
        ('True', True),
        ('False', False),
        ('\n True \n', True),
        ('\n False \n', False),
        ('1', True),
        ('0', False),
        (None, False),
    ],
)
def test_the_resolve_mode_is_read_the_way_firewall_builder_reads_it(
    cls, stored, expected
):
    """``MultiAddress::isRunTime`` goes through ``FWObject::getBool``.

    A bare truthy test reads ``'False'`` as True and turns a
    compile-time table into a run-time one - the rules then name a set
    the script fills at activation instead of the addresses the table
    holds, and a routing rule naming it is left out altogether.
    """
    assert _obj(cls, 'object name', {'run_time': stored}).is_run_time() is expected


@pytest.mark.parametrize('cls', [DNSName, AddressTable])
def test_an_object_with_no_resolve_mode_is_compile_time(cls):
    assert _obj(cls, 'object name', {}).is_run_time() is False


@pytest.mark.parametrize(
    ('cls', 'key', 'label'),
    [
        (DNSName, 'dnsrec', 'DNS record'),
        (AddressTable, 'filename', 'Table file'),
    ],
)
def test_the_tooltip_names_the_source_and_the_resolve_mode(cls, key, label):
    """It used to read both off attributes these two objects do not have."""
    # The GUI package imports PySide6, which the CI runner does not install.
    pytest.importorskip('PySide6')
    from firewallfabrik.gui.tooltip_helpers import obj_tooltip

    made = _obj(cls, 'object name', {key: 'the source', 'run_time': True})
    tip = obj_tooltip(made)
    assert f'<b>{label}:</b> the source' in tip
    assert 'Run-time' in tip
