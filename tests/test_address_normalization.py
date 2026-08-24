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

"""An address an editor takes is one the compilers can read back.

Issue #154: an address object came out of the editor carrying a space,
and every rule naming it stopped matching.  The editor trims the field
for the check and then stored the field, so a value that a paste out of
a wiki page or a PDF brings along - a trailing space, a non-breaking
space, neither of them visible in the field - passed as an address and
was written untrimmed.

``ipaddress.ip_network('192.168.2.0 /255.0.0.0')`` raises, and every
compiler path answers a raise by dropping the netmask and printing the
address alone.  A rule written for 192.168.2.0/8 was installed as a rule
about the single host 192.168.2.0, in a script that loads without a word
of warning.  Firewall Builder has no such gap because it stores the
``InetAddr`` it validated (``NetworkDialog::applyChanges``).

The netmask half of the same defect is covered by
``test_netmask_validation.py``.
"""

import ast
import ipaddress
import pathlib

import pytest

from firewallfabrik.gui.netmask import (
    address_for_ipv4,
    address_for_ipv6,
    netmask_for_ipv4_address,
)

ADDRESS_DIALOGS = (
    pathlib.Path(__file__).resolve().parents[1]
    / 'src'
    / 'firewallfabrik'
    / 'gui'
    / 'address_dialogs.py'
)

# What a paste carries along and what the field does not show.  U+00A0 is
# the one that survives a copy out of rendered HTML; str.strip() drops it,
# which is exactly why it passed the check and broke the compile.
INVISIBLE = [' ', '\t', '\xa0', '\u2009']


@pytest.mark.parametrize('padding', INVISIBLE)
def test_an_ipv4_address_is_stored_without_what_a_paste_carried_along(padding):
    assert address_for_ipv4(f'{padding}192.168.2.0{padding}') == '192.168.2.0'


@pytest.mark.parametrize('padding', INVISIBLE)
def test_an_ipv6_address_is_stored_without_what_a_paste_carried_along(padding):
    assert address_for_ipv6(f'{padding}2001:db8::1{padding}') == '2001:db8::1'


def test_an_ipv6_address_is_stored_the_way_inet_ntop_writes_it():
    """``InetAddr::toString()`` writes the normal form, so the editors do too."""
    assert address_for_ipv6('2001:0DB8:0000:0000:0000:0000:0000:0001') == '2001:db8::1'


@pytest.mark.parametrize('typed', ['192.168.2', '192.168.2.256', 'eth0', '', ' '])
def test_an_ipv4_address_the_editor_cannot_read_is_refused(typed):
    assert address_for_ipv4(typed) is None


@pytest.mark.parametrize('typed', ['2001:db8::x', '192.168.2.0', '', ' '])
def test_an_ipv6_address_the_editor_cannot_read_is_refused(typed):
    assert address_for_ipv6(typed) is None


@pytest.mark.parametrize('padding', INVISIBLE)
def test_a_stored_pair_survives_the_round_trip(padding):
    """The invariant issue #154 broke: address and netmask still pair up.

    This is the whole point of normalising in the editor.  Any pair the
    editor writes has to come back out of ``ip_network()``, because the
    compilers have no other way to tell a network from a single host.
    """
    address = address_for_ipv4(f'{padding}192.168.2.0{padding}')
    netmask = netmask_for_ipv4_address(f'{padding}255.0.0.0{padding}')
    assert ipaddress.ip_network(f'{address}/{netmask}', strict=False).prefixlen == 8


def _apply_changes_of_base_address_dialog():
    """The method body, read out of the source.

    ``address_dialogs`` cannot be imported: it pulls in the UI loader,
    which imports the dialogs back.  The source answers the question
    anyway, and the suite reads GUI source elsewhere for the same reason
    (see ``test_gui_widget_api.py``).
    """
    tree = ast.parse(ADDRESS_DIALOGS.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == '_BaseAddressDialog':
            for inner in node.body:
                if (
                    isinstance(inner, ast.FunctionDef)
                    and inner.name == '_apply_changes'
                ):
                    return inner
    pytest.fail('_BaseAddressDialog._apply_changes not found')
    return None


@pytest.mark.parametrize('field', ['address', 'netmask'])
def test_the_editor_reads_each_field_once(field):
    """Read twice is how the value that was validated stops being the one stored.

    ``_apply_changes`` used to read ``self.address.text()`` a second time
    to store it, next to the validated value it had already computed and
    then dropped.  Reading the field once and carrying that value to the
    end is what keeps the two from drifting apart again.
    """
    method = _apply_changes_of_base_address_dialog()
    reads = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == 'text'
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == field
    ]
    assert len(reads) == 1, (
        f'self.{field}.text() is read {len(reads)} times in _apply_changes; '
        f'store the validated value instead of reading the field again'
    )
