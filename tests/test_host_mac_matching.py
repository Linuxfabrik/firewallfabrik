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

"""Where the "MAC address matching" checkbox of a host is kept.

Firewall Builder stores it as the host option ``use_mac_addr_filter``
(`HostDialog.cpp:161`) and the compilers read it from there
(`Compiler.cpp:485`, `ipt_utils.cpp:171`): a physAddress is taken into a
rule only when the host it belongs to says so.  The FirewallFabrik host
editor wrote ``mac_filter_enabled`` into the object's ``data`` instead -
a different key in a different column - so ticking the box in the editor
changed nothing at all: a host meant to be pinned to its MAC address was
compiled from its IP address alone, and a MAC-only host contributed
nothing and had its rule left out.  The same mismatch made the editor
show the box unticked for every host imported from a `.fwb`.

`Host.matches_by_mac` is the one answer both the editor and the
compilers go through.
"""

import uuid

import pytest

from firewallfabrik.compiler._combined_address import host_matches_by_mac
from firewallfabrik.core.objects import Host


def _host(options=None, data=None) -> Host:
    made = Host(id=uuid.uuid4(), name='workstation')
    made.options = options or {}
    made.data = data or {}
    return made


@pytest.mark.parametrize('stored', [True, 'True', 'true'])
def test_the_key_an_imported_file_carries(stored):
    """A `.fwb` writes the option out as the string "True"."""
    assert _host(options={'use_mac_addr_filter': stored}).matches_by_mac() is True


@pytest.mark.parametrize('stored', [False, 'False', 'false'])
def test_the_option_switched_off(stored):
    assert _host(options={'use_mac_addr_filter': stored}).matches_by_mac() is False


def test_a_host_that_was_never_asked():
    assert _host().matches_by_mac() is False


def test_the_key_an_older_release_of_the_editor_wrote_is_still_read():
    """A `.fwf` saved before the editor learnt the real key keeps its setting."""
    assert _host(data={'mac_filter_enabled': True}).matches_by_mac() is True


def test_the_option_wins_over_the_key_an_older_release_wrote():
    host = _host(
        options={'use_mac_addr_filter': False}, data={'mac_filter_enabled': True}
    )

    assert host.matches_by_mac() is False


def test_saving_writes_the_key_the_compilers_read():
    host = _host()

    host.set_matches_by_mac(True)

    assert host.options['use_mac_addr_filter'] is True
    assert host.matches_by_mac() is True


def test_saving_retires_the_key_an_older_release_wrote():
    """Leaving it behind would let the two answers drift apart again."""
    host = _host(data={'mac_filter_enabled': True})

    host.set_matches_by_mac(False)

    assert 'mac_filter_enabled' not in host.data
    assert host.matches_by_mac() is False


def test_the_compiler_asks_the_same_question():
    assert host_matches_by_mac(_host(options={'use_mac_addr_filter': True})) is True
    assert host_matches_by_mac(_host()) is False
    assert host_matches_by_mac(None) is False
