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

"""The names iptables refuses as a chain name because a target has them.

``assert_valid_chain_name`` (netfilter iptables/xshared.c) asks
``xtables_find_target(name, XTF_TRY_LOAD)`` and refuses the name when it
answers, so a rule set or branch named after a target produces a ``-N`` the
firewall rejects, and the activation stops there.

The compiler keeps the names in ``IPTABLES_TARGET_NAMES``. The two tests
here re-derive that list instead of trusting it: one from the extension
files of a netfilter iptables checkout (``FWF_IPTABLES_SOURCE``), one by
offering every name to the installed binaries. Both skip themselves when
what they need is missing.
"""

import os
import pathlib
import re
import shutil
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.iptables._utils import (
    IPTABLES_TARGET_NAMES,
    _chain_name_problem,
)

_SOURCE = os.environ.get('FWF_IPTABLES_SOURCE', '')

# The extension file that holds the shared parser of SNAT and DNAT and
# names no target of its own.
_NOT_A_TARGET = frozenset({'NAT'})

# The verdicts the standard target provides. They have no extension file,
# so the file sweep cannot find them.
_VERDICTS = frozenset({'ACCEPT', 'DROP', 'QUEUE', 'RETURN'})

_EXTENSION = re.compile(r'^lib(?:xt|ipt|ip6t)_([A-Z][A-Za-z0-9_]*)\.[a-z]+$')


def _names_from_source(repo: pathlib.Path) -> set[str]:
    extensions = repo / 'extensions'
    names = set()
    for path in extensions.iterdir():
        match = _EXTENSION.match(path.name)
        if match:
            names.add(match.group(1))
    return names


def _chain_name_refused(tool: str, name: str) -> bool:
    """Return whether *tool* refuses *name* as a chain name."""
    result = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', tool, '-N', name],
        capture_output=True,
        text=True,
        check=False,
    )
    return 'may not clash with target name' in result.stderr


def _namespace_works() -> bool:
    if not shutil.which('unshare') or not shutil.which('iptables'):
        return False
    return not _chain_name_refused('iptables', 'fwf_probe_chain')


def test_verdicts_are_listed():
    assert _VERDICTS <= IPTABLES_TARGET_NAMES


@pytest.mark.parametrize('name', ['SNAT', 'TEE', 'MASQUERADE', 'ACCEPT'])
def test_a_target_name_is_refused_as_a_chain_name(name):
    assert 'iptables target' in _chain_name_problem(name)


@pytest.mark.parametrize('name', ['mail_server', 'SecMark', 'branch1', 'Accept'])
def test_an_ordinary_name_is_accepted(name):
    assert _chain_name_problem(name) == ''


@pytest.mark.skipif(not _SOURCE, reason='set FWF_IPTABLES_SOURCE to a git clone')
def test_list_matches_the_netfilter_extensions():
    expected = (_names_from_source(pathlib.Path(_SOURCE)) - _NOT_A_TARGET) | _VERDICTS
    assert expected == IPTABLES_TARGET_NAMES


@pytest.mark.skipif(not _namespace_works(), reason='needs unshare -rn and iptables')
@pytest.mark.parametrize('name', sorted(IPTABLES_TARGET_NAMES))
def test_the_tools_refuse_every_listed_name(name):
    refused = _chain_name_refused('iptables', name)
    if not refused and shutil.which('ip6tables'):
        # Some targets exist for one family only: HL, DNPT and SNPT are
        # IPv6, TTL and ECN are IPv4. A dual-stack firewall creates its
        # chains in both rulesets, so either tool refusing the name is
        # enough to keep it out.
        refused = _chain_name_refused('ip6tables', name)
    assert refused, f'{name} is not a target name of the installed iptables'
