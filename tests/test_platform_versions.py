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

"""Every release a compiler gates on has its own entry in the editor's list.

Each entry is one range of releases between two gates, so that exactly one
entry is right for a machine.  A gate without an entry merges two ranges
that compile differently: an administrator on the newer half, picking the
entry, loses what that half can do - and on nftables the rules behind it,
which are reported and left out.  This fails as soon as a compiler learns
a gate the list has not.
"""

import pathlib
import re

import pytest

from firewallfabrik.platforms import _versions
from firewallfabrik.platforms.iptables import _nat_print_rule as ipt_nat_print_rule
from firewallfabrik.platforms.iptables import _print_rule as ipt_print_rule
from firewallfabrik.platforms.iptables import _utils as ipt_utils
from firewallfabrik.platforms.nftables import _utils as nft_utils

SRC = pathlib.Path(__file__).resolve().parents[1] / 'src' / 'firewallfabrik'
RELEASE = re.compile(r'\d+(\.\d+)+')


def _values(platform):
    return {value for value, _label in _versions.versions(platform)}


def _nftables_gates():
    return {
        value
        for name, value in vars(nft_utils).items()
        if name.startswith('NFT_') and name.endswith('_FIRST_RELEASE')
    }


def _iptables_gates():
    """The first releases the iptables compiler asks for.

    A `*_LAST_RELEASE` names the release *before* a gate, and the entry
    for the release after it is written by hand ("1.3.8"), so those are
    left out here; the `0` of a match every release has is no gate.
    """
    gates = set()

    def add(value):
        if isinstance(value, str) and RELEASE.fullmatch(value):
            gates.add(value)

    for module in (ipt_utils, ipt_print_rule, ipt_nat_print_rule):
        for name, value in vars(module).items():
            if not name.isupper() or name.endswith('_LAST_RELEASE'):
                continue
            if name.startswith('DEFAULT_') or name.startswith('XT_'):
                continue
            if isinstance(value, dict):
                for item in value.values():
                    for release in item if isinstance(item, tuple) else (item,):
                        add(release)
            elif isinstance(value, tuple):
                for release in value:
                    add(release)
            elif name.endswith(('_SINCE', '_FIRST_RELEASE')):
                add(value)
    for path in (SRC / 'platforms' / 'iptables').glob('*.py'):
        text = path.read_text()
        for match in re.finditer(r"version_compare\([^,()]+,\s*'([\d.]+)'\)", text):
            add(match.group(1))
        for match in re.finditer(
            r"first_release = '([\d.]+)' if .* else '([\d.]+)'", text
        ):
            add(match.group(1))
            add(match.group(2))
    return gates


@pytest.mark.parametrize(
    ('platform', 'gates'),
    [('nftables', _nftables_gates()), ('iptables', _iptables_gates())],
    ids=['nftables', 'iptables'],
)
def test_every_gate_starts_an_entry(platform, gates):
    assert gates
    missing = sorted(gates - _values(platform))
    assert not missing, f'{platform} gates without an entry: {missing}'


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_a_firewall_naming_no_release_is_compiled_for_the_top_entry(platform):
    default = (
        ipt_utils.DEFAULT_IPTABLES_VERSION
        if platform == 'iptables'
        else nft_utils.DEFAULT_NFTABLES_VERSION
    )
    assert default == _versions.newest(platform)[0]


def test_a_label_names_the_range_and_where_it_is_right():
    """No tooltip to wait for: the distributions are in the label."""
    assert _versions.label('nftables', '0.9.5') == (
        '0.9.[5-8] (rhel9.0 debian11 leap15.5)'
    )
    assert _versions.label('nftables', '0.9.9') == '0.9.9'
    assert _versions.describe('nftables', '0.9.5') == 'nftables 0.9.[5-8]'
    assert _versions.describe('nftables', '') == 'nftables (not set)'
    assert _versions.describe('iptables', '', has_release=False) == 'iptables'
