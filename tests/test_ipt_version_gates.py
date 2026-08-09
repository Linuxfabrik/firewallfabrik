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

"""The release a match first shipped in, per address family.

Several iptables matches started out IPv4-only and only reached ip6tables
when netfilter merged the two extension trees into ``libxt_``. The compiler
keeps that in ``_MATCH_FIRST_RELEASE`` so a firewall pinned to an older
release does not get a command its binary refuses.

``test_first_release_matches_the_netfilter_history`` re-derives the table
from the netfilter iptables checkout, so the numbers can be re-checked
rather than trusted. Point ``FWF_IPTABLES_SOURCE`` at a clone with tags to
run it; without the variable it is skipped.
"""

import os
import pathlib
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.iptables._print_rule import _MATCH_FIRST_RELEASE

# The extension file a match ships in, per family. There never was a
# libip6t_ variant of any of them: the IPv6 side only arrived with the
# family-neutral libxt_ file.
_EXTENSION_FILES = {
    'tos': ('libipt_tos.c', 'libxt_tos.c'),
    'dscp': ('libipt_dscp.c', 'libxt_dscp.c'),
    'iprange': ('libipt_iprange.c', 'libxt_iprange.c'),
    'set': ('libipt_set.c', 'libxt_set.c'),
}

_SOURCE = os.environ.get('FWF_IPTABLES_SOURCE', '')


def _first_release(repo: pathlib.Path, extension: str) -> str:
    """Return the first release tag holding *extension*."""
    added = subprocess.run(  # nosec B603 B607
        [
            'git',
            '-C',
            str(repo),
            'log',
            '--all',
            '--format=%H',
            '--diff-filter=A',
            '--',
            f'extensions/{extension}',
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert added, f'{extension} was never added in {repo}'
    tags = subprocess.run(  # nosec B603 B607
        ['git', '-C', str(repo), 'tag', '--contains', added[-1]],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    releases = sorted(
        (t for t in tags if t.startswith('v1.') and t[1:].replace('.', '').isdigit()),
        key=lambda t: [int(p) for p in t[1:].split('.')],
    )
    assert releases, f'{extension} is in no release tag'
    return releases[0][1:]


def test_table_covers_every_match_the_compiler_gates():
    assert set(_MATCH_FIRST_RELEASE) == set(_EXTENSION_FILES)


def test_ipv6_never_arrives_before_ipv4():
    for match, (v4, v6) in _MATCH_FIRST_RELEASE.items():
        assert v4 <= v6, match


@pytest.mark.skipif(not _SOURCE, reason='set FWF_IPTABLES_SOURCE to a git clone')
@pytest.mark.parametrize('match', sorted(_EXTENSION_FILES))
def test_first_release_matches_the_netfilter_history(match):
    repo = pathlib.Path(_SOURCE)
    _ipv4_file, ipv6_file = _EXTENSION_FILES[match]
    expected_v6 = _first_release(repo, ipv6_file)
    assert _MATCH_FIRST_RELEASE[match][1] == expected_v6, (
        f'{match} reached ip6tables in {expected_v6}'
    )
    # The IPv4 column of `tos` predates the release tags the loop above can
    # sort, so it is only checked to be no later than the merged file.
    assert _MATCH_FIRST_RELEASE[match][0] <= expected_v6
