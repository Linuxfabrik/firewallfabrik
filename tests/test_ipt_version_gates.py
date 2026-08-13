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

"""The release a match or target first shipped in, per address family.

Several iptables extensions started out IPv4-only and only reached
ip6tables later, either through a ``libip6t_`` file of their own or when
netfilter merged the two trees into ``libxt_``. The compiler keeps that in
``MATCH_FIRST_RELEASE`` and ``TARGET_FIRST_RELEASE`` so a firewall pinned
to an older release does not get a command its binary refuses.

The two ``*_matches_the_netfilter_history`` tests re-derive both tables
from the netfilter iptables checkout, so the numbers can be re-checked
rather than trusted. Point ``FWF_IPTABLES_SOURCE`` at a clone with tags to
run them; without the variable they are skipped.
"""

import os
import pathlib
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.iptables._utils import (
    MARK_MASK_FIRST_RELEASE,
    MATCH_ABSENT_BETWEEN,
    MATCH_FIRST_RELEASE,
    TARGET_FIRST_RELEASE,
)

# The extension file a match ships in, per family. Most of these never had
# a libip6t_ variant: the IPv6 side only arrived with the family-neutral
# libxt_ file, which is what makes the second column a real cut-off.
# hashlimit is the exception, it got a libip6t_ file of its own first.
_EXTENSION_FILES = {
    'connlimit': ('libipt_connlimit.c', 'libxt_connlimit.c'),
    'dscp': ('libipt_dscp.c', 'libxt_dscp.c'),
    'hashlimit': ('libipt_hashlimit.c', 'libip6t_hashlimit.c'),
    'iprange': ('libipt_iprange.c', 'libxt_iprange.c'),
    'set': ('libipt_set.c', 'libxt_set.c'),
    'time': ('libipt_time.c', 'libxt_time.c'),
    'tos': ('libipt_tos.c', 'libxt_tos.c'),
}

# The same for the targets. CLASSIFY reached ip6tables through the merged
# libxt_ file, CONNMARK through a libip6t_ file of its own, which is why
# the second column names different kinds of file.
_TARGET_FILES = {
    'CLASSIFY': ('libipt_CLASSIFY.c', 'libxt_CLASSIFY.c'),
    'CONNMARK': ('libipt_CONNMARK.c', 'libip6t_CONNMARK.c'),
}

_SOURCE = os.environ.get('FWF_IPTABLES_SOURCE', '')


def _releases(repo: pathlib.Path) -> list[str]:
    """Return every release tag of the checkout, oldest first."""
    tags = subprocess.run(  # nosec B603 B607
        ['git', '-C', str(repo), 'tag'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return sorted(
        (t for t in tags if t.startswith('v1.') and t[1:].replace('.', '').isdigit()),
        key=lambda t: [int(p) for p in t[1:].split('.')],
    )


def _offers_match(repo: pathlib.Path, tag: str, match: str, ipv6: bool) -> bool:
    """Report whether *tag* ships an extension registering *match* by name.

    Asking for the name rather than for the file is what makes the answer
    right for a match that was renamed: libipt_connlimit.c goes back to
    v1.2.1, but up to v1.2.8 the extension inside it registers itself as
    ``iplimit`` and spells its options ``--iplimit-*``.
    """
    files = subprocess.run(  # nosec B603 B607
        [
            'git',
            '-C',
            str(repo),
            'ls-tree',
            '-r',
            '--name-only',
            tag,
            '--',
            'extensions/',
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    prefix = 'libip6t_' if ipv6 else 'libipt_'
    candidates = [
        name
        for name in files
        if name.endswith(f'{match}.c')
        and (
            name.startswith(f'extensions/{prefix}')
            or name.startswith('extensions/libxt_')
        )
    ]
    for name in candidates:
        # Not text=True: an old extension file may carry a latin-1 author
        # name, which is not the compiler's problem.
        blob = subprocess.run(  # nosec B603 B607
            ['git', '-C', str(repo), 'show', f'{tag}:{name}'],
            capture_output=True,
            check=True,
        ).stdout
        if f'"{match}"'.encode() in blob:
            return True
    return False


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
    assert set(MATCH_FIRST_RELEASE) == set(_EXTENSION_FILES)


def test_ipv6_never_arrives_before_ipv4():
    for match, (v4, v6) in MATCH_FIRST_RELEASE.items():
        assert v4 <= v6, match


@pytest.mark.skipif(not _SOURCE, reason='set FWF_IPTABLES_SOURCE to a git clone')
@pytest.mark.parametrize('match', sorted(_EXTENSION_FILES))
def test_the_gate_names_the_release_the_match_first_shipped_in(match):
    """The gate has to follow the match, not the file it lives in."""
    repo = pathlib.Path(_SOURCE)
    releases = _releases(repo)
    for ipv6 in (False, True):
        offering = [tag for tag in releases if _offers_match(repo, tag, match, ipv6)]
        assert offering, f'{match} is in no release for ipv6={ipv6}'
        gate = MATCH_FIRST_RELEASE[match][ipv6]
        if gate != '0':
            # A gate of "0" stands for a match older than every target
            # Firewall Builder can express, so there is nothing to compare.
            assert gate == offering[0][1:], (
                f'{match} (ipv6={ipv6}) first ships in {offering[0]}'
            )
        # Every release from the first one on has to offer it, unless the
        # table says the match went away again for a while.
        gone, back = MATCH_ABSENT_BETWEEN.get(match, ('', ''))
        for tag in releases[releases.index(offering[0]) :]:
            absent = bool(gone) and gone <= tag[1:] < back
            assert _offers_match(repo, tag, match, ipv6) is not absent, (
                f'{match} (ipv6={ipv6}) at {tag} contradicts MATCH_ABSENT_BETWEEN'
            )


def test_target_table_covers_every_target_the_compiler_gates():
    assert set(TARGET_FIRST_RELEASE) == set(_TARGET_FILES)


@pytest.mark.skipif(not _SOURCE, reason='set FWF_IPTABLES_SOURCE to a git clone')
@pytest.mark.parametrize('target', sorted(_TARGET_FILES))
def test_target_first_release_matches_the_netfilter_history(target):
    repo = pathlib.Path(_SOURCE)
    ipv4_file, ipv6_file = _TARGET_FILES[target]
    assert TARGET_FIRST_RELEASE[target][0] == _first_release(repo, ipv4_file)
    assert TARGET_FIRST_RELEASE[target][1] == _first_release(repo, ipv6_file)


@pytest.mark.skipif(not _SOURCE, reason='set FWF_IPTABLES_SOURCE to a git clone')
@pytest.mark.parametrize('ipv6', [False, True], ids=['iptables', 'ip6tables'])
def test_the_masked_set_mark_gate_matches_the_netfilter_history(ipv6):
    """`--set-mark value/mask` is younger than the target that carries it.

    Revisions 0 and 1 read the argument as a plain number and answer a "/"
    with "Bad MARK value"; the revision that takes value/mask arrives with
    the family-neutral extensions/libxt_MARK.c, whose help text is the
    thing to grep for.  Both families cross over in the same release for
    that reason.
    """
    repo = pathlib.Path(_SOURCE)
    releases = _releases(repo)
    offering = []
    for tag in releases:
        files = subprocess.run(  # nosec B603 B607
            [
                'git',
                '-C',
                str(repo),
                'ls-tree',
                '-r',
                '--name-only',
                tag,
                '--',
                'extensions/',
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        prefix = 'libip6t_MARK.c' if ipv6 else 'libipt_MARK.c'
        candidates = [n for n in files if n.endswith(('libxt_MARK.c', prefix))]
        for name in candidates:
            blob = subprocess.run(  # nosec B603 B607
                ['git', '-C', str(repo), 'show', f'{tag}:{name}'],
                capture_output=True,
                check=True,
            ).stdout
            if b'set-mark value[/mask]' in blob:
                offering.append(tag)
                break

    assert offering, 'no release offers a masked --set-mark'
    assert MARK_MASK_FIRST_RELEASE[ipv6] == offering[0][1:], (
        f'a masked --set-mark first ships in {offering[0]}'
    )
