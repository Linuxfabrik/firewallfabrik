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

"""The releases a firewall can be compiled for, and where each one is right.

Both compilers gate what they write on the release the firewall names,
and one list per platform offers those releases in the editor.  Each entry
is one range of releases between two gates, newest first, so that one
entry is exactly right for a given machine: an entry below the machine's
release still loads there, but leaves out - and reports - every rule that
needs more, which on a Deny rule means the firewall lets through what it
should stop.  There is therefore no "or later" below the top entry and no
"any": the top entry is the one range that is open upwards.

The label names the distributions an entry is right for, in the label
itself, because a tooltip is too slow to wait for while picking.

The stored value is the first release of the range, which keeps every
value Firewall Builder wrote readable (`1.4.0`, `lt_1.2.6`).  An empty
value is what an imported `.fwb` or an older data file carries; it is
compiled as the top entry and the compiler says so.

`tests/test_platform_versions.py` fails when a compiler gains a gate this
list has no row for.
"""

from __future__ import annotations

import re

# (stored value, range of releases, distributions it is right for),
# newest first.  The list is read from the top: the first entry that names
# a distribution is the one for it, so "rhel8.0+" below "rhel8.6+" stands
# for 8.0 to 8.5, and "+" on the top entry for every later release.
# Only what was measured is named: the releases each
# distribution installs from its own repositories, and the corpus compiled
# for the entry loaded on it without a rejection - see "The Release a
# Firewall Is Compiled For" in docs/developer-guide/PlatformDefaults.md.
# RHEL covers its rebuilds (Rocky Linux was measured).
_ENTRIES: dict[str, list[tuple[str, str, str]]] = {
    # The gates are the version checks of the iptables compiler, and the
    # upper end of each range the last iptables release before the next
    # gate (netfilter iptables tags).  `lt_1.2.6` is Firewall Builder's
    # "1.2.5 or earlier", which the comparison reads as 0.2.6, below every
    # gate.
    'iptables': [
        (
            '1.6.2',
            '1.6.2+',
            'rhel8+ debian11+ leap15.5+ ubuntu22.04+',
        ),
        ('1.6.1', '1.6.1', ''),
        ('1.6.0', '1.6.0', ''),
        ('1.4.20', '1.4.[20-21]', ''),
        ('1.4.17', '1.4.17-1.4.19.1', ''),
        ('1.4.11', '1.4.11-1.4.16.3', ''),
        ('1.4.9', '1.4.[9-10]', ''),
        ('1.4.4', '1.4.[4-8]', ''),
        ('1.4.3', '1.4.3-1.4.3.2', ''),
        ('1.4.1.1', '1.4.1.1-1.4.2', ''),
        ('1.4.1', '1.4.1', ''),
        ('1.4.0', '1.4.0', ''),
        ('1.3.8', '1.3.8', ''),
        ('1.3.7', '1.3.7', ''),
        ('1.3.5', '1.3.[5-6]', ''),
        ('1.3.0', '1.3.[0-4]', ''),
        ('1.2.11', '1.2.11', ''),
        ('1.2.9', '1.2.[9-10]', ''),
        ('1.2.8', '1.2.8', ''),
        ('1.2.7', '1.2.7', ''),
        ('1.2.6', '1.2.6', ''),
        ('lt_1.2.6', '1.2.5 and earlier', ''),
    ],
    # The gates are the NFT_*_FIRST_RELEASE constants of the nftables
    # compiler (platforms/nftables/_utils.py).  RHEL 8 is placed by its
    # kernel, not by the nftables it ships (0.9.3, and 1.0.4 from 8.9).
    'nftables': [
        (
            '1.0.9',
            '1.0.9+',
            'rhel9.4+ debian13+ leap16.0+ ubuntu24.04+',
        ),
        ('1.0.0', '1.0.[0-8]', 'rhel9.1+ debian12 ubuntu22.04'),
        ('0.9.9', '0.9.9', ''),
        ('0.9.5', '0.9.[5-8]', 'rhel9.0 debian11 leap15.5'),
        ('0.9.3', '0.9.[3-4]', ''),
        ('0.9.2', '0.9.2', ''),
        ('0.9.1', '0.9.1', 'rhel8.6+'),
        ('0.9.0', '0.9.0', 'rhel8.0+'),
    ],
}

# (stored value, label), newest first.
VERSIONS: dict[str, list[tuple[str, str]]] = {
    platform: [
        (value, f'{rng} ({dists})' if dists else rng) for value, rng, dists in entries
    ]
    for platform, entries in _ENTRIES.items()
}


def versions(platform: str) -> list[tuple[str, str]]:
    """Return the ``(value, label)`` entries of *platform*, newest first."""
    return VERSIONS.get(platform, [])


def newest(platform: str) -> tuple[str, str]:
    """Return the top entry of *platform*, or ``('', '')`` for none."""
    entries = versions(platform)
    return entries[0] if entries else ('', '')


def label(platform: str, value: str) -> str:
    """Return the label of *value*, or the value itself if it has none."""
    return dict(versions(platform)).get(value, value)


def release_range(platform: str, value: str) -> str:
    """Return the range of releases of *value*, without the distributions."""
    for entry_value, rng, _dists in _ENTRIES.get(platform, []):
        if entry_value == value:
            return rng
    return value


def newest_range(platform: str) -> str:
    """The range of the top entry, "1.0.9+", without the distributions."""
    entries = _ENTRIES.get(platform, [])
    return entries[0][1] if entries else ''


def unset_label(platform: str) -> str:
    """How the editor shows a firewall that names no release."""
    entries = _ENTRIES.get(platform, [])
    return f'not set: compiled for {entries[0][1]}' if entries else 'not set'


def describe(platform: str, value: str, has_release: bool = True) -> str:
    """The platform and its release the way lists show them.

    "iptables 1.4.1", "nftables 1.0.[0-8]", "nftables (not set)"; a
    cluster has no release of its own (*has_release* False) and shows the
    platform alone.
    """
    if not platform:
        return ''
    if not has_release:
        return platform
    if not value:
        return f'{platform} (not set)'
    return f'{platform} {release_range(platform, value)}'


# The RHEL family as /etc/os-release names it.  RHEL 8 is the one place
# where the entry does not follow the nftables release: its kernel lacks
# what the release it ships can write (see the RHEL 8 comment above).
_RHEL_IDS = frozenset({'almalinux', 'centos', 'ol', 'rhel', 'rocky'})


# The RHEL 8 kernel build that brought the set element expressions (the
# "nf_tables: add elements with stateful expressions" series), and with it
# the 0.9.1 entry; RHEL 8.6 is the first point release to ship it.
_RHEL8_SET_EXPRESSIONS_BUILD = 359


def entry_for(
    platform: str, release: str, os_release: dict[str, str], kernel: str = ''
) -> str:
    """Return the entry that is right for a machine, '' if none fits.

    *release* is what `iptables --version` or `nft --version` printed,
    *os_release* the fields of /etc/os-release and *kernel* what `uname -r`
    printed.  The entry is the newest one whose first release is not newer
    than *release* - except on RHEL 8, which is placed by its kernel, as
    measured by loading the corpus on each: builds before 4.18.0-359
    (RHEL 8.0 to 8.5) take 0.9.0, later ones 0.9.1.  The kernel decides
    rather than the point release, because an early RHEL 8 rebuild names
    none (Rocky Linux 8.3 has `VERSION_ID="8"`); without a readable kernel
    the point release is used, and without that the later case.
    """
    from firewallfabrik.platforms.iptables._utils import version_compare

    if platform == 'nftables':
        ids = {os_release.get('ID', '')} | set(os_release.get('ID_LIKE', '').split())
        major, _, minor = os_release.get('VERSION_ID', '').partition('.')
        if ids & _RHEL_IDS and major == '8':
            build = re.match(r'4\.18\.0-(\d+)', kernel)
            if build:
                old = int(build.group(1)) < _RHEL8_SET_EXPRESSIONS_BUILD
            else:
                old = minor.isdigit() and int(minor) <= 5
            return '0.9.0' if old else '0.9.1'
    if not release:
        return ''
    for value, _label in versions(platform):
        if value.startswith('lt_') or version_compare(release, value) >= 0:
            return value
    return ''
