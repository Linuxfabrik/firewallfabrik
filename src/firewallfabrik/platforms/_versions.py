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

The stored value is the first release of the range, which keeps every
value Firewall Builder wrote readable (`1.4.0`, `lt_1.2.6`).  An empty
value is what an imported `.fwb` or an older data file carries; it is
compiled as the top entry and the compiler says so.

`tests/test_platform_versions.py` fails when a compiler gains a gate this
list has no row for.
"""

from __future__ import annotations

# (stored value, label), newest first.
VERSIONS: dict[str, list[tuple[str, str]]] = {
    # The gates are the version checks of the iptables compiler, and the
    # upper end of each range the last iptables release before the next
    # gate (netfilter iptables tags).  `lt_1.2.6` is Firewall Builder's
    # "1.2.5 or earlier", which the comparison reads as 0.2.6, below every
    # gate.
    'iptables': [
        ('1.6.2', '1.6.2+'),
        ('1.6.1', '1.6.1'),
        ('1.6.0', '1.6.0'),
        ('1.4.20', '1.4.20 to 1.4.21'),
        ('1.4.17', '1.4.17 to 1.4.19.1'),
        ('1.4.11', '1.4.11 to 1.4.16.3'),
        ('1.4.9', '1.4.9 to 1.4.10'),
        ('1.4.4', '1.4.4 to 1.4.8'),
        ('1.4.3', '1.4.3 to 1.4.3.2'),
        ('1.4.1.1', '1.4.1.1 to 1.4.2'),
        ('1.4.1', '1.4.1'),
        ('1.4.0', '1.4.0'),
        ('1.3.8', '1.3.8'),
        ('1.3.7', '1.3.7'),
        ('1.3.5', '1.3.5 to 1.3.6'),
        ('1.3.0', '1.3.0 to 1.3.4'),
        ('1.2.11', '1.2.11'),
        ('1.2.9', '1.2.9 to 1.2.10'),
        ('1.2.8', '1.2.8'),
        ('1.2.7', '1.2.7'),
        ('1.2.6', '1.2.6'),
        ('lt_1.2.6', '1.2.5 and earlier'),
    ],
    # The gates are the NFT_*_FIRST_RELEASE constants of the nftables
    # compiler (platforms/nftables/_utils.py).
    'nftables': [
        ('1.0.9', '1.0.9+'),
        ('1.0.0', '1.0.0 to 1.0.8'),
        ('0.9.9', '0.9.9'),
        ('0.9.5', '0.9.5 to 0.9.8'),
        ('0.9.3', '0.9.3 to 0.9.4'),
        ('0.9.2', '0.9.2'),
        ('0.9.1', '0.9.1'),
        ('0.9.0', '0.9.0'),
    ],
}

# Where each entry is the one to pick.  Only what was measured is named:
# the releases each distribution installs from its own repositories, and
# the corpus compiled for the entry loaded on it without a rejection -
# see "The Release a Firewall Is Compiled For" in
# docs/developer-guide/PlatformDefaults.md for the table and how it was
# taken.  RHEL covers its rebuilds (Rocky Linux was measured).
HINTS: dict[str, dict[str, str]] = {
    'iptables': {
        '1.6.2': (
            'Pick this on RHEL 8 up to 10, Debian 11 up to 13, Fedora 44,\n'
            'openSUSE Leap 15.5 and 16.0, Ubuntu 22.04 up to 26.04\n'
            '(all of them ship iptables 1.8). The RHEL kernels have no time\n'
            'match (xt_time), so a rule with a time window fails there.'
        ),
    },
    'nftables': {
        '1.0.9': (
            'Pick this on RHEL 9.4 up to 9.8, RHEL 10.0 up to 10.2, Debian 13,\n'
            'Fedora 44, openSUSE Leap 16.0, Ubuntu 24.04 and 26.04.'
        ),
        '1.0.0': 'Pick this on RHEL 9.1 up to 9.3, Debian 12, Ubuntu 22.04.',
        '0.9.5': 'Pick this on RHEL 9.0, Debian 11, openSUSE Leap 15.5.',
        '0.9.3': (
            'Not for RHEL 8, although it ships nftables 0.9.3: its kernel\n'
            'refuses what this entry writes. See 0.9.1 and 0.9.0.'
        ),
        '0.9.1': (
            'Pick this on RHEL 8.6 up to 8.10, whatever nftables it runs:\n'
            'its kernel cannot match the time of day or IP options.'
        ),
        '0.9.0': (
            'Pick this on RHEL 8.0 up to 8.5, whatever nftables it runs:\n'
            'its kernel cannot count connections or rate-limit per source.'
        ),
    },
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


def hint(platform: str, value: str) -> str:
    """Return where the *value* entry of *platform* is the one to pick."""
    return HINTS.get(platform, {}).get(value, '')


def unset_label(platform: str) -> str:
    """How the editor shows a firewall that names no release."""
    return f'not set: compiled for {newest(platform)[1]}'
