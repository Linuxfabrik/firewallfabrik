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

"""Platform and host OS definitions with QSettings-backed enabled state."""

from PySide6.QtCore import QSettings

# Internal key → display name.
PLATFORMS = {'iptables': 'iptables', 'nftables': 'nftables'}
HOST_OS = {'linux24': 'Linux'}

# The releases a firewall can be compiled for, as (stored value, label).
#
# The compilers gate about fifteen matches and targets on the release the
# firewall names, and the empty value means "whatever the machine runs",
# which both read as the newest.  Without this list nothing could put a
# value there but a `.fwb` import, so a firewall created here always
# compiled for the newest release and an administrator with an older one
# had no way to say so.
#
# iptables: the list Firewall Builder offers, value for value
# (`getVersionsForPlatform`, libgui/platforms.cpp:418).  Two of its
# entries are not release numbers: "1.2.5 or earlier" is stored as
# `lt_1.2.6` and "1.2.6 to 1.2.8" as `ge_1.2.6`, which the comparison
# reads with `atoi` semantics as 0.2.6 - deliberately below every real
# release.
#
# nftables: the releases at which this compiler's output changes, derived
# from the netfilter nftables history.  `meta hour` / `meta day` /
# `meta time`, which a rule with a Time object compiles to, arrived in
# 0.9.3 (`NFT_META_TIME_HOUR`, 2019-08-29); `snat prefix to` and
# `dnat prefix to`, which a 1:1 network translation compiles to, in 0.9.5
# (`STMT_NAT_F_PREFIX`, 2020-04-24).  Everything else the compiler emits
# is 0.8.2 or older.  A release that is too old for a construct refuses
# the *whole* ruleset, so the firewall keeps the rules it had.
PLATFORM_VERSIONS = {
    'iptables': [
        ('', '- any -'),
        ('lt_1.2.6', '1.2.5 or earlier'),
        ('ge_1.2.6', '1.2.6 to 1.2.8'),
        ('1.2.9', '1.2.9 to 1.2.11'),
        ('1.3.0', '1.3.x'),
        ('1.4.0', '1.4.0 or later'),
        ('1.4.1.1', '1.4.1.1 or later'),
        ('1.4.3', '1.4.3'),
        ('1.4.4', '1.4.4 or later'),
        ('1.4.11', '1.4.11 or later'),
        ('1.4.20', '1.4.20 or later'),
    ],
    'nftables': [
        ('', '- any -'),
        ('0.9.0', '0.9.2 or earlier'),
        ('0.9.3', '0.9.3 or later'),
        ('0.9.5', '0.9.5 or later'),
    ],
}


def get_versions_for_platform(key):
    """Return the ``(value, label)`` releases offered for a platform."""
    return PLATFORM_VERSIONS.get(key, [])


def is_platform_enabled(key):
    """Return whether the given platform key is enabled (default True)."""
    return QSettings().value(f'Platforms/enabled_{key}', True, type=bool)


def set_platform_enabled(key, enabled):
    """Persist the enabled state for the given platform key."""
    QSettings().setValue(f'Platforms/enabled_{key}', enabled)


def get_enabled_platforms():
    """Return ``{key: display}`` for all enabled platforms."""
    return {k: v for k, v in PLATFORMS.items() if is_platform_enabled(k)}


def is_os_enabled(key):
    """Return whether the given host OS key is enabled (default True)."""
    return QSettings().value(f'Platforms/os_enabled_{key}', True, type=bool)


def set_os_enabled(key, enabled):
    """Persist the enabled state for the given host OS key."""
    QSettings().setValue(f'Platforms/os_enabled_{key}', enabled)


def get_enabled_os():
    """Return ``{key: display}`` for all enabled host OS entries."""
    return {k: v for k, v in HOST_OS.items() if is_os_enabled(k)}
