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

from firewallfabrik.platforms import _versions

# Internal key → display name.
PLATFORMS = {'iptables': 'iptables', 'nftables': 'nftables'}
HOST_OS = {'linux24': 'Linux'}

# The releases a firewall can be compiled for, newest first, and where each
# entry is the one to pick.  The list lives beside the compilers
# (platforms/_versions.py), which derive the release a firewall without one
# is compiled for from its top entry.
PLATFORM_VERSIONS = _versions.VERSIONS


def get_versions_for_platform(key):
    """Return the ``(value, label)`` releases offered for a platform."""
    return _versions.versions(key)


def get_unset_version_label(key):
    """How the combo shows a firewall that names no release."""
    return _versions.unset_label(key)


def get_newest_version(key):
    """The stored value of the top entry, which a new firewall starts with."""
    return _versions.newest(key)[0]


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
