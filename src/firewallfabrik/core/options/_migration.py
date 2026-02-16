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

"""Legacy key migration for backward compatibility.

This module handles migration from legacy option key names to canonical
keys. When loading .fwf files that were saved with older versions,
legacy keys are automatically mapped to their canonical equivalents.

The mapping is applied during file load and GUI population, ensuring
the compiler always sees canonical keys.
"""

from firewallfabrik.core.options._keys import LinuxOption

# Map legacy keys to canonical keys.
# Format: {'legacy_key': CanonicalKey}
#
# This handles the conntrack key mismatch where the GUI previously
# saved without the 'linux24_' prefix but the compiler expected it.
LEGACY_KEY_MAP: dict[str, str] = {
    # Conntrack settings - GUI previously saved without linux24_ prefix
    'conntrack_max': LinuxOption.CONNTRACK_MAX,
    'conntrack_hashsize': LinuxOption.CONNTRACK_HASHSIZE,
    'conntrack_tcp_be_liberal': LinuxOption.CONNTRACK_TCP_BE_LIBERAL,
}


def migrate_options(options: dict | None) -> dict:
    """Migrate legacy option keys to canonical keys.

    Args:
        options: The raw options dict from the database or file.

    Returns:
        A new dict with legacy keys replaced by canonical keys.
        Values are preserved; only keys are remapped.
    """
    if not options:
        return {}

    result = {}
    for key, value in options.items():
        canonical_key = LEGACY_KEY_MAP.get(key, key)
        # If both legacy and canonical exist, prefer canonical
        if canonical_key in result:
            continue
        result[canonical_key] = value

    return result


def get_canonical_key(key: str) -> str:
    """Get the canonical key for a possibly-legacy key.

    Args:
        key: The option key to look up.

    Returns:
        The canonical key if a mapping exists, otherwise the original key.
    """
    return LEGACY_KEY_MAP.get(key, key)
