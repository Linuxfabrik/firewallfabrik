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

"""Platform and OS defaults loader.

Loads, caches, and provides typed access to platform/OS option
definitions from ``defaults.yaml`` files co-located with each
platform package.

Each YAML file defines an ``options:`` mapping where every key is
a canonical option name and its value is a dict with at least
``type``, ``default``, and ``description``.

Example usage::

    from firewallfabrik.platforms._defaults import (
        get_default_values,
        get_platform_defaults,
    )

    schema = get_platform_defaults('iptables')
    seed   = get_default_values('iptables')
"""

import functools
import importlib.resources
import logging
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_SENTINEL = object()

# Map host_OS values (as stored in the database) to the Python package
# directory that contains the corresponding ``defaults.yaml``.
_OS_PACKAGE_MAP: dict[str, str] = {
    'linux24': 'linux',
}


@functools.cache
def _load_yaml(package_path: str) -> dict:
    """Load and cache a ``defaults.yaml`` from a platform package."""
    ref = importlib.resources.files(package_path) / 'defaults.yaml'
    text = ref.read_text(encoding='utf-8')
    return yaml.safe_load(text) or {}


def get_platform_defaults(platform: str) -> dict[str, dict]:
    """Return the full options schema for a compiler platform.

    Returns ``{option_key: {type, default, supported, description, …}}``.
    """
    pkg = f'firewallfabrik.platforms.{platform}'
    return _load_yaml(pkg).get('options', {})


def get_os_defaults(os_name: str) -> dict[str, dict]:
    """Return the full options schema for a host OS.

    *os_name* is the value stored in ``host.data['host_OS']``
    (e.g. ``'linux24'``).
    """
    pkg_name = _OS_PACKAGE_MAP.get(os_name, os_name)
    pkg = f'firewallfabrik.platforms.{pkg_name}'
    return _load_yaml(pkg).get('options', {})


def get_default_values(platform: str) -> dict[str, Any]:
    """Return ``{key: default_value}`` for seeding new firewall objects.

    Only includes options where ``supported`` is ``true`` (or absent).
    """
    schema = get_platform_defaults(platform)
    return {
        k: v['default']
        for k, v in schema.items()
        if v.get('supported', True)
    }


def get_os_default_values(os_name: str) -> dict[str, Any]:
    """Return ``{key: default_value}`` for OS-level options."""
    schema = get_os_defaults(os_name)
    return {
        k: v['default']
        for k, v in schema.items()
        if v.get('supported', True)
    }


def get_option_default(
    platform: str,
    os_name: str,
    key: str,
    fallback: Any = _SENTINEL,
) -> Any:
    """Look up a single option's default, checking platform then OS.

    Returns *fallback* (or raises ``KeyError``) if the key is unknown
    in both schemas.
    """
    entry = get_platform_defaults(platform).get(key)
    if entry is not None:
        return entry['default']
    entry = get_os_defaults(os_name).get(key)
    if entry is not None:
        return entry['default']
    if fallback is not _SENTINEL:
        return fallback
    msg = f'Unknown option key {key!r} for platform={platform!r}, os={os_name!r}'
    raise KeyError(msg)


def get_known_keys(platform: str, os_name: str = '') -> set[str]:
    """Return all known option keys for a platform + OS combination."""
    keys = set(get_platform_defaults(platform))
    if os_name:
        keys |= set(get_os_defaults(os_name))
    return keys


def validate_options(
    platform: str,
    os_name: str,
    options: dict,
) -> list[str]:
    """Return warnings for unknown keys in an options dict."""
    known = get_known_keys(platform, os_name)
    unknown = sorted(set(options) - known)
    return [
        f'Unknown option key {k!r} for platform={platform!r}, os={os_name!r}'
        for k in unknown
    ]
