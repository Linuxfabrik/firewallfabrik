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

"""Interface name pattern recognition and autoconfiguration.

Ports fwbuilder's linux24Interfaces.cpp / interfaceProperties.cpp.
When enabled via Preferences > Interface > autoconfigure, this
module guesses the interface type and parameters from its name.
"""

import re

# VLAN patterns (Linux):
# eth0.100 -> base=eth0, vlan_id=100
# vlan100 -> base=vlan, vlan_id=100
_VLAN_DOT_RE = re.compile(r'^([a-zA-Z0-9-]+\d+)\.(\d+)$')
_VLAN_NAME_RE = re.compile(r'^vlan(\d+)$')

# Interface type patterns (by prefix, no dot):
_TYPE_PATTERNS = [
    (re.compile(r'^bond\d'), 'bonding'),
    (re.compile(r'^br\d'), 'bridge'),
    (re.compile(r'^en[opsx]\d'), 'ethernet'),  # systemd predictable names
    (re.compile(r'^eno\d'), 'ethernet'),
    (re.compile(r'^eth\d'), 'ethernet'),
    (re.compile(r'^ppp\d'), 'ethernet'),
    (re.compile(r'^tap\d'), 'ethernet'),
    (re.compile(r'^tun\d'), 'ethernet'),
    (re.compile(r'^wlan\d'), 'ethernet'),
    (re.compile(r'^wl\w'), 'ethernet'),  # systemd wlp2s0 etc.
]


def _parse_vlan(name: str) -> tuple[str, int] | None:
    """Extract (base_name, vlan_id) from a VLAN interface name.

    Returns ``None`` if *name* does not look like a VLAN interface.
    """
    m = _VLAN_DOT_RE.match(name)
    if m:
        vlan_id = int(m.group(2))
        if 0 <= vlan_id <= 4095:
            return m.group(1), vlan_id
    m = _VLAN_NAME_RE.match(name)
    if m:
        vlan_id = int(m.group(1))
        if 0 <= vlan_id <= 4095:
            return 'vlan', vlan_id
    return None


def guess_interface_type(name: str, parent_iface=None) -> dict:
    """Guess interface type and parameters from its name and parent.

    When *parent_iface* is given (an ``Interface`` ORM object), the
    function mirrors fwbuilder's ``guessSubInterfaceTypeAndAttributes``:

    * VLAN names (``eth0.100``) are only accepted when the base name
      matches the parent interface name.
    * Sub-interfaces of a bridge parent get ``type=ethernet``.
    * Sub-interfaces of a bonding parent get ``type=ethernet`` and
      the ``_set_unnumbered`` flag.

    Returns a dict with keys to merge into the interface's options dict.
    Returns empty dict if no pattern matches.
    """
    if not name:
        return {}

    # -- Sub-interface with known parent --
    if parent_iface is not None:
        parent_name = parent_iface.name or ''
        parent_type = (parent_iface.options or {}).get('type', '')

        vlan = _parse_vlan(name)
        if vlan is not None:
            base_name, vlan_id = vlan
            # "vlanNNN" style is always valid under any parent.
            # "parent.NNN" style must match the parent name.
            if base_name == 'vlan' or base_name == parent_name:
                return {'type': '8021q', 'vlan_id': str(vlan_id)}
            # Name looks like VLAN but does not match parent — warn.
            return {'_vlan_name_mismatch': parent_name}

        # Non-VLAN sub-interface under a bridge → ethernet.
        if parent_type == 'bridge':
            return {'type': 'ethernet'}

        # Non-VLAN sub-interface under bonding → ethernet + unnumbered.
        if parent_type == 'bonding':
            return {'type': 'ethernet', '_set_unnumbered': True}

        return {}

    # -- Top-level interface (no parent) --

    vlan = _parse_vlan(name)
    if vlan is not None:
        base_name, vlan_id = vlan
        if base_name != 'vlan':
            # "eth0.100" at top level → should be a sub-interface of "eth0".
            return {'_vlan_needs_parent': base_name}
        return {'type': '8021q', 'vlan_id': str(vlan_id)}

    if '.' not in name:
        for pattern, iface_type in _TYPE_PATTERNS:
            if pattern.match(name):
                return {'type': iface_type}

    return {}
