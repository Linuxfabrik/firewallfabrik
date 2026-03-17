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


def guess_interface_type(name: str) -> dict:
    """Guess interface type and parameters from its name.

    Returns a dict with keys to merge into the interface's options dict:
    - 'type': interface type string (ethernet, bonding, bridge, 8021q)
    - 'vlan_id': VLAN ID (only for 8021q type)

    Returns empty dict if no pattern matches.
    """
    if not name:
        return {}

    # Check VLAN patterns first (they contain dots).
    m = _VLAN_DOT_RE.match(name)
    if m:
        vlan_id = int(m.group(2))
        if 0 <= vlan_id <= 4095:
            return {'type': '8021q', 'vlan_id': str(vlan_id)}

    m = _VLAN_NAME_RE.match(name)
    if m:
        vlan_id = int(m.group(1))
        if 0 <= vlan_id <= 4095:
            return {'type': '8021q', 'vlan_id': str(vlan_id)}

    # Check type patterns (no dot in name).
    if '.' not in name:
        for pattern, iface_type in _TYPE_PATTERNS:
            if pattern.match(name):
                return {'type': iface_type}

    return {}
