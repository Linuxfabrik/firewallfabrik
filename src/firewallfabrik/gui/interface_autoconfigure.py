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
    """Extract ``(base_name, vlan_id)`` from a VLAN interface name.

    ``linux24Interfaces::parseVlan``, with the VLAN id range of
    ``isValidVlanInterfaceName``: an id above 4095 is no VLAN to configure.
    """
    from firewallfabrik.driver._interface_properties import (
        LinuxInterfaceProperties,
    )

    parsed = LinuxInterfaceProperties().parse_vlan(name)
    if parsed is None or not 0 <= parsed[1] <= 4095:
        return None
    return parsed


def guess_interface_type(name: str, parent_iface=None) -> dict:
    """Guess interface type and parameters from its name and parent.

    With *parent_iface* (an ``Interface`` ORM object) this is
    ``interfaceProperties::guessSubInterfaceTypeAndAttributes``
    (interfaceProperties.cpp:467): a VLAN name that names its parent
    ("eth0.100" under "eth0", or "vlan100") makes a VLAN; anything else
    under a bridge is an Ethernet port, and under a bond an unnumbered
    Ethernet slave - a VLAN named after another interface under a bridge
    included.  Whether the name may sit there at all is the editor's
    ``validate``, which refuses it before this runs.

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
        if vlan is not None and vlan[0] in ('vlan', parent_name):
            return {'type': '8021q', 'vlan_id': str(vlan[1])}
        if parent_type == 'bridge':
            return {'type': 'ethernet'}
        if parent_type == 'bonding':
            return {'type': 'ethernet', '_set_unnumbered': True}
        return {}

    # -- Top-level interface (no parent) --

    # A top-level VLAN: "vlan100" anywhere, "eth0.100" on a cluster, which
    # may have top-level VLAN interfaces (interfaceProperties.cpp:355).
    vlan = _parse_vlan(name)
    if vlan is not None:
        return {'type': '8021q', 'vlan_id': str(vlan[1])}

    if '.' not in name:
        for pattern, iface_type in _TYPE_PATTERNS:
            if pattern.match(name):
                return {'type': iface_type}

    return {}
