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

"""Tests for interface name autoconfiguration.

Ports the interface-detection parts of fwbuilder's compilerLibTest
(guessSubInterfaceTypeAndAttributes / validateInterface).
"""

from firewallfabrik.gui.interface_autoconfigure import guess_interface_type


class _FakeInterface:
    """Minimal interface stub for testing parent context."""

    def __init__(self, name, options=None):
        self.name = name
        self.options = options or {}


class TestGuessInterfaceTypeTopLevel:
    """Test type guessing for top-level interfaces (no parent)."""

    def test_ethernet(self):
        assert guess_interface_type('eth0') == {'type': 'ethernet'}

    def test_ethernet_systemd(self):
        assert guess_interface_type('ens192') == {'type': 'ethernet'}
        assert guess_interface_type('enp0s3') == {'type': 'ethernet'}

    def test_bonding(self):
        assert guess_interface_type('bond0') == {'type': 'bonding'}

    def test_bridge(self):
        assert guess_interface_type('br0') == {'type': 'bridge'}

    def test_vlan_named(self):
        assert guess_interface_type('vlan100') == {'type': '8021q', 'vlan_id': '100'}

    def test_vlan_dot_needs_parent(self):
        # eth0.100 at top level should warn about missing parent
        result = guess_interface_type('eth0.100')
        assert '_vlan_needs_parent' in result
        assert result['_vlan_needs_parent'] == 'eth0'

    def test_ppp(self):
        assert guess_interface_type('ppp0') == {'type': 'ethernet'}

    def test_tun(self):
        assert guess_interface_type('tun0') == {'type': 'ethernet'}

    def test_wlan(self):
        assert guess_interface_type('wlan0') == {'type': 'ethernet'}

    def test_unknown(self):
        assert guess_interface_type('xyz0') == {}

    def test_empty(self):
        assert guess_interface_type('') == {}

    def test_loopback(self):
        # lo doesn't match any pattern
        assert guess_interface_type('lo') == {}


class TestGuessInterfaceTypeWithParent:
    """Test type guessing for sub-interfaces with a parent."""

    def test_vlan_matching_parent(self):
        parent = _FakeInterface('eth0')
        result = guess_interface_type('eth0.100', parent)
        assert result == {'type': '8021q', 'vlan_id': '100'}

    def test_vlan_mismatched_parent(self):
        parent = _FakeInterface('ens192')
        result = guess_interface_type('eth0.100', parent)
        assert '_vlan_name_mismatch' in result
        assert result['_vlan_name_mismatch'] == 'ens192'

    def test_vlan_named_under_any_parent(self):
        parent = _FakeInterface('ens192')
        result = guess_interface_type('vlan100', parent)
        assert result == {'type': '8021q', 'vlan_id': '100'}

    def test_sub_interface_under_bridge(self):
        parent = _FakeInterface('br0', options={'type': 'bridge'})
        result = guess_interface_type('eth0', parent)
        assert result == {'type': 'ethernet'}

    def test_sub_interface_under_bonding(self):
        parent = _FakeInterface('bond0', options={'type': 'bonding'})
        result = guess_interface_type('eth0', parent)
        assert result == {'type': 'ethernet', '_set_unnumbered': True}

    def test_regular_sub_interface(self):
        parent = _FakeInterface('eth0', options={'type': 'ethernet'})
        result = guess_interface_type('eth0.subif', parent)
        assert result == {}

    def test_vlan_id_range(self):
        parent = _FakeInterface('eth0')
        # Valid VLAN IDs
        result = guess_interface_type('eth0.1', parent)
        assert result == {'type': '8021q', 'vlan_id': '1'}

        result = guess_interface_type('eth0.4094', parent)
        assert result == {'type': '8021q', 'vlan_id': '4094'}

    def test_vlan_id_out_of_range(self):
        parent = _FakeInterface('eth0')
        # 4096 is out of 802.1Q range (0-4095)
        result = guess_interface_type('eth0.5000', parent)
        # Should not match VLAN pattern
        assert '_vlan_name_mismatch' not in result or result == {}
