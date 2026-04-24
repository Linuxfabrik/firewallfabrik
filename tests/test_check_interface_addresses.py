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

"""Tests for CompilerDriver.check_interface_addresses().

Mirrors fwbuilder's CompilerDriver::processFirewallOrCluster sanity check
(CompilerDriver.cpp) which aborts the compile when a regular firewall
interface has IP address 0.0.0.0 / :: or netmask /0.
"""

from firewallfabrik.driver._compiler_driver import CompilerDriver


class _FakeAddress:
    def __init__(self, address, netmask=''):
        self._address = address
        self._netmask = netmask

    def get_address(self):
        return self._address

    def get_netmask(self):
        return self._netmask


class _FakeInterface:
    def __init__(self, name, addresses, regular=True, iface_id='iface-uuid-1'):
        self.name = name
        self.id = iface_id
        self.addresses = addresses
        self._regular = regular

    def is_regular(self):
        return self._regular


class _FakeFirewall:
    def __init__(self, interfaces):
        self.interfaces = interfaces


class _Driver(CompilerDriver):
    """Minimal subclass to access check_interface_addresses without a DB."""

    def __init__(self):
        # Skip CompilerDriver.__init__ which requires a DatabaseManager
        pass


def _check(interfaces):
    fw = _FakeFirewall(interfaces)
    return _Driver().check_interface_addresses(fw)


class TestRegularInterface:
    """Regular interfaces must have a real (non-zero) address."""

    def test_valid_ipv4(self):
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('192.0.2.1', '255.255.255.0')],
        )
        assert _check([iface]) == ''

    def test_valid_ipv6(self):
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('2001:db8::1', 'ffff:ffff:ffff:ffff::')],
        )
        assert _check([iface]) == ''

    def test_valid_with_no_netmask_field(self):
        # Plain IPv4 address objects have no netmask child.
        iface = _FakeInterface('eth0', [_FakeAddress('192.0.2.1')])
        assert _check([iface]) == ''

    def test_zero_ipv4_aborts(self):
        # Test fixture for the zero-address validator; not a real bind address.
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('0.0.0.0', '0.0.0.0')],  # nosec B104
            iface_id='id-eth0',
        )
        err = _check([iface])
        assert err == 'Interface eth0 (id=id-eth0) has IP address 0.0.0.0.'

    def test_zero_ipv6_aborts(self):
        iface = _FakeInterface('eth0', [_FakeAddress('::', '::')])
        err = _check([iface])
        assert 'has IP address ::' in err

    def test_zero_netmask_with_nonzero_address_aborts(self):
        # Test fixture for the zero-netmask validator; not a real bind address.
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('192.0.2.1', '0.0.0.0')],  # nosec B104
            iface_id='id-eth0',
        )
        err = _check([iface])
        assert err == 'Interface eth0 (id=id-eth0) has invalid netmask 0.0.0.0.'

    def test_invalid_address_string_is_ignored(self):
        # garbage in the address field (e.g. malformed import) should not
        # raise — the check just skips the entry.
        iface = _FakeInterface('eth0', [_FakeAddress('not-an-ip', '')])
        assert _check([iface]) == ''

    def test_first_bad_interface_wins(self):
        good = _FakeInterface(
            'eth0',
            [_FakeAddress('192.0.2.1', '255.255.255.0')],
        )
        # Test fixture for the zero-address validator; not a real bind address.
        bad = _FakeInterface(
            'eth1',
            [_FakeAddress('0.0.0.0', '0.0.0.0')],  # nosec B104
            iface_id='id-eth1',
        )
        err = _check([good, bad])
        assert 'eth1' in err and '0.0.0.0' in err  # nosec B104


class TestNonRegularInterface:
    """Dynamic / unnumbered / bridge-port interfaces are exempt."""

    def test_zero_on_non_regular_is_skipped(self):
        # Dynamic (or unnumbered, or bridge-port) interfaces only get
        # their address at runtime, so 0.0.0.0 is acceptable at compile.
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('0.0.0.0', '0.0.0.0')],  # nosec B104
            regular=False,
        )
        assert _check([iface]) == ''


class TestEmpty:
    """Edge cases: no interfaces, empty addresses."""

    def test_no_interfaces(self):
        assert _check([]) == ''

    def test_interface_with_no_addresses(self):
        iface = _FakeInterface('eth0', [])
        assert _check([iface]) == ''

    def test_interface_with_empty_address_string(self):
        iface = _FakeInterface('eth0', [_FakeAddress('', '')])
        assert _check([iface]) == ''
