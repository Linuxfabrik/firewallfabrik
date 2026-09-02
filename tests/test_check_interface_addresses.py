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
    def __init__(
        self,
        name,
        addresses,
        regular=True,
        iface_id='iface-uuid-1',
        sub_interfaces=(),
    ):
        self.name = name
        self.id = iface_id
        self.addresses = addresses
        # The check walks the sub-interfaces too, the way
        # `getByTypeDeep(Interface::TYPENAME)` reads them: a VLAN
        # interface carries an address of its own.
        self.sub_interfaces = list(sub_interfaces)
        self.parent_interface = None
        for child in self.sub_interfaces:
            child.parent_interface = self
        self._regular = regular

    def get_option(self, key, default=None):
        return default

    def get_failover_group(self):
        return None

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
        assert err.startswith('Interface eth0 (id=id-eth0) has IP address 0.0.0.0.')
        assert 'mark it dynamic' in err, 'and says what to do about it'

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
        assert err.startswith(
            'Interface eth0 (id=id-eth0) has invalid netmask 0.0.0.0.'
        )

    def test_address_no_compiler_can_read_aborts(self):
        """Skipping it here is how it became a rule about something else.

        The check used to walk past a value ``ipaddress`` cannot read.
        The compilers do not: they write it into the script, where
        iptables stops the activation with every chain already at DROP
        and nftables refuses the whole ruleset.  Naming it before the
        script is written is the only place it costs nothing.
        """
        iface = _FakeInterface('eth0', [_FakeAddress('not-an-ip', '')])
        assert 'is not an address any compiler can read' in _check([iface])

    def test_netmask_no_compiler_can_read_aborts(self):
        """The silent half of the same gap, and the one issue #154 was.

        A netmask the print rules cannot read is left out by all of them,
        which matches the address alone - so a firewall interface stood
        for one host instead of for its network, in a script that loads
        without a word.
        """
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('192.0.2.1', '255.0.255.0')],
            iface_id='id-eth0',
        )
        err = _check([iface])
        assert 'is not a netmask' in err
        assert 'single address 192.0.2.1' in err

    def test_a_netmask_carrying_a_stray_space_still_compiles(self):
        """One reader takes every spelling, so this costs no rule.

        The value is what came out of the editors before this release.
        Reporting it would take out a rule whose netmask is perfectly
        clear; reading it is the answer, and only a value that means
        nothing at all is refused above.
        """
        iface = _FakeInterface('eth0', [_FakeAddress('192.0.2.1', '255.255.255.0 ')])
        assert _check([iface]) == ''

    def test_an_ipv6_netmask_is_read_as_a_length(self):
        """``NetworkIPv6::toXML`` writes the length, so /64 is not /0."""
        iface = _FakeInterface('eth0', [_FakeAddress('2001:db8::1', '64')])
        assert _check([iface]) == ''

    def test_an_ipv6_netmask_of_zero_aborts(self):
        """The /0 branch reaches IPv6 too now that the length is read."""
        iface = _FakeInterface(
            'eth0',
            [_FakeAddress('2001:db8::1', '0')],
            iface_id='id-eth0',
        )
        assert 'invalid netmask 0' in _check([iface])

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
        """A rule naming it compiles into an element that matches all.

        Firewall Builder refuses the firewall for it ("Missing IP address
        for interface"), and so does this: an error has to stop the
        compile rather than end in a script that quietly accepts
        everything.
        """
        iface = _FakeInterface('eth0', [])
        assert 'eth0' in _check([iface])

    def test_interface_with_empty_address_string(self):
        """An address child that carries no address is not an address."""
        iface = _FakeInterface('eth0', [_FakeAddress('', '')])
        assert 'eth0' in _check([iface])
