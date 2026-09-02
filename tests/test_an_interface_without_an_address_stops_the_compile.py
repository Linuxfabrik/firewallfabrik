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

"""The "Missing IP address" abort of ``CompilerDriver::commonChecks2``.

An empty rule element is "any" everywhere in both compilers, so a rule
naming an interface that has no address is a rule for every address there
is - installed by a script that loads without a word. Firewall Builder
refuses the firewall instead, and `fwb_ipt` 5.3.7 answers
`tests/fixtures/cluster-tests.fwb` with "Missing IP address for interface
eth0.100" for exactly the firewall this compiler used to accept.
"""

import uuid

from firewallfabrik.driver._compiler_driver import CompilerDriver


class _Address:
    def __init__(self, address='192.0.2.1', netmask='255.255.255.0'):
        self._address = address
        self._netmask = netmask

    def get_address(self):
        return self._address

    def get_netmask(self):
        return self._netmask


class _Interface:
    def __init__(
        self,
        name,
        addresses=(),
        sub_interfaces=(),
        options=None,
        regular=True,
        parent=None,
    ):
        self.id = uuid.uuid4()
        self.name = name
        self.addresses = list(addresses)
        self.sub_interfaces = list(sub_interfaces)
        self.options = options or {}
        self.parent_interface = parent
        self._regular = regular
        for child in self.sub_interfaces:
            child.parent_interface = self

    def is_regular(self):
        return self._regular

    def get_option(self, key, default=None):
        return self.options.get(key, default)

    def get_failover_group(self):
        return None


class _Firewall:
    def __init__(self, interfaces):
        self.interfaces = list(interfaces)


class _Driver(CompilerDriver):
    def __init__(self):
        pass


def _check(interfaces):
    return _Driver().check_interface_addresses(_Firewall(interfaces))


def test_an_interface_with_an_address_passes():
    assert _check([_Interface('eth0', [_Address()])]) == ''


def test_an_interface_without_an_address_is_refused():
    said = _check([_Interface('eth0')])

    assert 'eth0' in said
    assert 'no IP address' in said


def test_a_sub_interface_without_an_address_is_refused():
    said = _check([_Interface('eth0', [_Address()], [_Interface('eth0.100')])])

    assert 'eth0.100' in said


def test_a_dynamic_interface_needs_no_address():
    """It gets one at boot time; `is_regular` is what says so."""
    assert _check([_Interface('ppp0', regular=False)]) == ''


def test_a_heartbeat_cluster_interface_needs_no_address():
    """`no_ip_ok` is True for heartbeat, openais and "none"."""
    iface = _Interface(
        'eth0',
        options={'cluster_interface': True, 'failover_protocol': 'heartbeat'},
    )
    assert _check([iface]) == ''


def test_a_vrrp_cluster_interface_needs_one():
    """`no_ip_ok` is False for vrrp: the address is the firewall's own."""
    iface = _Interface(
        'eth0',
        options={'cluster_interface': True, 'failover_protocol': 'vrrp'},
    )
    assert 'eth0' in _check([iface])
