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

"""The address check reads sub-interfaces as well.

A VLAN interface hangs under the interface it tags and carries an address
of its own; a bridge port hangs under the bridge.  ``fw.interfaces`` is
the top level alone, so a netmask of /0 one level down was waved through
- and the compilers answer that by matching every address, in a script
that loads without a word.  Firewall Builder reads the same list with
``getByTypeDeep(Interface::TYPENAME)`` (CompilerDriver.cpp:443).
"""

import uuid

from firewallfabrik.driver._compiler_driver import CompilerDriver


class _Address:
    def __init__(self, address, netmask):
        self._address = address
        self._netmask = netmask

    def get_address(self):
        return self._address

    def get_netmask(self):
        return self._netmask


class _Interface:
    def __init__(self, name, addresses=(), sub_interfaces=()):
        self.id = uuid.uuid4()
        self.name = name
        self.addresses = list(addresses)
        self.sub_interfaces = list(sub_interfaces)
        self.parent_interface = None
        for child in self.sub_interfaces:
            child.parent_interface = self

    def is_regular(self):
        return True

    def get_option(self, key, default=None):
        return default

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


def test_a_healthy_sub_interface_passes():
    eth0 = _Interface(
        'eth0',
        [_Address('192.0.2.1', '255.255.255.0')],
        [_Interface('eth0.100', [_Address('198.51.100.1', '255.255.255.0')])],
    )
    assert _check([eth0]) == ''


def test_a_netmask_of_zero_on_a_sub_interface_is_refused():
    eth0 = _Interface(
        'eth0',
        [_Address('192.0.2.1', '255.255.255.0')],
        [_Interface('eth0.100', [_Address('198.51.100.1', '0.0.0.0')])],  # nosec B104
    )
    said = _check([eth0])

    assert 'eth0.100' in said
    assert 'every address' in said


def test_a_zero_address_on_a_sub_interface_is_refused():
    br0 = _Interface(
        'br0',
        [_Address('192.0.2.1', '255.255.255.0')],
        [_Interface('eth1', [_Address('0.0.0.0', '255.255.255.0')])],  # nosec B104
    )
    said = _check([br0])

    assert 'eth1' in said


def test_a_sub_interface_two_levels_down_is_reached():
    """One level is all Firewall Builder allows, but the walk is a walk."""
    inner = _Interface('eth0.100.7', [_Address('198.51.100.1', '0.0.0.0')])  # nosec B104
    middle = _Interface('eth0.100', [_Address('203.0.113.1', '255.255.255.0')], [inner])
    eth0 = _Interface(
        'eth0',
        [_Address('192.0.2.1', '255.255.255.0')],
        [middle],
    )
    assert 'eth0.100.7' in _check([eth0])
