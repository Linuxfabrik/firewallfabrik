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

"""A bridge takes every sub-interface as a port.

``printBridgeInterfaceConfigurationCommands`` collects the ports with no
test on the interface type (``OSConfigurator_linux24_interfaces.cpp``).
Both ports of this one carried a filter for the type ``vlan``, a spelling
neither Firewall Builder nor this editor writes - both store ``8021q`` -
so it read as a guard and dropped nothing.  `update_bridge` removes every
port of the bridge the call does not name, so a filter that starts firing
takes a port off the bridge on every activation.
"""

import pytest

pytest.importorskip('PySide6', reason='the GUI extra is not installed')

from firewallfabrik.gui.iface_opts_dialog import (
    _DEVICE_TYPES as IFACE_TYPE_ITEMS,
)


def _bridge_block(platform, bridge_ports):
    """Render the bridge block of *platform* for one bridge."""
    module = __import__(
        f'firewallfabrik.platforms.{platform}._os_configurator',
        fromlist=['_os_configurator'],
    )
    cls = next(
        value
        for name, value in vars(module).items()
        if name.startswith('OSConfigurator_')
    )
    oscnf = cls.__new__(cls)
    oscnf.fw = _Firewall([_Interface('br0', 'bridge', bridge_ports)])
    return cls.print_bridge_interface_configuration_commands(oscnf)


class _Interface:
    def __init__(self, name, iface_type, sub_interfaces=()):
        self.name = name
        self.iface_type = iface_type
        self.sub_interfaces = list(sub_interfaces)

    def get_option(self, key, default=None):
        return self.iface_type if key == 'type' else default


class _Firewall:
    def __init__(self, interfaces):
        self.interfaces = list(interfaces)


def test_the_editor_spells_a_vlan_interface_8021q():
    """The token the dropped filter asked for was never written."""
    stored = {value for _label, value in IFACE_TYPE_ITEMS}
    assert '8021q' in stored
    assert 'vlan' not in stored


@pytest.mark.parametrize('platform', ('iptables', 'nftables'))
def test_a_vlan_sub_interface_stays_a_bridge_port(platform):
    ports = [_Interface('eth1', 'ethernet'), _Interface('eth1.100', '8021q')]
    block = _bridge_block(platform, ports)

    assert 'update_bridge br0 "eth1 eth1.100"' in block


@pytest.mark.parametrize('platform', ('iptables', 'nftables'))
def test_the_port_list_is_one_argument(platform):
    """`update_bridge` splits it again; quoting each port breaks it."""
    ports = [_Interface('eth2', 'ethernet'), _Interface('eth3', 'ethernet')]
    block = _bridge_block(platform, ports)

    assert 'update_bridge br0 "eth2 eth3"' in block
