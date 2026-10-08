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

"""Where an interface may sit, against ``interfaceProperties::validateInterface``.

Firewall Builder asks it for every interface pasted, dragged or renamed
under a firewall, a cluster or another interface; fwf asked only
``Interface::validateChild``, the one-level rule, and so took a VLAN
named after another interface, an Ethernet sub-interface of an Ethernet
interface and a bridge port as a cluster interface.
"""

import uuid

import pytest

from firewallfabrik.core._validation import tree_child_refusal
from firewallfabrik.core.objects import Cluster, Firewall, Interface
from firewallfabrik.driver._interface_properties import LinuxInterfaceProperties

PROPS = LinuxInterfaceProperties()


def _iface(name, iface_type=None, **kw):
    return Interface(
        id=uuid.uuid4(),
        name=name,
        options={'type': iface_type} if iface_type else {},
        **kw,
    )


@pytest.mark.parametrize(
    ('name', 'parent', 'refused'),
    [
        ('eth0.100', _iface('eth0'), False),
        ('vlan100', _iface('eth0'), False),
        ('eth5.10', _iface('eth0'), True),
        ('eth0.5000', _iface('eth0'), True),
        ('eth1', _iface('eth0'), True),
        ('eth1', _iface('br0', 'bridge'), False),
        ('eth1', _iface('bond0', 'bonding'), False),
        ('eth5.10', _iface('br0', 'bridge'), False),
    ],
)
def test_a_sub_interface_name(name, parent, refused):
    assert bool(PROPS.interface_problem(parent, _iface(name))) is refused


def test_a_vlan_at_the_top_level_belongs_to_a_cluster_only():
    assert PROPS.interface_problem(Firewall(name='fw'), _iface('eth0.100'))
    assert PROPS.interface_problem(Cluster(name='cl'), _iface('eth0.100')) == ''


def test_a_bridge_port_does_not_go_into_a_cluster():
    bridge = _iface('br0', 'bridge')
    port = _iface('eth1', 'ethernet', parent_interface=bridge)
    assert 'bridge port' in PROPS.interface_problem(Cluster(name='cl'), port)


def test_a_name_with_a_space_is_refused_and_a_dash_is_not():
    assert PROPS.basic_name_problem('eth 0')
    assert PROPS.basic_name_problem('ppp-dsl') == ''


def test_the_tree_asks_the_interface_rules():
    assert tree_child_refusal(_iface('eth0'), _iface('eth1'))
    assert tree_child_refusal(_iface('br0', 'bridge'), _iface('eth1')) == ''
