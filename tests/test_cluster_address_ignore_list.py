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

"""Which addresses the script is told to leave alone on a cluster member.

`update_addresses_of_interface` takes an ignore list, and it exists for
one thing: the address a failover group shares is put on and taken off by
keepalived, heartbeat or corosync, so the script must not touch it.

`interfaceProperties::manageIpAddresses` asks `isFailoverInterface()`
before it asks which protocol.  A cluster interface with no failover group
- a cluster's loopback, for one - therefore contributes nothing to the
list; without that question the member's own addresses of that name land
on it, and the script then never configures or corrects them.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Firewall
from firewallfabrik.driver._interface_properties import LinuxInterfaceProperties
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'


@pytest.fixture
def tree():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    return dm


def _ignore_lists(tree, cluster_name, member_name):
    with tree.session() as session:
        cluster_id = str(
            session.scalars(
                sqlalchemy.select(Cluster).where(Cluster.name == cluster_name),
            )
            .one()
            .id
        )
        fw_id = str(
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == member_name),
            )
            .one()
            .id
        )

    driver = CompilerDriver_ipt(tree)
    properties = LinuxInterfaceProperties()
    answers = {}
    with driver.compile_session() as session:
        cluster, fw = driver.get_firewall_and_cluster(session, cluster_id, fw_id)
        assert driver.populate_cluster_elements(session, cluster, fw) == ''
        for iface in fw.interfaces:
            if iface.cluster_interface:
                continue
            manage, _update, ignore = properties.manage_ip_addresses(iface)
            if manage:
                answers[iface.name] = ignore
    return answers


def test_the_loopback_of_a_cluster_ignores_nothing(tree):
    """vrrp_cluster_2 has a loopback with no failover group under it."""
    answers = _ignore_lists(tree, 'vrrp_cluster_2', 'linux-1')

    assert answers['lo'] == []


def test_a_shared_address_is_still_ignored(tree):
    """The interface that does run vrrp keeps the address off the script."""
    answers = _ignore_lists(tree, 'vrrp_cluster_1', 'linux-1')

    assert answers['eth0'] == ['172.24.0.1/16']
