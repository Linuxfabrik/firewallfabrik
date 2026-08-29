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

"""A cluster group keeps the object it belongs to.

A FailoverClusterGroup is a child of the cluster's Interface and a
StateSyncClusterGroup a child of the Cluster itself.  Both landed at the
library root on import, so nothing could answer which interface a
failover group belongs to - and that question is the whole of what the
group says.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Cluster,
    FailoverClusterGroup,
    StateSyncClusterGroup,
)

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'


def _load(path):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(path))
    return dm


def _cluster(session, name):
    return session.scalars(
        sqlalchemy.select(Cluster).where(Cluster.name == name),
    ).one()


@pytest.fixture(scope='module')
def imported():
    return _load(FIXTURE)


def test_failover_group_hangs_under_its_cluster_interface(imported):
    with imported.session() as session:
        cluster = _cluster(session, 'vrrp_cluster_1')
        eth0 = next(i for i in cluster.interfaces if i.name == 'eth0')

        group = eth0.get_failover_group()

        assert isinstance(group, FailoverClusterGroup)
        assert group.interface_id == eth0.id
        assert group.get_protocol() == 'vrrp'
        assert eth0.is_failover_interface()


def test_state_sync_group_hangs_under_its_cluster(imported):
    with imported.session() as session:
        cluster = _cluster(session, 'vrrp_cluster_1')

        groups = [
            g for g in cluster.child_groups if isinstance(g, StateSyncClusterGroup)
        ]

        assert [g.get_protocol() for g in groups] == ['conntrack']
        assert groups[0].device_id == cluster.id


def test_a_failover_group_names_the_interface_of_each_member(imported):
    with imported.session() as session:
        cluster = _cluster(session, 'vrrp_cluster_1')
        eth1 = next(i for i in cluster.interfaces if i.name == 'eth1')
        group = eth1.get_failover_group()

        members = cluster.get_members_list()

        assert [fw.name for fw in members] == ['linux-1', 'linux-2']
        for member in members:
            iface = group.get_interface_for_member(member)
            assert iface is not None
            assert iface.device_id == member.id


def test_a_cluster_interface_of_another_cluster_is_not_a_member(imported):
    with imported.session() as session:
        cluster = _cluster(session, 'vrrp_cluster_1')
        other = _cluster(session, 'vrrp_cluster_2')
        group = next(i for i in cluster.interfaces if i.name == 'eth0')

        assert group.get_failover_group().get_interface_for_member(other) is None


def test_the_parent_survives_a_yaml_round_trip(imported, tmp_path):
    saved = tmp_path / 'cluster.fwf'
    imported.save(str(saved))

    reloaded = _load(saved)
    with reloaded.session() as session:
        cluster = _cluster(session, 'vrrp_cluster_1')
        eth0 = next(i for i in cluster.interfaces if i.name == 'eth0')

        assert eth0.get_failover_group().get_protocol() == 'vrrp'
        assert [fw.name for fw in cluster.get_members_list()] == ['linux-1', 'linux-2']
        assert [
            g.get_protocol()
            for g in cluster.child_groups
            if isinstance(g, StateSyncClusterGroup)
        ] == ['conntrack']
