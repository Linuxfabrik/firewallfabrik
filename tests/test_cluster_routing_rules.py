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

"""A cluster's routes belong to its members.

``CompilerDriver::populateClusterElements`` merges all three kinds of
rule set into the member - policy, NAT *and* routing
(CompilerDriver.cpp:1095).  The port merged the first two, so a cluster
that keeps the routes its members share compiled into members with the
new packet filter and no route at all, and said nothing about it.  No
oracle could see it either: ``compare-reference.sh`` counts ``$IPTABLES``
lines and a route installs none.
"""

import pathlib
import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
    Interface,
    Routing,
    rule_elements,
)
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'

# The route heartbeat_cluster_1 keeps for both of its members, as the
# Firewall Builder reference writes it (`heartbeat_cluster_1_linux-1.fw.orig`).
CLUSTER_ROUTE = '172.24.1.0/24 via 172.24.0.100 dev eth0'


@pytest.fixture
def tree():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    return dm


def _ids(dm, cluster_name, member_name):
    with dm.session() as session:
        cluster = session.scalars(
            sqlalchemy.select(Cluster).where(Cluster.name == cluster_name),
        ).one()
        member = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == member_name),
        ).one()
        return str(cluster.id), str(member.id)


def _compile(dm, driver_cls, cluster_id, fw_id, tmp_path):
    driver = driver_cls(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'member.fw'
    driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'member.fw').read_text()


@pytest.mark.parametrize('driver_cls', [CompilerDriver_ipt, CompilerDriver_nft])
@pytest.mark.parametrize('member', ['linux-1', 'linux-2'])
def test_a_member_installs_the_routes_of_its_cluster(
    tree, tmp_path, driver_cls, member
):
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1', member)

    script = _compile(tree, driver_cls, cluster_id, fw_id, tmp_path)

    assert CLUSTER_ROUTE in script


def test_the_member_keeps_a_routing_rule_set_of_its_own(tree, tmp_path):
    """A rule set the member fills itself wins over the cluster's.

    ``mergeRuleSets`` replaces only an *empty* rule set of the same name;
    one the member filled is kept and the cluster's is passed over out
    loud (fwbuilder ticket #372).
    """
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1', 'linux-1')
    with tree.session() as session:
        cluster = session.scalars(
            sqlalchemy.select(Cluster).where(Cluster.name == 'heartbeat_cluster_1'),
        ).one()
        cluster_routing = session.scalars(
            sqlalchemy.select(Routing).where(Routing.device_id == cluster.id),
        ).one()
        own = session.scalars(
            sqlalchemy.select(Routing).where(
                Routing.device_id == uuid.UUID(fw_id),
                Routing.name == cluster_routing.name,
            ),
        ).one()
        assert not own.rules, 'the fixture is meant to start with an empty one'
        # Move the cluster's rules onto the member, so the member's own
        # rule set carries them and the cluster's has nothing to add.
        for rule in list(cluster_routing.rules):
            rule.rule_set = own

    driver = CompilerDriver_ipt(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'member.fw'
    driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')

    script = (tmp_path / 'member.fw').read_text()
    assert CLUSTER_ROUTE in script
    assert any(
        'ignoring cluster rule set' in warning for warning in driver.all_warnings
    ), driver.all_warnings


def test_an_interface_of_another_cluster_is_reported(tree, tmp_path):
    """`dev <name>` may only name a device the member actually has.

    ``rItfChildOfFw`` walks ``cluster->getMembersList()`` before it lets a
    cluster interface stand for the firewall's own.  Any cluster would do
    in the port, so a routing rule of one cluster naming another's
    interface compiled into a command for a device the box has not got -
    and since the routing rollback that stops the whole activation.
    """
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1', 'linux-1')
    with tree.session() as session:
        # `server-cluster-1` has members of its own and linux-1 is none of
        # them, so its interface names nothing on this box.
        stranger = session.scalars(
            sqlalchemy.select(Cluster).where(Cluster.name == 'server-cluster-1'),
        ).one()
        assert not any(
            member.id == uuid.UUID(fw_id) for member in stranger.get_members_list()
        )
        foreign = Interface(
            id=uuid.uuid4(),
            name='eth9',
            device=stranger,
            library=stranger.library,
        )
        session.add(foreign)
        session.flush()
        cluster_routing = session.scalars(
            sqlalchemy.select(Routing).where(
                Routing.device_id == uuid.UUID(cluster_id)
            ),
        ).one()
        rule = cluster_routing.rules[0]
        session.execute(
            rule_elements.update()
            .where(
                rule_elements.c.rule_id == rule.id,
                rule_elements.c.slot == 'ritf',
            )
            .values(target_id=foreign.id)
        )

    driver = CompilerDriver_ipt(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'member.fw'
    driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')

    script = (tmp_path / 'member.fw').read_text()
    assert 'dev eth9' not in script
    assert 'is not an interface of this firewall' in script
