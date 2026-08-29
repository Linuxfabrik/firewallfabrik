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

"""Compiling a member of a cluster.

A cluster is not a machine: it is what its members have in common, and
Firewall Builder compiles it by compiling each member with the cluster
named alongside (`CompilerDriver::compile`).  Before the member's own
rules are read, the cluster's interfaces and rule sets are copied into it
(`CompilerDriver::populateClusterElements`).  None of that was ported, so
a member compiled without any of the cluster's rules and a cluster
compiled as if it were a firewall of its own.
"""

import pathlib
import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Firewall, Interface, Policy
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'


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


def _compile(dm, driver_cls, cluster_id, fw_id, tmp_path, **kwargs):
    driver = driver_cls(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    for key, value in kwargs.items():
        setattr(driver, key, value)
    driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')
    return driver


@pytest.mark.parametrize(
    ('driver_cls', 'needle'),
    [(CompilerDriver_ipt, '224.0.0.18'), (CompilerDriver_nft, '224.0.0.18')],
)
def test_the_cluster_rules_are_compiled_into_the_member(
    tree, tmp_path, driver_cls, needle
):
    cluster_id, fw_id = _ids(tree, 'vrrp_cluster_1', 'linux-1')

    driver = _compile(
        tree, driver_cls, cluster_id, fw_id, tmp_path, file_name_setting='member.fw'
    )

    script = (tmp_path / 'member.fw').read_text()
    # Rule 0 of the cluster's policy permits VRRP to the multicast group;
    # the member has no rule of its own that mentions it.
    assert needle in script
    assert driver.cluster is not None


def test_the_member_gets_the_address_the_cluster_shares(tree, tmp_path):
    cluster_id, fw_id = _ids(tree, 'vrrp_cluster_1', 'linux-1')

    _compile(
        tree,
        CompilerDriver_ipt,
        cluster_id,
        fw_id,
        tmp_path,
        file_name_setting='member.fw',
    )

    script = (tmp_path / 'member.fw').read_text()
    # 172.24.0.1 is the cluster's address on eth0, 172.24.0.2 the
    # member's own.  The anti-spoofing rule of the cluster names the
    # cluster object and has to cover both.
    assert '172.24.0.1' in script
    assert '172.24.0.2' in script


def test_the_compile_leaves_the_object_tree_alone(tree, tmp_path):
    cluster_id, fw_id = _ids(tree, 'vrrp_cluster_1', 'linux-1')
    with tree.session() as session:
        before = sorted(
            i.name
            for i in session.scalars(
                sqlalchemy.select(Interface).where(
                    Interface.device_id == uuid.UUID(fw_id)
                ),
            ).all()
        )

    _compile(
        tree,
        CompilerDriver_ipt,
        cluster_id,
        fw_id,
        tmp_path,
        file_name_setting='member.fw',
    )

    with tree.session() as session:
        after = sorted(
            i.name
            for i in session.scalars(
                sqlalchemy.select(Interface).where(
                    Interface.device_id == uuid.UUID(fw_id)
                ),
            ).all()
        )
    assert after == before


def test_the_output_file_carries_the_cluster_name(tree, tmp_path):
    cluster_id, fw_id = _ids(tree, 'vrrp_cluster_1', 'linux-1')

    _compile(
        tree,
        CompilerDriver_ipt,
        cluster_id,
        fw_id,
        tmp_path,
        prepend_cluster_name=True,
    )

    assert (tmp_path / 'vrrp_cluster_1_linux-1.fw').exists()


def test_a_cluster_with_no_interfaces_is_refused(tree, tmp_path):
    cluster_id, fw_id = _ids(tree, 'vrrp_cluster_1', 'linux-1')
    with tree.session() as session:
        cluster = session.get(Cluster, uuid.UUID(cluster_id))
        for iface in list(cluster.interfaces):
            session.delete(iface)

    driver = _compile(tree, CompilerDriver_ipt, cluster_id, fw_id, tmp_path)

    assert any('no interfaces' in err for err in driver.all_errors)


def test_a_state_sync_group_of_another_platform_is_refused(tree, tmp_path):
    """A `.fwb` written for PF carries `pfsync`, which Linux cannot speak."""
    cluster_id, fw_id = _ids(tree, 'vrrp_cluster_1', 'linux-1')
    with tree.session() as session:
        cluster = session.get(Cluster, uuid.UUID(cluster_id))
        group = cluster.child_groups[0]
        group.data = {**(group.data or {}), 'type': 'pfsync'}

    driver = _compile(tree, CompilerDriver_ipt, cluster_id, fw_id, tmp_path)

    assert any('pfsync' in err for err in driver.all_errors)


def test_the_member_keeps_a_rule_set_of_its_own_with_the_same_name(tree, tmp_path):
    """fwbuilder ticket #372: the member's own rule set wins, and it says so."""
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1', 'linux-1')
    with tree.session() as session:
        cluster = session.get(Cluster, uuid.UUID(cluster_id))
        member = session.get(Firewall, uuid.UUID(fw_id))
        cluster_policy = next(
            rs for rs in cluster.rule_sets if isinstance(rs, Policy) and rs.top
        )
        member_policy = next(
            rs for rs in member.rule_sets if isinstance(rs, Policy) and rs.top
        )
        member_policy.name = cluster_policy.name

    driver = _compile(tree, CompilerDriver_ipt, cluster_id, fw_id, tmp_path)

    assert any(
        'ignoring cluster rule set' in warning for warning in driver.all_warnings
    )
