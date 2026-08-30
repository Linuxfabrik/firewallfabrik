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

"""A cluster interface inherits what describes the member's interface.

fwbuilder #971, in `CompilerDriver::populateClusterElements`: dynamic,
unnumbered, unprotected and the security level are written onto the
*cluster's* interface object, not only onto the copy the member gets,
because a rule of the cluster names the cluster's interface.

Without it a cluster whose external interface gets its address by DHCP
has an interface that is neither dynamic nor addressed, so every rule
translating to it is dropped as naming nothing - the entire NAT rule set
of `heartbeat_cluster_1_d`, where the reference output writes the
run-time `$i_eth0` instead.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

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


def test_the_cluster_interface_becomes_dynamic(tree):
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1_d', 'linux-1-d')
    driver = CompilerDriver_ipt(tree)

    with driver.compile_session() as session:
        cluster, fw = driver.get_firewall_and_cluster(session, cluster_id, fw_id)
        member_eth0 = next(i for i in fw.interfaces if i.name == 'eth0')
        cluster_eth0 = next(i for i in cluster.interfaces if i.name == 'eth0')
        assert member_eth0.is_dynamic()
        assert not cluster_eth0.is_dynamic()

        assert driver.populate_cluster_elements(session, cluster, fw) == ''

        assert cluster_eth0.is_dynamic()


def test_a_translation_to_it_reaches_the_script(tree, tmp_path):
    """It is written as the run-time variable, the way the reference has it."""
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1_d', 'linux-1-d')

    driver = CompilerDriver_ipt(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'member.fw'
    driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')

    script = (tmp_path / 'member.fw').read_text()
    assert '-j SNAT --to-source $i_eth0' in script
    assert '-j MASQUERADE' in script


def test_the_object_tree_keeps_its_own_answer(tree, tmp_path):
    """The flag is written in the compile session, which is rolled back."""
    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1_d', 'linux-1-d')

    driver = CompilerDriver_ipt(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'member.fw'
    driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')

    with tree.session() as session:
        cluster = session.scalars(
            sqlalchemy.select(Cluster).where(
                Cluster.name == 'heartbeat_cluster_1_d',
            ),
        ).one()
        eth0 = next(i for i in cluster.interfaces if i.name == 'eth0')
        assert not eth0.is_dynamic()


def test_both_platforms_keep_a_rule_naming_it(tree, tmp_path):
    """The dynamic-interface check exempts the cluster on both platforms.

    `checkForDynamicInterfacesOfOtherObjects` asks the failover group
    whether it names an interface of *this* member; if it does, the
    address is answerable after all.  The nftables policy pipeline had no
    such exemption, so twelve rules of the reference clusters were left
    out on one platform and compiled on the other.
    """
    from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

    cluster_id, fw_id = _ids(tree, 'heartbeat_cluster_1_d', 'linux-1-d')

    reported = {}
    for name, cls in (('ipt', CompilerDriver_ipt), ('nft', CompilerDriver_nft)):
        driver = cls(tree)
        driver.wdir = str(tmp_path)
        driver.source_dir = str(FIXTURE.parent)
        driver.file_name_setting = f'{name}.fw'
        driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')
        reported[name] = {
            error
            for error in driver.all_errors
            if 'dynamic interface' in error and 'heartbeat_cluster_1_d' in error
        }

    assert reported['nft'] == reported['ipt'] == set()
