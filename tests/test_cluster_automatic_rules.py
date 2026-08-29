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

"""A cluster member permits its own failover and state sync traffic.

A firewall that drops by default drops the traffic that holds the cluster
together, and then both members consider themselves master and conntrackd
replicates nothing - so every failover drops the connections it was there
to preserve.  Firewall Builder writes those rules itself
(`AutomaticRules_ipt::addConntrackRule` / `addFailoverRules`); the class
that was supposed to port them was never instantiated, and built its
rules with empty source, destination and service, so wiring it up as it
stood would have permitted *everything* on the interface instead.

The addresses and ports come from Firewall Builder's host OS resource
file and agree with the tools: conntrackd's own sample configuration
names 225.0.0.50 and group 3780 and prints these very iptables rules
(`conntrack-tools/doc/sync/*/conntrackd.conf`), VRRP is IP protocol 112
to 224.0.0.18 (RFC 3768), heartbeat UDP 694 and OpenAIS UDP 5405.
"""

import pathlib
import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'


@pytest.fixture(scope='module')
def scripts():
    """Compile one member of every cluster of the fixture, once."""
    out = {}
    for cluster_name, member_name in (
        ('vrrp_cluster_1', 'linux-1'),
        ('heartbeat_cluster_1', 'linux-1'),
        ('heartbeat_cluster_2', 'linux-1'),
        ('openais_cluster_1', 'linux-1'),
    ):
        for driver_cls, platform in (
            (CompilerDriver_ipt, 'ipt'),
            (CompilerDriver_nft, 'nft'),
        ):
            dm = firewallfabrik.core.DatabaseManager('sqlite://')
            dm.load(str(FIXTURE))
            with dm.session() as session:
                cluster = session.scalars(
                    sqlalchemy.select(Cluster).where(Cluster.name == cluster_name),
                ).one()
                member = session.scalars(
                    sqlalchemy.select(Firewall).where(Firewall.name == member_name),
                ).one()
                cluster_id, fw_id = str(cluster.id), str(member.id)
            import tempfile

            with tempfile.TemporaryDirectory() as tmp:
                driver = driver_cls(dm)
                driver.wdir = tmp
                driver.source_dir = str(FIXTURE.parent)
                driver.file_name_setting = 'member.fw'
                driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')
                out[cluster_name, platform] = (
                    pathlib.Path(tmp) / 'member.fw'
                ).read_text()
    return out


def test_vrrp_is_permitted_by_protocol_and_group_address(scripts):
    ipt = scripts['vrrp_cluster_1', 'ipt']

    assert '-p 112  -d 224.0.0.18   -j ACCEPT' in ipt.replace('\t', ' ')
    assert 'VRRP (automatic)' in ipt


def test_vrrp_is_permitted_on_nftables_too(scripts):
    nft = scripts['vrrp_cluster_1', 'nft']

    assert 'ip daddr 224.0.0.18 meta l4proto 112 counter accept' in nft


def test_the_state_sync_link_is_permitted(scripts):
    for platform, needle in (
        ('ipt', '-d 225.0.0.50'),
        ('nft', 'ip daddr 225.0.0.50'),
    ):
        script = scripts['vrrp_cluster_1', platform]
        assert needle in script
        assert 'CONNTRACK (automatic)' in script
    # A group that overrides the port is followed, which is what the
    # option is there for.
    assert '--dport 3781' in scripts['heartbeat_cluster_1', 'ipt']


def test_a_unicast_state_sync_group_names_the_other_member(scripts):
    """There is no multicast group to name, so the rule names the peer.

    `heartbeat_cluster_2` has `conntrack_unicast` set, and the gold for it
    reads `-d 172.24.0.3` - the other member's interface on the sync link -
    instead of the multicast address.
    """
    ipt = scripts['heartbeat_cluster_2', 'ipt']

    assert '-d 172.24.0.3' in ipt
    assert '225.0.0.50' not in ipt


def test_heartbeat_uses_its_own_address_and_port(scripts):
    ipt = scripts['heartbeat_cluster_1', 'ipt']

    assert '-d 224.0.10.100' in ipt
    assert '--dport 694' in ipt
    assert 'heartbeat (automatic)' in ipt


def test_openais_uses_its_own_address_and_port(scripts):
    ipt = scripts['openais_cluster_1', 'ipt']

    assert '-d 226.94.1.1' in ipt
    assert '--dport 5405' in ipt
    assert 'openais (automatic)' in ipt


def test_the_rules_sit_in_front_of_the_policy(scripts):
    """`AutomaticRules::addMgmtRule` inserts them at the top, hidden.

    A negative position keeps them out of the numbering the editor shows
    and out of the shadowing check, and puts them ahead of any Deny the
    administrator wrote (fwbuilder ticket #16).
    """
    ipt = scripts['vrrp_cluster_1', 'ipt']

    positions = [
        int(line.split()[2])
        for line in ipt.splitlines()
        if '(automatic)' in line and line.strip().startswith('# Rule ')
    ]
    assert positions == sorted(positions)
    assert all(p < 0 for p in positions)


def test_a_firewall_outside_a_cluster_gets_none_of_them(tmp_path):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    with dm.session() as session:
        member = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == 'linux-1'),
        ).one()
        fw_id = str(member.id)
        assert uuid.UUID(fw_id)

    driver = CompilerDriver_ipt(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'alone.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')

    assert '(automatic)' not in (tmp_path / 'alone.fw').read_text()
