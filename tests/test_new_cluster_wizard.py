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

"""The New Cluster wizard builds a cluster that has members.

A cluster names its members nowhere directly: the failover groups under
its interfaces and its state sync group reference the member interfaces
(``Cluster::getMembersList``).  The wizard therefore has to create those
groups, the way ``newClusterDialog::createNewCluster`` does, or the
cluster compiles nothing ([#180]).  Taking over the rules of a member
points every reference to that member at the cluster, backs up each
member as ``<member>-bak`` and empties the members' rule sets.

[#180]: https://github.com/Linuxfabrik/firewallfabrik/issues/180
"""

import os
import uuid

import pytest
import sqlalchemy

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
    Library,
    PolicyRule,
    rule_elements,
)
from firewallfabrik.gui.object_tree_ops import TreeOperations

FIXTURE = 'tests/fixtures/cluster-tests.fwb'


def _database():
    dm = firewallfabrik.core.DatabaseManager()
    dm.load(FIXTURE)
    return dm


def _firewall(session, name):
    return session.scalars(
        sqlalchemy.select(Firewall).where(
            Firewall.type == 'Firewall', Firewall.name == name
        )
    ).one()


def _spec(session, copy_rules_from=None):
    members = [_firewall(session, 'linux-1'), _firewall(session, 'linux-2')]
    eth1 = [next(i for i in m.interfaces if i.name == 'eth1') for m in members]
    return {
        'copy_rules_from': copy_rules_from,
        'host_OS': 'linux24',
        'interfaces': [
            {
                'addresses': [
                    {'address': '192.0.2.1', 'ipv4': True, 'netmask': '255.255.255.255'}
                ],
                'comment': '',
                'label': 'inside',
                'members': [i.id for i in eth1],
                'name': 'eth1',
                'protocol': 'vrrp',
            }
        ],
        'members': [m.id for m in members],
        'name': 'wizcluster',
        'platform': 'iptables',
    }


def _create(dm, copy_from=None):
    with dm.session() as session:
        lib_id = (
            session.scalars(sqlalchemy.select(Library).where(Library.name == 'User'))
            .one()
            .id
        )
        source = _firewall(session, copy_from).id if copy_from else None
        spec = _spec(session, source)
    return TreeOperations(dm).create_cluster(lib_id, spec)


def test_cluster_gets_interfaces_groups_and_members():
    dm = _database()
    new_id = _create(dm)
    with dm.session() as session:
        cluster = session.get(Cluster, new_id)
        assert [m.name for m in cluster.get_members_list()] == ['linux-1', 'linux-2']
        (iface,) = cluster.interfaces
        assert iface.options == {'type': 'cluster_interface'}
        assert [a.name for a in iface.addresses] == ['wizcluster:eth1:ip']
        (group,) = iface.child_groups
        assert group.name == 'wizcluster:eth1:members'
        assert group.get_protocol() == 'vrrp'
        assert group.options['vrrp_vrid'] == '1'
        assert [(g.name, g.get_protocol()) for g in cluster.child_groups] == [
            ('conntrack', 'conntrack')
        ]
        assert sorted((rs.type, rs.top) for rs in cluster.rule_sets) == [
            ('NAT', True),
            ('Policy', True),
            ('Routing', True),
        ]


def test_taking_over_rules_points_them_at_the_cluster():
    dm = _database()
    with dm.session() as session:
        member = _firewall(session, 'linux-1')
        eth1 = next(i for i in member.interfaces if i.name == 'eth1')
        policy = next(rs for rs in member.rule_sets if rs.type == 'Policy')
        rule = PolicyRule(
            id=uuid.uuid4(), position=99, rule_set_id=policy.id, type='PolicyRule'
        )
        session.add(rule)
        session.flush()
        for slot, target in (('src', member.id), ('itf', eth1.id)):
            session.execute(
                rule_elements.insert().values(
                    position=0, rule_id=rule.id, slot=slot, target_id=target
                )
            )
        rule_count = sum(len(rs.rules) for rs in member.rule_sets)

    new_id = _create(dm, copy_from='linux-1')

    with dm.session() as session:
        cluster = session.get(Cluster, new_id)
        cluster_eth1 = cluster.interfaces[0]
        copied = [r for rs in cluster.rule_sets for r in rs.rules if r.position == 99]
        assert len(copied) == 1
        targets = dict(
            session.execute(
                sqlalchemy.select(
                    rule_elements.c.slot, rule_elements.c.target_id
                ).where(rule_elements.c.rule_id == copied[0].id)
            ).all()
        )
        assert targets == {'itf': cluster_eth1.id, 'src': cluster.id}

        for name in ('linux-1', 'linux-2'):
            member = _firewall(session, name)
            assert sorted(
                (rs.type, rs.top, len(rs.rules)) for rs in member.rule_sets
            ) == [
                ('NAT', True, 0),
                ('Policy', True, 0),
                ('Routing', True, 0),
            ]
            backup = _firewall(session, f'{name}-bak')
            assert backup.data['inactive'] is True
        backup = _firewall(session, 'linux-1-bak')
        assert sum(len(rs.rules) for rs in backup.rule_sets) == rule_count


def test_wizard_offers_only_interfaces_all_members_can_use():
    """Page 2 suggests a cluster interface per shared, eligible name."""
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    from firewallfabrik.gui.new_cluster_dialog import NewClusterDialog

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName('firewallfabrik-tests')
    QSettings().clear()

    dm = _database()
    with dm.session() as session:
        ids = [_firewall(session, n).id for n in ('linux-1', 'linux-2')]
    dialog = NewClusterDialog(dm, preselected_fw_ids=ids)
    dialog.obj_name.setText('wizcluster')
    dialog._on_next()
    assert dialog.stackedWidget.currentIndex() == 1
    names = [
        dialog.interfaceSelector.tabText(i)
        for i in range(dialog.interfaceSelector.count())
    ]
    # eth0 of linux-1 carries VLAN sub-interfaces, so the failover lives
    # on the VLANs and eth0 cannot be a cluster interface.
    assert 'eth0' not in names
    assert 'eth1' in names

    dialog._on_next()
    dialog._on_next()
    dialog._on_next()
    assert dialog.stackedWidget.currentIndex() == 4
    result = dialog.get_result()
    assert result['members'] == ids
    assert result['copy_rules_from'] is None
    assert {i['name'] for i in result['interfaces']} == set(names)
    dialog.reject()
