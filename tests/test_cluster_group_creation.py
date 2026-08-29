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

"""Where a cluster group lands when the editor creates one.

A failover group belongs to the cluster interface it fails over, and a
state sync group to the cluster.  Which parent a group has is the whole
of what it says: two clusters both have a group called "members", and a
compiler that cannot tell them apart has no rules to write.

Before this, "New Failover Group" was not offered at all and "New State
Sync Group" created an object with no link to anything, which the writer
then put beside the firewalls in the data file ([#78]).

[#78]: https://github.com/Linuxfabrik/firewallfabrik/issues/78
"""

import uuid

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Cluster,
    FWObjectDatabase,
    Group,
    Interface,
    Library,
)
from firewallfabrik.gui.object_tree_data import DEFAULT_CLUSTER_GROUP_PROTOCOL
from firewallfabrik.gui.object_tree_ops import TreeOperations


def _cluster_with_interface():
    """A database holding one library, one cluster and one interface."""
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        session.flush()
        cluster = Cluster(
            id=uuid.uuid4(),
            type='Cluster',
            name='cluster1',
            library_id=library.id,
        )
        session.add(cluster)
        session.flush()
        iface = Interface(
            id=uuid.uuid4(),
            name='eth0',
            device_id=cluster.id,
        )
        session.add(iface)
        session.commit()
        return dm, library.id, cluster.id, iface.id


def test_a_failover_group_is_created_under_its_interface():
    dm, lib_id, _cluster_id, iface_id = _cluster_with_interface()
    ops = TreeOperations(dm)

    new_id = ops.create_new_object(
        Group,
        'FailoverClusterGroup',
        lib_id,
        interface_id=iface_id,
        name='cluster1:eth0:members',
        extra_data={'type': DEFAULT_CLUSTER_GROUP_PROTOCOL['FailoverClusterGroup']},
    )

    with dm.session() as session:
        group = session.get(Group, new_id)
        assert group.interface_id == iface_id
        assert group.device_id is None
        assert group.library_id == lib_id
        assert (group.data or {}).get('type') == 'vrrp'


def test_a_state_sync_group_is_created_under_its_cluster():
    dm, lib_id, cluster_id, _iface_id = _cluster_with_interface()
    ops = TreeOperations(dm)

    new_id = ops.create_new_object(
        Group,
        'StateSyncClusterGroup',
        lib_id,
        device_id=cluster_id,
        name='cluster1:members',
        extra_data={'type': DEFAULT_CLUSTER_GROUP_PROTOCOL['StateSyncClusterGroup']},
    )

    with dm.session() as session:
        group = session.get(Group, new_id)
        assert group.device_id == cluster_id
        assert group.interface_id is None
        assert group.library_id == lib_id
        assert (group.data or {}).get('type') == 'conntrack'


def test_a_group_created_that_way_is_not_written_beside_the_firewalls(tmp_path):
    """The writer nests it, which is what #78 was about."""
    dm, lib_id, cluster_id, iface_id = _cluster_with_interface()
    ops = TreeOperations(dm)
    ops.create_new_object(
        Group,
        'FailoverClusterGroup',
        lib_id,
        interface_id=iface_id,
        name='cluster1:eth0:members',
        extra_data={'type': 'vrrp'},
    )
    ops.create_new_object(
        Group,
        'StateSyncClusterGroup',
        lib_id,
        device_id=cluster_id,
        name='cluster1:members',
        extra_data={'type': 'conntrack'},
    )

    out = tmp_path / 'cluster.fwf'
    dm.save(str(out))
    text = out.read_text()

    # Both group names appear exactly once, indented deeper than the
    # cluster they belong to.
    for name in ("'cluster1:eth0:members'", "'cluster1:members'"):
        assert text.count(name) == 1, text
    cluster_indent = min(
        len(line) - len(line.lstrip())
        for line in text.splitlines()
        if "name: 'cluster1'" in line
    )
    for name in ("'cluster1:eth0:members'", "'cluster1:members'"):
        line = next(line for line in text.splitlines() if name in line)
        assert len(line) - len(line.lstrip()) > cluster_indent, line


def _tree_item(parent_type, child_types=()):
    """A tree item under a *parent_type* node, with *child_types* below it."""
    import os

    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem

    QApplication.instance() or QApplication([])
    tree = QTreeWidget()
    parent = QTreeWidgetItem(tree)
    parent.setData(0, Qt.ItemDataRole.UserRole + 1, parent_type)
    item = QTreeWidgetItem(parent)
    item.setData(0, Qt.ItemDataRole.UserRole + 1, 'Interface')
    for child_type in child_types:
        child = QTreeWidgetItem(item)
        child.setData(0, Qt.ItemDataRole.UserRole + 1, child_type)
    return tree, item


def test_a_cluster_interface_offers_a_failover_group():
    from firewallfabrik.gui.object_tree_menu import _get_interface_new_types

    _tree, item = _tree_item('Cluster')

    offered = _get_interface_new_types(item)

    assert ('FailoverClusterGroup', 'Failover Group', True) in offered


def test_a_firewall_interface_does_not():
    """Only a cluster fails over, so only its interfaces offer the group."""
    from firewallfabrik.gui.object_tree_menu import _get_interface_new_types

    _tree, item = _tree_item('Firewall')

    offered = _get_interface_new_types(item)

    assert not any(entry[0] == 'FailoverClusterGroup' for entry in offered)


def test_a_second_failover_group_is_offered_but_not_enabled():
    """One interface fails over with one protocol, so it has one group."""
    from firewallfabrik.gui.object_tree_menu import _get_interface_new_types

    _tree, item = _tree_item('Cluster', ('FailoverClusterGroup',))

    offered = _get_interface_new_types(item)

    assert ('FailoverClusterGroup', 'Failover Group', False) in offered
