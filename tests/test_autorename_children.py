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

"""Renaming an interface renames what hangs under it.

`ObjectManipulator::autorenameChildren` calls `autorename` once per kind
of child, and there are five: the addresses, the MAC, the failover group
of a cluster interface and the Attached Networks object.  The port walked
`iface.addresses` alone, and the two groups are reached through
`child_groups` - so a renamed interface left them naming an interface
that no longer exists, which is exactly what the scheme is for.
"""

import os
import uuid

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import firewallfabrik.core
from firewallfabrik.core.objects import (
    AttachedNetworks,
    Cluster,
    FailoverClusterGroup,
    FWObjectDatabase,
    Interface,
    IPv4,
    Library,
    PhysAddress,
)
from firewallfabrik.gui.editor_manager import (
    _autorename_interface,
    _has_renameable_children,
)


@pytest.fixture
def cluster_interface():
    """A cluster interface with one address, a MAC and both groups."""
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        session.flush()
        cluster = Cluster(
            id=uuid.uuid4(), type='Cluster', name='cluster1', library_id=library.id
        )
        session.add(cluster)
        session.flush()
        iface = Interface(id=uuid.uuid4(), name='eth1', device_id=cluster.id)
        session.add(iface)
        session.flush()
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='cluster1:eth0:ip',
                interface_id=iface.id,
                inet_addr_mask={'address': '192.0.2.1', 'netmask': '255.255.255.0'},
            )
        )
        session.add(
            PhysAddress(
                id=uuid.uuid4(),
                type='PhysAddress',
                name='cluster1:eth0:mac',
                interface_id=iface.id,
            )
        )
        session.add(
            FailoverClusterGroup(
                id=uuid.uuid4(),
                type='FailoverClusterGroup',
                name='cluster1:eth0:members',
                interface_id=iface.id,
                library_id=library.id,
                data={'type': 'vrrp'},
            )
        )
        session.add(
            AttachedNetworks(
                id=uuid.uuid4(),
                type='AttachedNetworks',
                name='cluster1:eth0:attached',
                interface_id=iface.id,
                library_id=library.id,
            )
        )
        session.commit()
        return dm, iface.id


def test_every_kind_of_child_follows_the_interface(cluster_interface):
    dm, iface_id = cluster_interface

    with dm.session() as session:
        iface = session.get(Interface, iface_id)
        renamed = _autorename_interface(iface, 'cluster1')
        names = sorted(obj.name for obj in renamed)

    assert names == [
        'cluster1:eth1:attached',
        'cluster1:eth1:ip',
        'cluster1:eth1:mac',
        'cluster1:eth1:members',
    ]


def test_an_interface_whose_only_child_is_a_group_is_offered_the_rename(
    cluster_interface,
):
    """The offer used to be made only for addresses and sub-interfaces."""
    dm, iface_id = cluster_interface

    with dm.session() as session:
        iface = session.get(Interface, iface_id)
        for addr in list(iface.addresses):
            session.delete(addr)
        session.flush()
        session.refresh(iface)
        assert not iface.addresses
        assert iface.child_groups

        assert _has_renameable_children(iface)
