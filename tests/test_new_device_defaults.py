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

"""What a new firewall, cluster or host starts out with.

Firewall Builder gives a new firewall an empty Policy, NAT and Routing
rule set, each the top one of its kind (``Firewall::init``), and a new
cluster also its state sync group (``Cluster::init``).  A host gets
neither.
"""

import uuid

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
    FWObjectDatabase,
    Host,
    Library,
)
from firewallfabrik.gui.object_tree_ops import TreeOperations


def _create(model_cls):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        lib_id = library.id
    new_id = TreeOperations(dm).create_new_object(
        model_cls, model_cls.__name__, lib_id, name='new'
    )
    return dm, new_id


@pytest.mark.parametrize('model_cls', [Firewall, Cluster])
def test_firewall_and_cluster_get_top_rule_sets(model_cls):
    dm, new_id = _create(model_cls)
    with dm.session() as session:
        device = session.get(Host, new_id)
        rule_sets = sorted((rs.type, rs.name, rs.top) for rs in device.rule_sets)
    assert rule_sets == [
        ('NAT', 'NAT', True),
        ('Policy', 'Policy', True),
        ('Routing', 'Routing', True),
    ]


def test_cluster_gets_a_state_sync_group():
    dm, new_id = _create(Cluster)
    with dm.session() as session:
        groups = [
            (g.type, g.name, g.get_protocol())
            for g in session.get(Host, new_id).child_groups
        ]
    assert groups == [('StateSyncClusterGroup', 'State Sync Group', 'conntrack')]


def test_host_gets_neither():
    dm, new_id = _create(Host)
    with dm.session() as session:
        host = session.get(Host, new_id)
        assert host.rule_sets == []
        assert host.child_groups == []
