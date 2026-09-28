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

"""Duplicating a firewall or a cluster copies everything it owns.

The copy has to point at its own parts, the way
``FWObjectDatabase::fixReferences`` rewrites a copied subtree: a
sub-interface at the copy of its parent, a rule branching into a rule set
of the same firewall at the copy of that rule set, and a failover group
or state sync group has to come along, or the copy of a cluster has no
members.
"""

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Firewall
from firewallfabrik.gui.object_tree_ops import TreeOperations


def _duplicate(fixture, model_cls, name):
    dm = firewallfabrik.core.DatabaseManager()
    dm.load(fixture)
    with dm.session() as session:
        source = session.scalars(
            sqlalchemy.select(model_cls).where(model_cls.name == name)
        ).one()
        source_id, lib_id = source.id, source.library_id
    new_id = TreeOperations(dm).duplicate_object(source_id, model_cls, lib_id)
    return dm, source_id, new_id


def test_sub_interfaces_point_at_the_copied_parent():
    dm, source_id, new_id = _duplicate(
        'tests/fixtures/objects-for-regression-tests.fwb', Firewall, 'firewall23-1'
    )
    with dm.session() as session:
        source = session.get(Firewall, source_id)
        copy = session.get(Firewall, new_id)
        own = {iface.id for iface in copy.interfaces}
        parents = [i.parent_interface_id for i in copy.interfaces]
        assert len(copy.interfaces) == len(source.interfaces)
        assert any(parents)
        assert all(p is None or p in own for p in parents)


def test_branches_into_own_rule_sets_follow_the_copy():
    dm, _source_id, new_id = _duplicate(
        'tests/fixtures/objects-for-regression-tests.fwb', Firewall, 'firewall25'
    )
    with dm.session() as session:
        copy = session.get(Firewall, new_id)
        own = {str(rs.id) for rs in copy.rule_sets}
        branches = [
            rule.options['branch_id']
            for rs in copy.rule_sets
            for rule in rs.rules
            if (rule.options or {}).get('branch_id')
        ]
        assert branches
        assert all(branch in own for branch in branches)


def test_cluster_copy_keeps_its_groups_and_members():
    dm, source_id, new_id = _duplicate(
        'tests/fixtures/cluster-tests.fwb', Cluster, 'vrrp_cluster_1'
    )
    with dm.session() as session:
        source = session.get(Cluster, source_id)
        copy = session.get(Cluster, new_id)
        assert [m.name for m in copy.get_members_list()] == [
            m.name for m in source.get_members_list()
        ]
        assert [g.type for g in copy.child_groups] == ['StateSyncClusterGroup']
        for iface in copy.interfaces:
            for group in iface.child_groups:
                assert group.interface_id == iface.id
