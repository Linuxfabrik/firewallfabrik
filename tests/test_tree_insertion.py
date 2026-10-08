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

"""Pasting, grouping and deleting in the object tree, against fwbuilder.

``ObjectManipulator::actuallyPasteTo`` adds a reference when the target is
a group that is not a standard folder, and a copy of the whole subtree
otherwise; ``FWObject::addRef`` asks the group's ``validateChild``; and a
deletion takes the XML children of an object along.  The port pasted a
copy into a group, which no rule then saw, pasted an interface without
its addresses, grouped anything with anything, and left the state sync
groups of a deleted cluster behind.
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core._validation import load_object
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
    Group,
    Interface,
    IPv4,
    ObjectGroup,
    Policy,
    RuleSet,
    StateSyncClusterGroup,
    TCPService,
    group_membership,
    rule_elements,
)

pytest.importorskip('PySide6')

from firewallfabrik.gui.object_tree_data import group_contents
from firewallfabrik.gui.object_tree_ops import TreeOperations
from firewallfabrik.gui.object_usage import (
    find_option_references,
    find_referencing_firewalls,
)

from .conftest import FIXTURES_DIR


def _db(name='objects-for-regression-tests.fwb'):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / name))
    return db


def _members(db, group_id):
    with db.session() as session:
        return [
            row.member_id
            for row in session.execute(
                sqlalchemy.select(group_membership.c.member_id)
                .where(group_membership.c.group_id == group_id)
                .order_by(group_membership.c.position)
            )
        ]


def _user_group(db, name='rfc1918-nets'):
    with db.session() as session:
        return (
            session.scalars(
                sqlalchemy.select(ObjectGroup).where(ObjectGroup.name == name)
            )
            .first()
            .id
        )


def test_a_member_is_added_and_a_service_is_not():
    db = _db()
    group_id = _user_group(db)
    with db.session() as session:
        address = session.scalars(sqlalchemy.select(IPv4)).first().id
        service = session.scalars(sqlalchemy.select(TCPService)).first().id
    before = _members(db, group_id)

    added = TreeOperations(db).add_group_members(group_id, [address, service])

    assert added == 1
    assert _members(db, group_id) == [*before, address]


def test_an_interface_becomes_a_member():
    """#189: what the editor refused although Firewall Builder takes it."""
    db = _db()
    group_id = _user_group(db)
    with db.session() as session:
        iface = (
            session.scalars(
                sqlalchemy.select(Interface).where(Interface.device_id.is_not(None))
            )
            .first()
            .id
        )

    assert TreeOperations(db).add_group_members(group_id, [iface]) == 1
    with db.session() as session:
        group = session.get(Group, group_id)
        assert iface in [m.id for m in group.get_member_objects()]
        assert any(isinstance(o, Interface) for o in group_contents(group))


def test_grouping_a_selection_keeps_only_what_the_group_takes():
    db = _db()
    with db.session() as session:
        lib_id = session.scalars(sqlalchemy.select(IPv4)).first().library_id
        address = session.scalars(sqlalchemy.select(IPv4)).first().id
        service = session.scalars(sqlalchemy.select(TCPService)).first().id
        policy = session.scalars(sqlalchemy.select(Policy)).first().id

    new_id = TreeOperations(db).group_objects(
        'ObjectGroup', 'mixed', lib_id, [address, service, policy]
    )

    assert _members(db, new_id) == [address]


def test_the_tree_counts_the_members_of_a_user_group():
    db = _db()
    with db.session() as session:
        group = session.get(Group, _user_group(db))
        assert len(group_contents(group)) == 3


def test_a_pasted_interface_brings_its_addresses():
    db = _db()
    with db.session() as session:
        iface = next(
            i
            for i in session.scalars(sqlalchemy.select(Interface))
            if i.device_id is not None and i.addresses
        )
        source_id, count = iface.id, len(iface.addresses)
        target = (
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.id != iface.device_id)
            )
            .first()
            .id
        )

    new_id = TreeOperations(db).duplicate_object(
        source_id, Interface, None, target_device_id=target
    )

    with db.session() as session:
        copy = session.get(Interface, new_id)
        assert copy.device_id == target
        assert len(copy.addresses) == count


def test_a_rule_set_is_pasted_with_its_rules():
    db = _db()
    with db.session() as session:
        source = next(
            rs for rs in session.scalars(sqlalchemy.select(Policy)) if rs.rules
        )
        source_id, rules = source.id, len(source.rules)
        target = (
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.id != source.device_id)
            )
            .first()
            .id
        )

    new_id = TreeOperations(db).paste_rule_set(None, source_id, target)

    with db.session() as session:
        copy = session.get(RuleSet, new_id)
        assert copy.device_id == target
        assert len(copy.rules) == rules
        assert not copy.top, 'the firewall has a top policy already'


def test_deleting_a_cluster_takes_its_state_sync_group_along():
    db = _db('cluster-tests.fwb')
    with db.session() as session:
        cluster = next(
            c for c in session.scalars(sqlalchemy.select(Cluster)) if c.child_groups
        )
        cluster_id, name = cluster.id, cluster.name

    assert TreeOperations(db).delete_object(cluster_id, Cluster, name, 'Cluster')

    with db.session() as session:
        orphans = session.scalars(
            sqlalchemy.select(StateSyncClusterGroup).where(
                StateSyncClusterGroup.device_id.is_(None),
                StateSyncClusterGroup.interface_id.is_(None),
            )
        ).all()
        assert orphans == []


def test_deleting_a_parent_interface_takes_its_sub_interfaces_along():
    db = _db()
    with db.session() as session:
        parent = next(
            i for i in session.scalars(sqlalchemy.select(Interface)) if i.sub_interfaces
        )
        parent_id = parent.id
        sub_ids = [s.id for s in parent.sub_interfaces]

    assert TreeOperations(db).delete_object(parent_id, Interface, 'x', 'Interface')

    with db.session() as session:
        assert all(session.get(Interface, sid) is None for sid in sub_ids)


def test_a_branch_target_is_where_used_and_marks_the_firewall():
    db = _db()
    with db.session() as session:
        refs = []
        for rs in session.scalars(sqlalchemy.select(RuleSet)):
            refs = find_option_references(session, [rs.id])
            if refs:
                break
        if not refs:
            pytest.skip('the fixture branches nowhere')
        rule, key = refs[0]
        assert key == 'branch_id'
        owner = session.get(RuleSet, rule.rule_set_id).device_id
        assert owner in {fw.id for fw in find_referencing_firewalls(session, rs.id)}


def test_an_unknown_id_is_no_member():
    db = _db()
    group_id = _user_group(db)
    assert TreeOperations(db).add_group_members(group_id, [uuid.uuid4()]) == 0


def _ref_ids_of_firewall(session, fw):
    return {
        row.target_id
        for rs in fw.rule_sets
        for rule in rs.rules
        for row in session.execute(
            sqlalchemy.select(rule_elements.c.target_id).where(
                rule_elements.c.rule_id == rule.id
            )
        )
    }


def test_a_firewall_pasted_into_another_file_brings_what_its_rules_name():
    """recursivelyCopySubtree follows every reference (FWObjectDatabase_tree_ops.cpp:494)."""
    source = _db('reject_actions.fwf')
    target = _db('compiler-tests.fwf')
    with source.session() as session:
        fw = session.scalars(sqlalchemy.select(Firewall)).first()
        fw_id = fw.id
    with target.session() as session:
        lib_id = session.scalars(sqlalchemy.select(Firewall)).first().library_id

    new_id = TreeOperations(target).duplicate_object_cross_db(
        source, fw_id, Firewall, lib_id
    )

    with target.session() as session:
        copy = session.get(Firewall, new_id)
        refs = _ref_ids_of_firewall(session, copy)
        assert refs
        missing = [r for r in refs if load_object(session, r) is None]
        assert missing == [], 'every object a copied rule names exists here'
