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

"""Rules and objects copied from one data file into another.

``RuleSetView::createInsertTemplate`` copies a rule of another project
file with ``recursivelyCopySubtree`` (fwbuilder5 RuleSetView.cpp:1555):
what the rule names and the target file has not got is copied along, an
object of the Standard library is the target's own, and a firewall whose
rules name its own interfaces is copied once, with a last pass that points
every reference at the copies.
"""

import os
import uuid

import pytest

pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import sqlalchemy
from PySide6.QtWidgets import QApplication

import firewallfabrik.core
from firewallfabrik.core._validation import load_object
from firewallfabrik.core.objects import (
    STANDARD_LIBRARY_NAME,
    Firewall,
    Library,
    Policy,
    Rule,
    RuleSet,
    TagService,
    rule_elements,
)
from firewallfabrik.gui.object_tree_ops import TreeOperations
from firewallfabrik.gui.policy_model import PolicyTreeModel

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _empty_clipboard():
    yield
    PolicyTreeModel._clipboard = []
    PolicyTreeModel._clipboard_source = None


def _load(name):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / name))
    return db


def _elements(session, rule_id):
    rows = session.execute(
        sqlalchemy.select(rule_elements.c.slot, rule_elements.c.target_id).where(
            rule_elements.c.rule_id == rule_id
        )
    ).all()
    return [(slot, load_object(session, target_id)) for slot, target_id in rows]


def _library_name(obj):
    while getattr(obj, 'library', None) is None:
        obj = (
            getattr(obj, 'group', None)
            or getattr(obj, 'parent_group', None)
            or getattr(obj, 'interface', None)
            or getattr(obj, 'device', None)
        )
        if obj is None:
            return None
    return obj.library.name


def _rule_naming_standard_and_user_objects(db):
    """A policy rule naming a TCP service of the Standard library and an interface."""
    with db.session() as session:
        for rule in session.scalars(
            sqlalchemy.select(Rule).where(Rule.type == 'PolicyRule')
        ):
            objs = [obj for _slot, obj in _elements(session, rule.id)]
            if any(
                type(obj).__name__ == 'TCPService'
                and _library_name(obj) == STANDARD_LIBRARY_NAME
                for obj in objs
            ) and any(type(obj).__name__ == 'Interface' for obj in objs):
                return rule.id, rule.rule_set_id
    raise AssertionError('no such rule in the fixture')


def _top_policy(db, fw_name):
    with db.session() as session:
        fw = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == fw_name)
        ).one()
        return next(rs.id for rs in fw.rule_sets if isinstance(rs, Policy) and rs.top)


def _copy(db, rule_set_id, rule_id):
    model = PolicyTreeModel(db, rule_set_id, rule_set_type='Policy')
    model.copy_rules([model.index_for_rule(rule_id)])


def _paste(db, rule_set_id):
    model = PolicyTreeModel(db, rule_set_id, rule_set_type='Policy')
    return model.paste_rules(model.index(0, 0), before=True)


def test_a_rule_is_pasted_into_another_file(qt_app):
    source = _load('objects-for-regression-tests.fwb')
    target = _load('objects-for-regression-tests.fwb')
    rule_id, rule_set_id = _rule_naming_standard_and_user_objects(source)
    with source.session() as session:
        before = [(slot, obj.name) for slot, obj in _elements(session, rule_id)]
    _copy(source, rule_set_id, rule_id)

    target_policy = _top_policy(target, 'firewall2')
    new_ids = _paste(target, target_policy)

    assert len(new_ids) == 1
    with target.session() as session:
        after = _elements(session, new_ids[0])
        assert sorted((slot, obj.name) for slot, obj in after) == sorted(before)
        for _slot, obj in after:
            assert obj is not None, 'every element names an object of this file'
            if type(obj).__name__ == 'TCPService':
                # The Standard library's own, not a copy in the user's.
                assert _library_name(obj) == STANDARD_LIBRARY_NAME


def test_the_other_file_keeps_its_rule(qt_app):
    source = _load('objects-for-regression-tests.fwb')
    target = _load('basic_accept_deny.fwf')
    rule_id, rule_set_id = _rule_naming_standard_and_user_objects(source)
    _copy(source, rule_set_id, rule_id)

    _paste(target, _top_policy(target, 'fw-test'))

    with source.session() as session:
        assert session.get(Rule, rule_id) is not None


def test_a_file_without_a_standard_library_gets_a_copy(qt_app):
    source = _load('objects-for-regression-tests.fwb')
    target = _load('basic_accept_deny.fwf')
    rule_id, rule_set_id = _rule_naming_standard_and_user_objects(source)
    _copy(source, rule_set_id, rule_id)

    new_ids = _paste(target, _top_policy(target, 'fw-test'))

    with target.session() as session:
        names = {type(obj).__name__ for _slot, obj in _elements(session, new_ids[0])}
        assert 'TCPService' in names
        assert {lib.name for lib in session.scalars(sqlalchemy.select(Library))} == {
            'Test Objects'
        }


def _paste_with_options(options):
    """Paste the fixture rule with *options* added; return target and its options."""
    source = _load('objects-for-regression-tests.fwb')
    target = _load('basic_accept_deny.fwf')
    rule_id, rule_set_id = _rule_naming_standard_and_user_objects(source)
    with source.session() as session:
        rule = session.get(Rule, rule_id)
        rule.options = {**(rule.options or {}), **options(session, rule_set_id)}
    _copy(source, rule_set_id, rule_id)
    new_ids = _paste(target, _top_policy(target, 'fw-test'))
    with target.session() as session:
        return target, dict(session.get(Rule, new_ids[0]).options)


def test_the_tag_object_is_copied_along(qt_app):
    """Firewall Builder leaves `tagobject_id` naming the other file's object."""

    names = []

    def tagging(session, _rule_set_id):
        tag = session.scalars(sqlalchemy.select(TagService)).first()
        names.append(tag.name)
        return {'tagging': True, 'tagobject_id': str(tag.id)}

    target, options = _paste_with_options(tagging)

    with target.session() as session:
        tag_copy = session.get(TagService, uuid.UUID(options['tagobject_id']))
        assert tag_copy is not None
        assert tag_copy.name == names[0]


def test_a_branch_into_a_rule_set_copied_along_follows_it(qt_app):
    """The rule names an interface, which brings its firewall and rule sets."""

    def branching(session, rule_set_id):
        rule_set = session.get(RuleSet, rule_set_id)
        return {'branch_id': str(rule_set_id), 'branch_name': rule_set.name}

    target, options = _paste_with_options(branching)

    with target.session() as session:
        rule_set = session.get(RuleSet, uuid.UUID(options['branch_id']))
        assert rule_set is not None, 'the copy, not the original'
        assert options['branch_name'] == rule_set.name


def test_a_branch_into_another_firewall_brings_that_firewall_along(qt_app):
    """Firewall Builder leaves the branch without a target; fwf copies it.

    The rule set belongs to a firewall nothing else in the rule names, so
    only the branch can bring it.
    """
    names = []

    def branching(session, rule_set_id):
        own_device = session.get(RuleSet, rule_set_id).device_id
        other = next(
            rs
            for rs in session.scalars(sqlalchemy.select(RuleSet))
            if rs.device_id != own_device and rs.type == 'Policy'
        )
        names.append((other.name, other.device.name))
        return {'branch_id': str(other.id), 'branch_name': other.name}

    target, options = _paste_with_options(branching)

    with target.session() as session:
        rule_set = session.get(RuleSet, uuid.UUID(options['branch_id']))
        assert rule_set is not None, 'the copy, not the original'
        assert options['branch_name'] == rule_set.name == names[0][0]
        assert rule_set.device.name.startswith(names[0][1])


def test_a_branch_into_a_rule_set_that_does_not_exist_has_no_target(qt_app):
    """Keeping the name would send it into this firewall's rule set of that name."""
    _target, options = _paste_with_options(
        lambda _session, _rs: {'branch_id': str(uuid.uuid4()), 'branch_name': 'Policy'}
    )

    assert 'branch_id' not in options
    assert 'branch_name' not in options


def _count(db, cls):
    with db.session() as session:
        return len(session.scalars(sqlalchemy.select(cls)).all())


def test_pasting_twice_copies_what_the_rules_name_once(qt_app):
    source = _load('objects-for-regression-tests.fwb')
    target = _load('basic_accept_deny.fwf')
    rule_id, rule_set_id = _rule_naming_standard_and_user_objects(source)
    target_policy = _top_policy(target, 'fw-test')
    _copy(source, rule_set_id, rule_id)

    first = _paste(target, target_policy)
    firewalls = _count(target, Firewall)
    second = _paste(target, target_policy)

    assert _count(target, Firewall) == firewalls
    with target.session() as session:
        assert {o.id for _s, o in _elements(session, first[0])} == {
            o.id for _s, o in _elements(session, second[0])
        }


def test_an_object_pasted_twice_is_copied_twice(qt_app):
    """Only what the pasted object names is reused, not the object itself."""
    source = _load('basic_accept_deny.fwf')
    target = _load('compiler-tests.fwf')
    with source.session() as session:
        fw_id = session.scalars(sqlalchemy.select(Firewall)).one().id
    with target.session() as session:
        lib_id = next(
            lib.id for lib in session.scalars(sqlalchemy.select(Library)) if not lib.ro
        )
    ops = TreeOperations(target)

    first = ops.duplicate_object_cross_db(source, fw_id, Firewall, lib_id)
    second = ops.duplicate_object_cross_db(source, fw_id, Firewall, lib_id)

    assert first != second


def test_a_firewall_naming_its_own_interfaces_is_copied_once(qt_app):
    source = _load('basic_accept_deny.fwf')
    target = _load('compiler-tests.fwf')
    with source.session() as session:
        fw_id = session.scalars(sqlalchemy.select(Firewall)).one().id
    with target.session() as session:
        lib_id = next(
            lib.id for lib in session.scalars(sqlalchemy.select(Library)) if not lib.ro
        )

    new_id = TreeOperations(target).duplicate_object_cross_db(
        source, fw_id, Firewall, lib_id
    )

    with target.session() as session:
        copy = session.get(Firewall, new_id)
        own = {addr.id for iface in copy.interfaces for addr in iface.addresses}
        policy = next(rs for rs in copy.rule_sets if isinstance(rs, Policy))
        named = {
            obj.id
            for rule in policy.rules
            for slot, obj in _elements(session, rule.id)
            if slot == 'dst'
            and obj is not None
            and type(obj).__name__ == 'IPv4'
            and obj.interface is not None
        }
        assert named, 'the rules name interface addresses'
        assert named <= own, "and those are the copy's own"
        dangling = [
            row
            for rs in session.scalars(sqlalchemy.select(RuleSet))
            for rule in rs.rules
            for row in _elements(session, rule.id)
            if row[1] is None
        ]
        assert dangling == []
