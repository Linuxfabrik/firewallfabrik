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

"""Find and Replace asks the container it replaces in.

``FindObjectWidget`` replaces references in rules and in groups, and its
``addRef`` asks the container's ``validateChild``.  The port replaced in
rules only, checked nothing but "address against address", and so could
put a host into an Interface element.
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core._validation import replace_kind
from firewallfabrik.core.objects import (
    DynamicGroup,
    Host,
    Interface,
    Network,
    ObjectGroup,
    TCPService,
    group_membership,
    rule_elements,
)

pytest.importorskip('PySide6')

from firewallfabrik.gui.find_panel import FindPanel, _FindResult

from .conftest import FIXTURES_DIR


def _db():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    return db


def _writable_group(session):
    """A user object group in a library that is not read-only, with members."""
    return next(
        g
        for g in session.scalars(
            sqlalchemy.select(ObjectGroup).where(ObjectGroup.type == 'ObjectGroup')
        )
        if not g.library.ro
        and any(isinstance(m, Network) for m in g.get_member_objects())
    )


def test_a_dynamic_group_can_replace_a_network():
    """validateReplaceObject counts MultiAddress and ObjectGroup as addresses."""
    assert replace_kind(DynamicGroup(name='dg')) == 'address'
    assert replace_kind(Network(name='n')) == 'address'
    assert replace_kind(Host(name='h')) == 'address'
    assert replace_kind(TCPService(name='s')) == 'service'


def test_a_host_does_not_replace_an_interface_in_a_rule():
    db = _db()
    with db.session() as session:
        row = next(
            r
            for r in session.execute(
                sqlalchemy.select(rule_elements).where(rule_elements.c.slot == 'itf')
            )
            if session.get(Interface, r.target_id) is not None
        )
        host = session.scalars(sqlalchemy.select(Host)).first()
        result = _FindResult(rule_id=row.rule_id, slot='itf', target_id=row.target_id)

        refusal = FindPanel._replace_one(session, result, row.target_id, host)

        assert refusal
        still = (
            session.execute(
                sqlalchemy.select(rule_elements.c.target_id).where(
                    rule_elements.c.rule_id == row.rule_id,
                    rule_elements.c.slot == 'itf',
                )
            )
            .scalars()
            .all()
        )
        assert row.target_id in still, 'the reference stays where it was'


def test_a_member_of_a_group_is_replaced():
    db = _db()
    with db.session() as session:
        group = _writable_group(session)
        old = next(m for m in group.get_member_objects() if isinstance(m, Network))
        new = session.scalars(
            sqlalchemy.select(Network).where(Network.id.not_in([old.id]))
        ).first()
        result = _FindResult(group_id=group.id, target_id=old.id)

        assert FindPanel._replace_one(session, result, old.id, new) == ''
        members = (
            session.execute(
                sqlalchemy.select(group_membership.c.member_id).where(
                    group_membership.c.group_id == group.id
                )
            )
            .scalars()
            .all()
        )
        assert new.id in members
        assert old.id not in members


def test_a_service_does_not_replace_a_member_of_an_object_group():
    db = _db()
    with db.session() as session:
        group = _writable_group(session)
        old = group.get_member_objects()[0]
        service = session.scalars(sqlalchemy.select(TCPService)).first()
        result = _FindResult(group_id=group.id, target_id=old.id)

        assert FindPanel._replace_one(session, result, old.id, service)


def test_an_unknown_replacement_is_reported():
    db = _db()
    with db.session() as session:
        result = _FindResult(group_id=uuid.uuid4(), target_id=uuid.uuid4())
        assert FindPanel._replace_one(session, result, uuid.uuid4(), None)
