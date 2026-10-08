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

"""A Dynamic Group selects every address and object group with the keyword.

``DynamicGroup::isMemberOfGroup`` takes whatever ``Address::cast`` or
``ObjectGroup::cast`` accepts.  An interface is an address there and a
cluster's failover group an object group.  The port looked only at three
of the four tables the objects live in and so never selected an
interface, and it asked the library of an interface address directly,
which only the interface has.
"""

import uuid

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core._dynamic_groups import dynamic_group_members
from firewallfabrik.core.objects import (
    Address,
    DynamicGroup,
    FailoverClusterGroup,
    Interface,
    Network,
    Service,
)

from .conftest import FIXTURES_DIR


def _members(db, fixture_objects, keyword='kwtest'):
    with db.session() as session:
        for cls, name in fixture_objects:
            obj = session.scalars(
                sqlalchemy.select(cls).where(cls.name == name)
            ).first()
            obj.keywords = {keyword}
        group = DynamicGroup(id=uuid.uuid4(), name='dg')
        return {
            (type(o).__name__, o.name)
            for o in dynamic_group_members(session, group, [('any', keyword)], 'OR')
        }


def _first(db, cls, where=None):
    with db.session() as session:
        stmt = sqlalchemy.select(cls)
        if where is not None:
            stmt = stmt.where(where)
        return session.scalars(stmt).first().name


def test_an_interface_and_its_address_are_selected():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    iface = _first(db, Interface, Interface.device_id.is_not(None))
    addr = _first(db, Address, Address.interface_id.is_not(None))

    members = _members(db, [(Interface, iface), (Address, addr)])

    assert ('Interface', iface) in members
    assert any(name == addr for _cls, name in members)


def test_a_failover_group_is_selected():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'cluster-tests.fwb'))
    group = _first(db, FailoverClusterGroup)

    members = _members(db, [(FailoverClusterGroup, group)])

    assert ('FailoverClusterGroup', group) in members


def test_services_and_the_any_placeholder_are_never_selected():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    service = _first(db, Service)

    members = _members(db, [(Service, service), (Network, 'Any')])

    assert all(name not in (service, 'Any') for _cls, name in members)
