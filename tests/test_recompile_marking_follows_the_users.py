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

"""Changing an address marks every firewall that names the host (#159).

The compile dialog offers a firewall when its ``lastModified`` is newer
than its ``lastCompiled``, so a firewall that is not stamped is a
firewall the administrator is not offered - it keeps running a script
built against an address that has since changed, and nothing says so.

Two hierarchies lead from an edited object to the firewalls it affects.
Group membership was already followed; containment was not, and it is
the one the issue's repro needs: a rule names *the host*, never the
address object under its interface, so asking who references the address
finds nobody.
"""

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Address,
    Firewall,
    Host,
    Interface,
    Rule,
    RuleSet,
    rule_elements,
)

pytest.importorskip('PySide6')

from firewallfabrik.gui.editor_manager import (
    _containment_chain,
    _find_parent_firewall,
    _find_referencing_firewalls,
)

from .conftest import FIXTURES_DIR

# `fw-services` is named in the source of a rule belonging to
# `fw-empty-src`, which is the shape the issue describes: two firewalls,
# one used in the other's policy.
NAMED_FIREWALL = 'fw-services'
FIREWALL_THAT_NAMES_IT = 'fw-empty-src'


@pytest.fixture(scope='module')
def database():
    dm = firewallfabrik.core.DatabaseManager()
    dm.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    return dm


def _address_of(session, firewall_name):
    """Return an IP address object under an interface of *firewall_name*."""
    fw = session.scalars(
        sqlalchemy.select(Firewall).where(Firewall.name == firewall_name)
    ).one()
    for iface in fw.interfaces:
        for addr in iface.addresses:
            if addr.get_address():
                return fw, iface, addr
    raise AssertionError(f'{firewall_name} carries no address')


def test_the_fixture_has_one_firewall_naming_another(database):
    """Otherwise the test below would pass without measuring anything."""
    with database.session() as session:
        named = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == NAMED_FIREWALL)
        ).one()
        owners = set()
        for row in session.execute(
            sqlalchemy.select(rule_elements).where(
                rule_elements.c.target_id == named.id
            )
        ).all():
            rule = session.get(Rule, row.rule_id)
            rule_set = session.get(RuleSet, rule.rule_set_id)
            owner = session.get(Host, rule_set.device_id)
            if owner is not None and owner.id != named.id:
                owners.add(owner.name)
    assert FIREWALL_THAT_NAMES_IT in owners


def test_the_chain_from_an_address_reaches_its_firewall(database):
    with database.session() as session:
        fw, iface, addr = _address_of(session, NAMED_FIREWALL)
        chain = _containment_chain(addr)
        kinds = [type(o).__name__ for o in chain]
        reaches_interface = any(
            isinstance(o, Interface) and o.id == iface.id for o in chain
        )
        reaches_firewall = any(isinstance(o, Firewall) and o.id == fw.id for o in chain)

    assert kinds[:2] == [type(addr).__name__, 'Interface']
    assert reaches_interface
    assert reaches_firewall


def test_the_owning_firewall_is_still_found(database):
    """The parent walk is built on the chain now; it must not have moved."""
    with database.session() as session:
        fw, iface, addr = _address_of(session, NAMED_FIREWALL)

        assert _find_parent_firewall(addr) is fw
        assert _find_parent_firewall(iface) is fw
        assert _find_parent_firewall(fw) is fw
        assert _find_parent_firewall(None) is None


@pytest.mark.parametrize('level', ('address', 'interface', 'firewall'))
def test_changing_a_host_marks_the_firewall_that_names_it(database, level):
    """Whether the edit lands on the address, the interface or the host."""
    with database.session() as session:
        fw, iface, addr = _address_of(session, NAMED_FIREWALL)
        edited = {'address': addr, 'interface': iface, 'firewall': fw}[level]

        found = {f.name for f in _find_referencing_firewalls(session, edited)}

    assert FIREWALL_THAT_NAMES_IT in found


def test_an_address_of_a_host_nobody_names_reaches_nobody(database):
    """The search has to stay a search, not stamp the whole file."""
    with database.session() as session:
        addresses = session.scalars(sqlalchemy.select(Address)).all()
        unused = [
            a
            for a in addresses
            if a.interface is not None
            and not session.execute(
                sqlalchemy.select(rule_elements).where(
                    rule_elements.c.target_id.in_([o.id for o in _containment_chain(a)])
                )
            ).all()
        ]
        if not unused:
            pytest.skip('every address of the fixture is named somewhere')
        found = _find_referencing_firewalls(session, unused[0])

    assert found == []
