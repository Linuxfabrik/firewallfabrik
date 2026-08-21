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

"""Why an expanded element ended up empty decides whether it is said.

`Compiler.expand_addr` can leave a rule element with nothing in it for
two quite different reasons, and an empty element means "any", so the
rule has to go either way.  Only one of the two is the ordinary fate of a
single-stack rule in the other family's pass, and only that one may stay
silent - `DropRuleWithEmptyRE` keeps quiet about it when the family the
rule does name is compiled as well.

A host that carries no usable address at all is gone from *every* pass,
so it has to be said, and the message has to name the object rather than
blame an address family that has nothing to do with it.
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import Host, PolicyAction

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def session():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    with db.session() as session:
        yield session


def _host(session, name):
    return (
        session.execute(
            sqlalchemy.select(Host).where(Host.name == name),
        )
        .scalars()
        .first()
    )


def _rule(objects):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    rule.src = list(objects)
    return rule


def _expand(objects, *, ipv6):
    compiler = Compiler.__new__(Compiler)
    compiler.ipv6_policy = ipv6
    rule = _rule(objects)
    compiler.expand_addr(rule, 'src')
    return rule


def test_a_host_with_no_address_names_itself(session):
    """`empty-ip` has an interface and no address on it."""
    rule = _expand([_host(session, 'empty-ip')], ipv6=False)
    assert rule.src == []
    assert rule.has_empty_re is True
    assert rule.empty_re_family_only is False, (
        'the host is gone from both passes, so the message must not be silenced'
    )
    assert rule.empty_re_reason == '"empty-ip" contributes no address to it'


def test_the_address_family_keeps_its_own_sentence(session):
    """An IPv4-only host in the IPv6 pass is the ordinary case."""
    rule = _expand([_host(session, 'dns-server')], ipv6=True)
    assert rule.src == []
    assert rule.has_empty_re is True
    assert rule.empty_re_family_only is True
    assert 'address family' in rule.empty_re_reason


def test_the_host_still_expands_in_the_family_it_has(session):
    rule = _expand([_host(session, 'dns-server')], ipv6=False)
    assert [a.get_address() for a in rule.src] == ['10.0.0.10']
    assert rule.has_empty_re is False


def test_an_addressless_host_beside_a_wrong_family_one_wins(session):
    """A reason that is not the address family is the one worth reporting."""
    rule = _expand(
        [_host(session, 'dns-server'), _host(session, 'empty-ip')], ipv6=True
    )
    assert rule.src == []
    assert rule.empty_re_family_only is False
    assert 'empty-ip' in rule.empty_re_reason
