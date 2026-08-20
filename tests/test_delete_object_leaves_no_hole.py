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

"""Deleting an object must not widen the rules that named it.

A rule element with no objects in it is "any" everywhere in the compiler.
So removing the last object from one turns "accept HTTPS from this host"
into "accept HTTPS from anywhere", and neither the editor nor the compiled
script says a word about it.

Firewall Builder cannot end up there - it leaves a `dummySource`
placeholder and `Compiler::Begin` skips the rule with a warning.
FirewallFabrik has no deleted objects and no placeholders, so it disables
the rule instead: it stays visible, it compiles to nothing, and the
administrator decides whether to repair or remove it.
"""

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall, Host, Rule, RuleSet, rule_elements

pytest.importorskip('PySide6')

from firewallfabrik.gui.object_tree_ops import TreeOperations

from .conftest import FIXTURES_DIR


def _rules_of(session, fw_name):
    fw = session.scalars(
        sqlalchemy.select(Firewall).where(Firewall.name == fw_name)
    ).one()
    rule_sets = session.execute(
        sqlalchemy.select(RuleSet).where(RuleSet.device_id == fw.id)
    ).scalars()
    return {
        (rs.name, rule.position): rule
        for rs in rule_sets
        for rule in rs.rules
        if rs.type == 'Policy'
    }


def _slot(session, rule, slot):
    return session.execute(
        sqlalchemy.select(rule_elements).where(
            rule_elements.c.rule_id == rule.id,
            rule_elements.c.slot == slot,
        )
    ).all()


def _pick_victim(db):
    """Find a host that is the only object in some other rule's element."""
    with db.session() as session:
        rows = session.execute(sqlalchemy.select(rule_elements)).all()
        by_rule_slot = {}
        for row in rows:
            by_rule_slot.setdefault((row.rule_id, row.slot), []).append(row.target_id)
        for (rule_id, slot), targets in by_rule_slot.items():
            if len(targets) != 1:
                continue
            host = session.get(Host, targets[0])
            if host is None:
                continue
            rule = session.get(Rule, rule_id)
            rule_set = session.get(RuleSet, rule.rule_set_id)
            if rule_set.device_id == host.id:
                continue  # the rule goes away with the host anyway
            return host.id, host.name, rule_id, slot
    return None


def test_the_only_object_of_an_element_disables_the_rule():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))

    victim = _pick_victim(db)
    if victim is None:
        pytest.skip('no rule in this fixture names exactly one foreign object')
    host_id, host_name, rule_id, slot = victim

    ops = TreeOperations(db)
    assert ops.delete_object(host_id, Host, host_name, 'Host')

    with db.session() as session:
        rule = session.get(Rule, rule_id)
        assert rule is not None, 'the rule itself stays'
        assert _slot(session, rule, slot) == [], 'and its element is empty'
        assert (rule.options or {}).get('disabled') is True, (
            'so it must not be compiled: an empty element matches everything'
        )


def test_an_element_that_keeps_another_object_is_left_alone():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))

    with db.session() as session:
        rows = session.execute(sqlalchemy.select(rule_elements)).all()
        by_rule_slot = {}
        for row in rows:
            by_rule_slot.setdefault((row.rule_id, row.slot), []).append(row.target_id)
        target = None
        for (rule_id, slot), targets in by_rule_slot.items():
            if len(targets) < 2:
                continue
            for tid in targets:
                host = session.get(Host, tid)
                rule = session.get(Rule, rule_id)
                rule_set = session.get(RuleSet, rule.rule_set_id)
                if host is not None and rule_set.device_id != host.id:
                    target = (tid, host.name, rule_id, slot)
                    break
            if target:
                break
    if target is None:
        pytest.skip('no rule in this fixture names two objects, one of them a host')
    host_id, host_name, rule_id, slot = target

    ops = TreeOperations(db)
    assert ops.delete_object(host_id, Host, host_name, 'Host')

    with db.session() as session:
        rule = session.get(Rule, rule_id)
        assert _slot(session, rule, slot), 'the other objects are still there'
        assert not (rule.options or {}).get('disabled'), 'so the rule keeps working'
