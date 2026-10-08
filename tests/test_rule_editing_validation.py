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

"""Rule editing refuses what Firewall Builder refuses.

- ``checkRuleType``: a policy rule pasted into a NAT rule set became an
  "any to any, translate nothing" rule that switched off the NAT below it.
- ``RuleSetView::canChange``: the rules of a locked firewall stayed
  editable.
- ``changeAction``: choosing the action a rule already has reset its
  stateless flag.
"""

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core._validation import keyword_refusal, simplify_keyword
from firewallfabrik.core.objects import NAT, Firewall, Policy, PolicyAction, Rule

pytest.importorskip('PySide6')

from PySide6.QtWidgets import QApplication

import firewallfabrik.gui.ui_loader  # the dialogs need it first
from firewallfabrik.gui.cluster_protocol_dialogs import (
    ConntrackOptionsDialog,
    VRRPOptionsDialog,
)
from firewallfabrik.gui.policy_model import PolicyTreeModel

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def qt_app():
    return QApplication.instance() or QApplication([])


def _db():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    return db


def _firewall_with(db, *kinds):
    with db.session() as session:
        for fw in session.scalars(sqlalchemy.select(Firewall)):
            sets = {}
            for rs in fw.rule_sets:
                if isinstance(rs, kinds) and rs.rules and type(rs) not in sets:
                    sets[type(rs)] = rs.id
            if len(sets) == len(kinds):
                return fw.id, sets
    raise AssertionError('no firewall with these rule sets')


def _model(db, rs_id, rs_type):
    return PolicyTreeModel(db, rs_id, rule_set_type=rs_type)


def _first_rule_index(model):
    with model._db_manager.session() as session:
        rule = session.scalars(
            sqlalchemy.select(Rule)
            .where(Rule.rule_set_id == model._rule_set_id)
            .order_by(Rule.position)
        ).first()
        return model.index_for_rule(rule.id), rule.id


def test_a_policy_rule_is_not_pasted_into_a_nat_rule_set(qt_app):
    db = _db()
    _fw, sets = _firewall_with(db, Policy, NAT)
    policy = _model(db, sets[Policy], 'Policy')
    nat = _model(db, sets[NAT], 'NAT')
    index, _rule = _first_rule_index(policy)
    policy.copy_rules([index])

    assert policy.pasteable_rule_ids()
    assert nat.pasteable_rule_ids() == []
    nat_index, _ = _first_rule_index(nat)
    assert nat.paste_rules(nat_index) == []


def test_the_rules_of_a_locked_firewall_do_not_change(qt_app):
    db = _db()
    fw_id, sets = _firewall_with(db, Policy)
    with db.session() as session:
        session.get(Firewall, fw_id).ro = True
    model = _model(db, sets[Policy], 'Policy')
    refused = []
    model.modification_refused.connect(refused.append)
    index, rule_id = _first_rule_index(model)
    with db.session() as session:
        before = session.get(Rule, rule_id).comment

    model.set_comment(index, 'changed')

    assert refused
    with db.session() as session:
        assert session.get(Rule, rule_id).comment == before


def test_choosing_the_same_action_keeps_the_stateless_flag(qt_app):
    db = _db()
    _fw, sets = _firewall_with(db, Policy)
    model = _model(db, sets[Policy], 'Policy')
    index, rule_id = _first_rule_index(model)
    model.set_action(index, PolicyAction.Accept)
    with db.session() as session:
        rule = session.get(Rule, rule_id)
        rule.options = {**(rule.options or {}), 'stateless': True}

    model.set_action(model.index_for_rule(rule_id), PolicyAction.Accept)

    with db.session() as session:
        assert session.get(Rule, rule_id).options.get('stateless') is True


def test_the_cluster_protocol_dialogs_refuse_unusable_values(qt_app):
    # An option key and a placeholder secret, not a credential.
    assert VRRPOptionsDialog({'vrrp_secret': ''}).validate()  # nosec B105
    # An option key and a placeholder secret, not a credential.
    assert VRRPOptionsDialog({'vrrp_secret': 'linuxfabrik'}).validate() == ''  # nosec B105
    assert ConntrackOptionsDialog({'conntrack_address': 'nonsense'}).validate()
    assert ConntrackOptionsDialog({'conntrack_address': '225.0.0.50'}).validate() == ''


def test_a_tag_is_simplified_and_has_no_comma():
    assert simplify_keyword('  a   b ') == 'a b'
    assert keyword_refusal('a,b')
    assert keyword_refusal('') and keyword_refusal('ok') == ''


def test_a_traffic_class_sets_the_classification_flag(qt_app):
    """RuleOptionsDialog::applyChanges derives the flag (RuleOptionsDialog.cpp:430)."""
    from firewallfabrik.gui.rule_options_dialog import RuleOptionsPanel

    db = _db()
    _fw, sets = _firewall_with(db, Policy)
    model = _model(db, sets[Policy], 'Policy')
    index, rule_id = _first_rule_index(model)
    panel = RuleOptionsPanel()
    panel.load_rule(model, index)

    panel.classify_str.setText('1:11')
    panel._save_options()

    with db.session() as session:
        options = session.get(Rule, rule_id).options or {}
        assert options.get('classify_str') == '1:11'
        assert options.get('classification') is True

    panel.classify_str.setText('')
    panel._save_options()
    with db.session() as session:
        assert not (session.get(Rule, rule_id).options or {}).get('classification')
