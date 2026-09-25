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

"""The Rule Options panel shows and keeps what a policy rule stores.

The panel saves every widget whenever one of them changes, so a value it
cannot show is lost on the next unrelated edit.  The references are Firewall
Builder's ``RuleOptionsDialog.cpp``: ``fillInterfaces`` for the interface
combos, ``hashlimit_mode_<mode>`` for the rate-limit keys, and the v3
migration of "assume fw is part of any".
"""

import os

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import sqlalchemy

# The loader registers the dialog modules at import time, so it has to be
# imported first: reaching for the dialog module directly is a circular
# import through `device_dialogs`.
import firewallfabrik.gui.ui_loader  # noqa: F401
from firewallfabrik.core.objects import Policy, PolicyRule
from firewallfabrik.gui.rule_options_dialog import RuleOptionsPanel
from tests.conftest import FIXTURES_DIR, _get_db


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _Row:
    def __init__(self, rule_id):
        self.rule_id = rule_id


class _Model:
    """The part of ``PolicyTreeModel`` the panel talks to."""

    def __init__(self, db_manager, rule_set_id, rule_id):
        self._db_manager = db_manager
        self.rule_set_id = rule_set_id
        self._rule_id = rule_id
        self.saved = None

    def get_row_data(self, index):
        return _Row(self._rule_id)

    def index_for_rule(self, rule_id):
        return object()

    def set_options(self, index, options):
        self.saved = options


def _panel(options):
    db = _get_db(FIXTURES_DIR / 'basic_accept_deny.fwf')
    with db.session() as session:
        rule = session.scalars(
            sqlalchemy.select(PolicyRule).join(
                Policy, PolicyRule.rule_set_id == Policy.id
            )
        ).first()
        rule.options = dict(options)
        interfaces = sorted(
            iface.name
            for iface in rule.rule_set.device.interfaces
            if not iface.is_loopback()
        )
        model = _Model(db, rule.rule_set_id, rule.id)
        session.commit()
    panel = RuleOptionsPanel()
    panel.load_rule(model, object())
    return panel, model, interfaces


def _edit_something_else(panel):
    # Any edit saves every widget.
    panel.ipt_logPrefix.setText('linuxfabrik ')
    panel.ipt_logPrefix.editingFinished.emit()


def test_the_interface_combos_offer_the_firewall_interfaces():
    panel, _model, interfaces = _panel({})
    assert interfaces
    for combo in (panel.ipt_iif, panel.ipt_oif):
        items = [combo.itemText(i) for i in range(combo.count())]
        assert items == ['', *interfaces]


def test_a_stored_interface_survives_an_unrelated_edit():
    *_unused, interfaces = _panel({})
    # The second one is not an interface of this firewall, but it is what
    # the rule says.
    panel, model, _interfaces = _panel({'ipt_iif': interfaces[0], 'ipt_oif': 'x'})
    assert panel.ipt_iif.currentText() == interfaces[0]
    assert panel.ipt_oif.currentText() == 'x'
    _edit_something_else(panel)
    assert model.saved['ipt_iif'] == interfaces[0]
    assert model.saved['ipt_oif'] == 'x'


@pytest.mark.parametrize(
    ('options', 'checked'),
    [
        ({'hashlimit_mode_srcip': True}, {'cb_srcip'}),
        ({'hashlimit_dstport': True}, {'cb_dstport'}),
        ({'hashlimit_mode': 'srcip,dstport'}, {'cb_srcip', 'cb_dstport'}),
        # The v2.1 string overrides the booleans in the compilers.
        ({'hashlimit_mode': 'dstip', 'hashlimit_mode_srcip': True}, {'cb_dstip'}),
    ],
)
def test_the_hashlimit_boxes_show_what_the_compilers_read(options, checked):
    panel, model, _interfaces = _panel(options)
    boxes = ('cb_dstip', 'cb_dstport', 'cb_srcip', 'cb_srcport')
    assert {name for name in boxes if getattr(panel, name).isChecked()} == checked

    _edit_something_else(panel)
    assert 'hashlimit_mode' not in model.saved
    assert {key for key in model.saved if key.startswith('hashlimit_')} == {
        f'hashlimit_mode_{name[3:]}' for name in checked
    }


def test_unticking_a_hashlimit_box_takes_the_mode_out():
    panel, model, _interfaces = _panel({'hashlimit_mode': 'srcip'})
    panel.cb_srcip.setChecked(False)
    assert not any(key.startswith('hashlimit_') for key in model.saved)


@pytest.mark.parametrize(
    ('stored', 'index', 'saved'),
    [
        (True, 1, '1'),
        ('True', 1, '1'),
        (False, 0, None),
        ('1', 1, '1'),
        ('0', 2, '0'),
    ],
)
def test_the_old_fw_part_of_any_checkbox_value_is_migrated(stored, index, saved):
    key = 'firewall_is_part_of_any_and_networks'
    panel, model, _interfaces = _panel({key: stored})
    assert panel.ipt_assume_fw_is_part_of_any.currentIndex() == index
    _edit_something_else(panel)
    assert model.saved.get(key) == saved
