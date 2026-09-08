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

"""The editor half of the per-platform Custom action (issue #161).

The action panel keeps one statement per packet filter while it is open,
the way the Custom Service editor keeps one code per platform, so
switching the combo does not lose the half that is no longer shown.  A
rule imported from Firewall Builder carries one platform-less statement,
which is read into the half whose syntax it is in - otherwise the first
save from this panel would drop it.
"""

import os

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from firewallfabrik.core.objects import PolicyAction

IPT_STATEMENT = '-j TCPMSS --set-mss 1400'
NFT_STATEMENT = 'tcp option maxseg size set 1400'


@pytest.fixture(scope='module')
def qt_app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _RowData:
    def __init__(self):
        self.action_int = PolicyAction.Custom
        self.nat_action_int = 0
        self.rule_id = None


class _Model:
    """Stands in for the rule-set model, which is all the panel asks."""

    rule_set_type = 'Policy'
    rule_set_id = None

    def __init__(self):
        self.saved = None

    def set_options(self, _index, options):
        self.saved = options

    def index_for_rule(self, _rule_id):
        return object()


def _panel(qt_app, options):
    from firewallfabrik.gui import ui_loader

    panel = ui_loader.CUSTOM_WIDGET_MAP['ActionsDialog']()
    panel._model = _Model()
    panel._index = object()
    panel._get_row_data = _RowData
    panel._read_rule_options = lambda: dict(options)
    panel._load_options()
    # `load_rule` is what wires the widgets in the running application;
    # without it the combo changes nothing and the test proves nothing.
    panel._connect_signals()
    return panel


def test_the_page_offers_both_packet_filters(qt_app):
    panel = _panel(qt_app, {})
    offered = {
        panel.custom_str_platform.itemData(i)
        for i in range(panel.custom_str_platform.count())
    }
    assert offered == {'iptables', 'nftables'}


def test_switching_the_combo_shows_the_other_statement(qt_app):
    panel = _panel(
        qt_app,
        {
            'custom_str_iptables': IPT_STATEMENT,
            'custom_str_nftables': NFT_STATEMENT,
        },
    )
    for platform, statement in (
        ('iptables', IPT_STATEMENT),
        ('nftables', NFT_STATEMENT),
    ):
        panel.custom_str_platform.setCurrentIndex(
            panel.custom_str_platform.findData(platform)
        )
        assert panel.custom_str.text() == statement


def test_editing_one_half_leaves_the_other_alone(qt_app):
    panel = _panel(
        qt_app,
        {
            'custom_str_iptables': IPT_STATEMENT,
            'custom_str_nftables': NFT_STATEMENT,
        },
    )
    panel.custom_str_platform.setCurrentIndex(
        panel.custom_str_platform.findData('nftables')
    )
    panel.custom_str.setText('tcp option maxseg size set 1300')
    panel._save_options()

    saved = panel._model.saved
    assert saved['custom_str_nftables'] == 'tcp option maxseg size set 1300'
    assert saved['custom_str_iptables'] == IPT_STATEMENT


def test_a_statement_imported_from_firewall_builder_reaches_its_own_half(qt_app):
    """It says iptables by its first character and nothing else says so."""
    panel = _panel(qt_app, {'custom_str': IPT_STATEMENT})
    panel.custom_str_platform.setCurrentIndex(
        panel.custom_str_platform.findData('iptables')
    )
    assert panel.custom_str.text() == IPT_STATEMENT

    panel.custom_str_platform.setCurrentIndex(
        panel.custom_str_platform.findData('nftables')
    )
    assert panel.custom_str.text() == ''


def test_saving_such_a_rule_keeps_the_statement_and_drops_the_old_key(qt_app):
    """Keeping both would leave two answers to one question behind."""
    panel = _panel(qt_app, {'custom_str': IPT_STATEMENT})
    panel._save_options()

    saved = panel._model.saved
    assert saved['custom_str_iptables'] == IPT_STATEMENT
    assert 'custom_str' not in saved
    assert 'custom_str_nftables' not in saved
