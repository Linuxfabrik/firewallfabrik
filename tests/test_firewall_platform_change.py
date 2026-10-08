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

"""A platform change forgets the compiler of the old platform, and nothing else.

The compile dialog runs the "compiler" option instead of `fwf-ipt` /
`fwf-nft`, so a path kept across a switch to nftables compiled the firewall
with the iptables compiler.  `FirewallDialog::applyChanges` clears the
option on a platform change; it also writes the new platform's defaults
over its options, which fwf leaves out because the options of iptables and
nftables mean the same.
"""

import os
from unittest import mock

import pytest

pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import sqlalchemy
from PySide6.QtWidgets import QApplication, QLabel

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.gui.device_dialogs import FirewallDialog
from firewallfabrik.gui.editor_manager import EditorManager

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def qt_app():
    return QApplication.instance() or QApplication([])


def _firewall_with_options(options):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    with db.session() as session:
        fw = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.type == 'Firewall')
        ).first()
        fw.data = {**(fw.data or {}), 'platform': 'iptables'}
        fw.options = {**(fw.options or {}), **options}
        return db, fw.id


def _switch_platform(db, fw_id, platform):
    dialog = FirewallDialog()
    manager = EditorManager(db, {'Firewall': dialog}, mock.MagicMock(), QLabel())
    manager.open_object(str(fw_id), 'Firewall')
    dialog.platform.setCurrentText(platform)
    manager.on_editor_changed()
    with db.session() as session:
        fw = session.get(Firewall, fw_id)
        return fw.data['platform'], dict(fw.options or {})


def test_a_platform_change_clears_the_compiler_path(qt_app):
    db, fw_id = _firewall_with_options({'compiler': '/usr/local/bin/fwf-ipt'})

    platform, options = _switch_platform(db, fw_id, 'nftables')

    assert platform == 'nftables'
    assert options['compiler'] == ''


def test_a_platform_change_keeps_the_other_options(qt_app):
    db, fw_id = _firewall_with_options(
        {'cmdline': '--verbose', 'log_prefix': 'FW %N '},
    )

    _platform, options = _switch_platform(db, fw_id, 'nftables')

    assert options['cmdline'] == '--verbose'
    assert options['log_prefix'] == 'FW %N '


def test_the_compiler_path_stays_while_the_platform_does(qt_app):
    db, fw_id = _firewall_with_options({'compiler': '/usr/local/bin/fwf-ipt'})

    _platform, options = _switch_platform(db, fw_id, 'iptables')

    assert options['compiler'] == '/usr/local/bin/fwf-ipt'
