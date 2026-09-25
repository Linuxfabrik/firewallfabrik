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

"""The platform and host OS settings dialogs keep what the firewall stores.

Firewall Builder maps "Accept TCP sessions opened prior to firewall
restart" 1:1 to ``accept_new_tcp_with_no_syn`` (``iptAdvancedDialog.cpp``)
and offers an empty entry first in the reject and limit-suffix lists
(``actionsOnReject`` / ``limitSuffixes`` in ``libgui/platforms.cpp``), so
opening the dialog and clicking OK changes nothing.  Its host OS dialog
stores the Data directory as ``data_dir`` (``linux24AdvancedDialog.cpp``).
"""

import os

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

# The loader registers the dialog modules at import time, so it has to be
# imported first: reaching for the dialog module directly is a circular
# import through `device_dialogs`.
import firewallfabrik.gui.ui_loader  # noqa: F401
from firewallfabrik.gui.iptables_settings_dialog import IptablesSettingsDialog
from firewallfabrik.gui.linux_settings_dialog import LinuxSettingsDialog
from firewallfabrik.gui.nftables_settings_dialog import NftablesSettingsDialog

_DIALOGS = [IptablesSettingsDialog, NftablesSettingsDialog]


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _Firewall:
    def __init__(self, options):
        self.name = 'fw-test'
        self.options = dict(options)
        self.version = ''


@pytest.mark.parametrize('dialog_class', _DIALOGS)
@pytest.mark.parametrize('accept', [True, False])
def test_accept_sessions_box_shows_the_stored_option(dialog_class, accept):
    fw = _Firewall({'accept_new_tcp_with_no_syn': accept})
    dlg = dialog_class(fw)
    assert dlg.acceptSessions.isChecked() is accept

    dlg.acceptSessions.setChecked(not accept)
    dlg.accept()
    assert fw.options['accept_new_tcp_with_no_syn'] is (not accept)


@pytest.mark.parametrize('dialog_class', _DIALOGS)
@pytest.mark.parametrize(
    'options',
    [
        {'action_on_reject': '', 'limit_suffix': '', 'log_level': ''},
        {
            'action_on_reject': 'TCP RST',
            'limit_suffix': '/minute',
            'log_level': 'warning',
        },
        # Not offered in the lists, but a hand-written or imported file
        # can carry it; an untouched dialog must not replace it.
        {'action_on_reject': 'ICMP unreachable', 'limit_suffix': '/sec'},
    ],
)
def test_an_untouched_dialog_keeps_the_combo_options(dialog_class, options):
    fw = _Firewall(options)
    dialog_class(fw).accept()
    for key, value in options.items():
        assert fw.options[key] == value


def test_the_linux_dialog_takes_over_fwbuilders_data_dir_key():
    fw = _Firewall({'data_dir': '/etc/fw'})
    dlg = LinuxSettingsDialog(fw, platform='iptables')
    assert dlg.linux24_data_dir.text() == '/etc/fw'
    dlg.accept()
    assert fw.options['linux24_data_dir'] == '/etc/fw'
    assert 'data_dir' not in fw.options


@pytest.mark.parametrize('dialog_class', _DIALOGS)
@pytest.mark.parametrize(('stored', 'checked'), [('\n  True\n', True), ('1', True)])
def test_a_checkbox_reads_what_the_compiler_reads(dialog_class, stored, checked):
    """Firewall Builder writes a value on a line of its own as well."""
    fw = _Firewall({'drop_invalid': stored})
    dlg = dialog_class(fw)
    assert dlg.dropInvalid.isChecked() is checked
    dlg.accept()
    assert fw.options['drop_invalid'] is checked
