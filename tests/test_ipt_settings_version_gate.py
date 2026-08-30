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

"""The editor does not offer what the pinned iptables release has no option for.

Firewall Builder greys out and clears the same two checkboxes
(``iptAdvancedDialog::loadFWObject``), so its compiler never sees a setting
the tool cannot carry out.  The releases come from the netfilter tree:
``--kerneltz`` first ships in iptables 1.4.11 (``extensions/libxt_time.c``)
and the ``set`` match in 1.4.9 (``extensions/libxt_set.c``).
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


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _Firewall:
    def __init__(self, version):
        self.version = version
        self.options = {'use_kerneltz': True, 'use_m_set': True}
        self.name = 'fw-test'


def _dialog(version):
    return IptablesSettingsDialog(_Firewall(version))


@pytest.mark.parametrize(
    ('version', 'kerneltz', 'module_set'),
    [
        ('1.8.11', True, True),
        ('1.4.11', True, True),
        ('1.4.10', False, True),
        ('1.4.9', False, True),
        ('1.4.8', False, False),
        ('1.2.9', False, False),
    ],
)
def test_a_box_the_release_cannot_carry_out_is_off_and_greyed(
    version, kerneltz, module_set
):
    dlg = _dialog(version)
    assert dlg.useKernelTz.isEnabled() is kerneltz
    assert dlg.useModuleSet.isEnabled() is module_set
    # Firewall Builder clears the box as well, so a save does not write
    # back a setting the tool has no option for.
    assert dlg.useKernelTz.isChecked() is kerneltz
    assert dlg.useModuleSet.isChecked() is module_set


def test_a_firewall_with_no_release_pinned_keeps_both():
    """An empty version means the compiler default, which is current."""
    dlg = _dialog('')
    assert dlg.useKernelTz.isEnabled()
    assert dlg.useModuleSet.isEnabled()
    assert dlg.useKernelTz.isChecked()
    assert dlg.useModuleSet.isChecked()
