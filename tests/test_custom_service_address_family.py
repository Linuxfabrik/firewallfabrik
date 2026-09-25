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

"""The Custom Service editor keeps the address family the compilers read.

No family puts the service into the IPv4 and the IPv6 rules
(``DropRulesByAddressFamily``), so the editor offers that as a choice of
its own instead of turning it into IPv4 on save.
"""

import os
import socket

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
from firewallfabrik.core.objects import CustomService
from firewallfabrik.gui.custom_service_dialog import CustomServiceDialog


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize(
    ('family', 'button'),
    [(None, 'ipv4_and_ipv6'), (socket.AF_INET, 'ipv4'), (socket.AF_INET6, 'ipv6')],
)
def test_an_untouched_editor_keeps_the_family(family, button):
    svc = CustomService(
        name='linuxfabrik',
        codes={'iptables': '-m addrtype --dst-type LOCAL'},
        custom_address_family=family,
    )
    dlg = CustomServiceDialog()
    dlg.load_object(svc)
    assert getattr(dlg, button).isChecked()

    dlg.apply_all()
    assert svc.custom_address_family == family


def test_choosing_both_families_clears_the_family():
    svc = CustomService(name='linuxfabrik', custom_address_family=socket.AF_INET)
    dlg = CustomServiceDialog()
    dlg.load_object(svc)
    dlg.ipv4_and_ipv6.setChecked(True)
    dlg.apply_all()
    assert svc.custom_address_family is None
