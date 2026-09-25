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

"""The interface type offered and saved follows Firewall Builder.

The lists come from ``res/os/linux24.xml`` as ``setInterfaceTypes``
(``libgui/platforms.cpp``) reads them, and a cluster interface is stored
as "cluster_interface" (``linux24IfaceOptsDialog.cpp``).  A sub-interface
of a bridge whose type turned from "unknown" into "ethernet" on save would
become a bridge port (``Interface::isBridgePort``).
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
from firewallfabrik.core.objects import Cluster, Firewall, Interface
from firewallfabrik.gui.iface_opts_dialog import IfaceOptsDialog


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _interface(options, parent_type=None, device_class=Firewall):
    iface = Interface(name='eth1', options=dict(options))
    if parent_type is None:
        iface.device = device_class(name='fw')
    else:
        iface.parent_interface = Interface(name='br0', options={'type': parent_type})
    return iface


def _offered(dlg):
    return [dlg.iface_type.itemData(i) for i in range(dlg.iface_type.count())]


@pytest.mark.parametrize(
    ('parent_type', 'offered'),
    [
        (None, ['ethernet', 'bridge', 'bonding']),
        ('', ['8021q', 'unknown']),
        ('ethernet', ['8021q', 'unknown']),
        ('bridge', ['ethernet', '8021q', 'unknown']),
        ('bonding', ['ethernet', '8021q', 'unknown']),
    ],
)
def test_the_types_offered_depend_on_the_parent(parent_type, offered):
    dlg = IfaceOptsDialog(_interface({}, parent_type))
    assert _offered(dlg) == offered


@pytest.mark.parametrize(
    ('parent_type', 'stored'),
    [
        ('bridge', 'unknown'),
        ('bonding', 'unknown'),
        ('bridge', '8021q'),
        # Not offered for a top-level interface, but what it says.
        (None, '8021q'),
    ],
)
def test_an_untouched_dialog_keeps_the_type(parent_type, stored):
    iface = _interface({'type': stored}, parent_type)
    IfaceOptsDialog(iface).accept()
    assert iface.options['type'] == stored


def test_no_type_under_a_bridge_stays_a_bridge_port():
    iface = _interface({}, 'bridge')
    IfaceOptsDialog(iface).accept()
    assert iface.options['type'] == 'ethernet'


def test_a_cluster_interface_hides_the_type_and_keeps_its_own():
    iface = _interface({'type': 'cluster_interface'}, device_class=Cluster)
    dlg = IfaceOptsDialog(iface)
    assert dlg.iface_type.isHidden()
    dlg.accept()
    assert iface.options['type'] == 'cluster_interface'


def test_a_line_wrapped_false_leaves_stp_off():
    iface = _interface({'type': 'bridge', 'enable_stp': '\n  False\n'})
    dlg = IfaceOptsDialog(iface)
    assert not dlg.enable_stp.isChecked()
