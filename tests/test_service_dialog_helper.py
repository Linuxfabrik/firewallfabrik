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

"""The connection tracking helper of the TCP and UDP service editors."""

import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

import firewallfabrik.gui.ui_loader  # noqa: F401
from firewallfabrik.gui.service_dialogs import (
    TCPServiceDialog,
    UDPServiceDialog,
)


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _Service:
    def __init__(self, data):
        self.name = 'svc'
        self.data = dict(data)
        self.src_range_start = self.src_range_end = 0
        self.dst_range_start = self.dst_range_end = 21
        self.tcp_flags = {}
        self.tcp_flags_masks = {}


def _dialog(cls, data):
    dialog = cls()
    dialog._obj = _Service(data)
    dialog._populate()
    return dialog


@pytest.mark.parametrize(
    ('cls', 'helper', 'absent'),
    [(TCPServiceDialog, 'ftp', 'tftp'), (UDPServiceDialog, 'tftp', 'ftp')],
)
def test_the_editor_offers_the_helpers_of_its_protocol(cls, helper, absent):
    dialog = _dialog(cls, {'conntrack_helper': helper})
    items = [
        dialog.conntrack_helper.itemData(i)
        for i in range(dialog.conntrack_helper.count())
    ]
    assert dialog.conntrack_helper.currentData() == helper
    assert absent not in items


@pytest.mark.parametrize('cls', [TCPServiceDialog, UDPServiceDialog])
def test_none_removes_the_key(cls):
    dialog = _dialog(cls, {'conntrack_helper': 'sip'})
    dialog.conntrack_helper.setCurrentIndex(0)
    dialog._apply_changes()
    assert 'conntrack_helper' not in dialog._obj.data


def test_a_value_the_editor_does_not_know_survives_a_save():
    """Written by hand or by another tool; the compiler reports it."""
    dialog = _dialog(UDPServiceDialog, {'conntrack_helper': 'something-else'})
    dialog._apply_changes()
    assert dialog._obj.data['conntrack_helper'] == 'something-else'
