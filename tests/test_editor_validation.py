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

"""The editor asks a dialog's ``validate`` before it saves anything.

``ObjectEditor::changed`` asks ``validate`` and reloads the editor when
the answer is no (fwbuilder5 ObjectEditor.cpp:331).  The port checked
nothing before saving: a blank name was stored, an address range was
renamed although its end address was refused, and a duplicate name raised
an exception outside the handler that left every later edit failing.
"""

import uuid
from unittest import mock

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import (
    AddressRange,
    Firewall,
    Group,
    Interface,
    IPv4,
    Library,
    Policy,
)

pytest.importorskip('PySide6')

from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

from firewallfabrik.gui.address_dialogs import AddressRangeDialog, IPv4Dialog
from firewallfabrik.gui.device_dialogs import FirewallDialog, InterfaceDialog
from firewallfabrik.gui.editor_manager import EditorManager
from firewallfabrik.gui.ruleset_dialog import RuleSetDialog

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def messages(monkeypatch):
    seen = []

    def record(*args, **_kwargs):
        seen.append(args[2] if len(args) > 2 else '')
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, 'critical', staticmethod(record))
    monkeypatch.setattr(QMessageBox, 'warning', staticmethod(record))
    return seen


def _db():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    return db


def _two_addresses(db):
    with db.session() as session:
        lib = next(
            lib for lib in session.scalars(sqlalchemy.select(Library)) if not lib.ro
        )
        group = next(
            g
            for g in session.scalars(
                sqlalchemy.select(Group).where(Group.library_id == lib.id)
            )
            if g.name == 'Addresses'
        )
        ids = []
        for name, address in (('src', '192.0.2.2'), ('taken', '192.0.2.1')):
            obj = IPv4(
                id=uuid.uuid4(),
                name=name,
                group_id=group.id,
                library_id=lib.id,
                inet_addr_mask={'address': address, 'netmask': ''},
            )
            session.add(obj)
            ids.append(obj.id)
        return ids


def _editor(db, dialog, obj_type, obj_id):
    manager = EditorManager(db, {obj_type: dialog}, mock.MagicMock(), QLabel())
    manager.open_object(str(obj_id), obj_type)
    return manager


def _stored_name(db, cls, obj_id):
    with db.session() as session:
        return session.get(cls, obj_id).name


def test_a_duplicate_name_is_refused_and_the_editor_keeps_working(qt_app, messages):
    db = _db()
    src, _taken = _two_addresses(db)
    dialog = IPv4Dialog()
    manager = _editor(db, dialog, 'IPv4', src)

    dialog.obj_name.setText('taken')
    manager.on_editor_changed()

    assert any('Duplicate names' in m for m in messages)
    assert dialog.obj_name.text() == 'src', 'the editor shows what is stored'
    assert _stored_name(db, IPv4, src) == 'src'

    dialog.obj_name.setText('renamed')
    manager.on_editor_changed()
    assert _stored_name(db, IPv4, src) == 'renamed', 'and the next edit works'


def test_a_blank_name_is_refused(qt_app, messages):
    db = _db()
    src, _taken = _two_addresses(db)
    dialog = IPv4Dialog()
    manager = _editor(db, dialog, 'IPv4', src)

    dialog.obj_name.setText('   ')
    manager.on_editor_changed()

    assert 'Object name should not be blank' in messages
    assert _stored_name(db, IPv4, src) == 'src'


def test_a_refused_range_keeps_its_name(qt_app, messages):
    db = _db()
    with db.session() as session:
        lib = next(
            lib for lib in session.scalars(sqlalchemy.select(Library)) if not lib.ro
        )
        rng = AddressRange(
            id=uuid.uuid4(),
            name='range',
            library_id=lib.id,
            start_address={'address': '192.0.2.1'},
            end_address={'address': '192.0.2.9'},
        )
        session.add(rng)
        rng_id = rng.id
    dialog = AddressRangeDialog()
    manager = _editor(db, dialog, 'AddressRange', rng_id)

    dialog.obj_name.setText('renamed')
    dialog.rangeEnd.setText('not-an-address')
    manager.on_editor_changed()

    assert _stored_name(db, AddressRange, rng_id) == 'range'


def test_a_rule_set_name_takes_the_allowed_characters_only(qt_app):
    dialog = RuleSetDialog()
    dialog._obj = Policy(name='Policy')
    for name, ok in (('Policy_1', True), ('a:b', False), ('has space', False)):
        dialog.obj_name.setText(name)
        assert (dialog.validate() == '') is ok, name


def test_a_firewall_name_has_no_slash(qt_app):
    dialog = FirewallDialog()
    dialog.obj_name.setText('fw/1')
    assert 'not allowed' in dialog.validate()


def test_an_interface_name_is_checked_against_its_place(qt_app):
    db = _db()
    with db.session() as session:
        fw = session.scalars(sqlalchemy.select(Firewall)).first()
        iface = Interface(id=uuid.uuid4(), name='eth9', device_id=fw.id)
        session.add(iface)
        session.flush()
        dialog = InterfaceDialog()
        dialog._obj = iface
        dialog.obj_name.setText('eth 9')
        assert dialog.validate()
        dialog.obj_name.setText('eth0.100')
        assert dialog.validate(), 'a VLAN at the top level of a firewall'
        dialog.obj_name.setText('eth9')
        assert dialog.validate() == ''
