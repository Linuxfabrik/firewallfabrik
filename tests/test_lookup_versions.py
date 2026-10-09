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

"""Tools > Lookup Versions of All Firewalls.

ssh is replaced by answers per address: one firewall logs in with a key,
one wants a password, one cannot be reached, one is locked.
"""

import os
from unittest import mock

import pytest

pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import sqlalchemy
from PySide6.QtWidgets import QApplication

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.gui import lookup_versions, version_lookup

from .conftest import FIXTURES_DIR

ROCKY_9 = version_lookup.Lookup(
    nftables='1.0.9',
    iptables='1.8.10',
    iptables_backend='nf_tables',
    kernel='5.14.0-427.el9.x86_64',
    os_release={'ID': 'rocky', 'VERSION_ID': '9.4', 'PRETTY_NAME': 'Rocky 9.4'},
)

# Firewall name: (address, platform, locked)
_SETUP = {
    'key': ('192.0.2.1', 'nftables', False),
    'locked': ('192.0.2.2', 'nftables', True),
    'password': ('192.0.2.3', 'iptables', False),
    'unreachable': ('192.0.2.4', 'nftables', False),
}


@pytest.fixture(scope='module')
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def db():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    with db.session() as session:
        firewalls = session.scalars(
            sqlalchemy.select(Firewall)
            .where(Firewall.type == 'Firewall')
            .order_by(Firewall.name)
        ).all()
        for fw, (name, (address, platform, locked)) in zip(
            firewalls, _SETUP.items(), strict=False
        ):
            fw.name = name
            fw.ro = locked
            fw.data = {**(fw.data or {}), 'platform': platform, 'version': ''}
            fw.options = {**(fw.options or {}), 'altAddress': address}
        # The rest of the fixture's firewalls are not part of the test, and
        # locked so nobody asks them.
        for fw in firewalls[len(_SETUP) :]:
            fw.ro = True
    return db


def _run(address, user, **kwargs):
    if address == '192.0.2.3' and not kwargs.get('password'):
        raise version_lookup.AuthenticationRequired('Permission denied')
    if address == '192.0.2.4':
        raise version_lookup.LookupFailed('no route to host')
    return ROCKY_9


def _versions(db):
    with db.session() as session:
        return {
            fw.name: (fw.data or {}).get('version', '')
            for fw in session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name.in_(_SETUP))
            )
        }


def _lookup(db, password, accept):
    window = mock.MagicMock(_db_manager=db)
    shown = []

    def choose(_parent, targets):
        shown.extend(targets)
        if not accept:
            return None
        return [target for target in targets if not target.remark]

    with (
        mock.patch.object(version_lookup, 'run', side_effect=_run),
        mock.patch.object(
            lookup_versions.QInputDialog,
            'getText',
            return_value=(password, bool(password)),
        ) as prompt,
        mock.patch.object(lookup_versions, '_choose', side_effect=choose),
        mock.patch.object(lookup_versions, 'QProgressDialog'),
    ):
        lookup_versions.QProgressDialog.return_value.wasCanceled.return_value = False
        changed = lookup_versions.lookup_all_versions(window)
    return changed, {target.name: target for target in shown}, prompt


def test_every_firewall_that_answers_gets_its_entry(qt_app, db):
    changed, shown, _prompt = _lookup(db, 'linuxfabrik', accept=True)

    assert changed
    assert _versions(db) == {
        'key': ROCKY_9.entry('nftables'),
        'locked': '',
        'password': ROCKY_9.entry('iptables'),
        'unreachable': '',
    }
    assert shown['locked'].remark == 'locked, not asked'
    assert shown['unreachable'].remark == 'not reachable: no route to host'


def test_only_the_firewall_that_wants_a_password_is_prompted(qt_app, db):
    _changed, _shown, prompt = _lookup(db, 'linuxfabrik', accept=True)

    assert prompt.call_count == 1
    assert prompt.call_args.args[2].startswith('password:')


def test_a_firewall_without_a_password_is_left_out(qt_app, db):
    _changed, shown, _prompt = _lookup(db, '', accept=True)

    assert shown['password'].remark == 'not asked, no password given'
    assert _versions(db)['password'] == ''
    assert _versions(db)['key'] == ROCKY_9.entry('nftables')


def test_cancel_changes_nothing(qt_app, db):
    changed, _shown, _prompt = _lookup(db, 'linuxfabrik', accept=False)

    assert not changed
    assert set(_versions(db).values()) == {''}


def test_all_entries_are_one_step_on_the_undo_stack(qt_app, db):
    before = len(db.get_history())

    _lookup(db, 'linuxfabrik', accept=True)

    history = db.get_history()
    assert len(history) == before + 1
    assert history[-1].description == 'Lookup versions of all firewalls'
