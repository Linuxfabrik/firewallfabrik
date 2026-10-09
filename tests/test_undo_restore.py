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

"""Undo and redo put the database back, cluster groups included.

A cluster group references its interface or cluster, and devices and
interfaces reference groups, so the tables form a cycle that no order of
DROP TABLE resolves while SQLite enforces foreign keys.  Every undo
failed with "FOREIGN KEY constraint failed" from v3.0.0 on.
"""

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import ClusterGroup, Firewall

from .conftest import FIXTURES_DIR


def _load(name):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / name))
    return db


def _rename_first_firewall(db, name):
    with db.session('rename') as session:
        session.scalars(
            sqlalchemy.select(Firewall).order_by(Firewall.name)
        ).first().name = name


def _names(db):
    with db.session() as session:
        return sorted(fw.name for fw in session.scalars(sqlalchemy.select(Firewall)))


def _cluster_groups(db):
    with db.session() as session:
        return sorted(
            (group.name, group.interface_id, group.device_id)
            for group in session.scalars(sqlalchemy.select(ClusterGroup))
        )


def test_undo_and_redo_restore_a_file_with_cluster_groups():
    db = _load('cluster_nat_dynamic_failover.fwf')
    before, groups = _names(db), _cluster_groups(db)
    assert groups
    _rename_first_firewall(db, 'renamed')
    after = _names(db)

    assert db.undo()
    assert _names(db) == before
    assert _cluster_groups(db) == groups

    assert db.redo()
    assert _names(db) == after
    assert _cluster_groups(db) == groups


def test_foreign_keys_are_enforced_again_after_an_undo():
    db = _load('basic_accept_deny.fwf')
    _rename_first_firewall(db, 'renamed')

    assert db.undo()

    with db.engine.connect() as connection:
        assert connection.exec_driver_sql('PRAGMA foreign_keys').scalar() == 1
