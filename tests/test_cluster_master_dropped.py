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

"""A cluster no longer names a master member.

Firewall Builder records which member is master (``master_iface`` on a
cluster group), and only its PIX, pf and secuwall configurators read it.
fwf wrote the same idea as ``master_fw_id`` and ``member_fw_ids`` onto a
cluster.  All three hold object ids, which do not survive a save and a
load, so reading either format drops them.
"""

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Group

_FIXTURE = 'tests/fixtures/cluster-tests.fwb'
_OBSOLETE = {'master_fw_id', 'master_iface', 'member_fw_ids'}


def _obsolete_keys_left(dm):
    with dm.session() as session:
        found = set()
        for obj in session.scalars(sqlalchemy.select(Group)):
            found |= _OBSOLETE & set(obj.data or {})
        for obj in session.scalars(sqlalchemy.select(Cluster)):
            found |= _OBSOLETE & set(obj.data or {})
        return found


def test_fwb_import_drops_master_iface():
    dm = firewallfabrik.core.DatabaseManager()
    dm.load(_FIXTURE)
    assert _obsolete_keys_left(dm) == set()


def test_fwf_load_drops_the_obsolete_keys(tmp_path):
    dm = firewallfabrik.core.DatabaseManager()
    dm.load(_FIXTURE)
    with dm.session() as session:
        cluster = session.scalars(sqlalchemy.select(Cluster)).first()
        cluster.data = {
            **(cluster.data or {}),
            'master_fw_id': 'linuxfabrik',
            'member_fw_ids': ['linuxfabrik'],
        }
        group = cluster.child_groups[0]
        group.data = {**(group.data or {}), 'master_iface': 'linuxfabrik'}
    path = tmp_path / 'cluster.fwf'
    dm.save(str(path))
    assert 'master_fw_id' in path.read_text()

    reloaded = firewallfabrik.core.DatabaseManager()
    reloaded.load(str(path))
    assert _obsolete_keys_left(reloaded) == set()
