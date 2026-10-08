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

"""A group keeps the order of its members through a save and a reload.

Firewall Builder keeps the order of a group's children, and the group
editor lists them in it.  The data file wrote the members sorted by path
and read them back without a position, so the order a group showed
changed with every save.
"""

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Group

from .conftest import FIXTURES_DIR


def _orders(db):
    with db.session() as session:
        result = {}
        for group in session.scalars(sqlalchemy.select(Group)):
            names = [m.name for m in group.get_member_objects()]
            if names:
                result.setdefault((group.library.name, group.name), []).append(names)
        return result


def test_the_member_order_survives_a_save(tmp_path):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    before = _orders(db)
    assert before

    out = tmp_path / 'saved.fwf'
    db.save(str(out))
    again = firewallfabrik.core.DatabaseManager()
    again.load(str(out))

    assert _orders(again) == before
