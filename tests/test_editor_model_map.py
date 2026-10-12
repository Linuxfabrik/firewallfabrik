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

"""Every object type that has an editor panel can be opened in it.

`EditorManager.open_object` answers a type that `_MODEL_MAP` does not
name by returning without a word, so a double click on the object did
nothing at all (#192: the failover group of a cluster).  Firewall Builder
registers one dialog per type in `ObjectEditor`; the type has to be
reachable here the same way.
"""

import os
import re
from pathlib import Path

import pytest
import sqlalchemy

pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import firewallfabrik.core
from firewallfabrik.core.objects import FailoverClusterGroup, StateSyncClusterGroup
from firewallfabrik.gui.editor_manager import _MODEL_MAP

GUI = Path(__file__).resolve().parent.parent / 'src' / 'firewallfabrik' / 'gui'


def _editor_types():
    """The types main_window.py hands an editor panel to."""
    source = (GUI / 'main_window.py').read_text(encoding='utf-8')
    block = source[source.index('editor_map = {') :]
    block = block[: block.index('}')]
    return set(re.findall(r"'(\w+)':", block))


def test_every_type_with_an_editor_has_a_model_class():
    assert _editor_types() - set(_MODEL_MAP) == set()


@pytest.mark.parametrize('cls', [FailoverClusterGroup, StateSyncClusterGroup])
def test_cluster_groups_load_through_the_model_class(cls):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load('tests/fixtures/cluster-tests.fwb')
    with dm.session() as session:
        group = session.scalars(sqlalchemy.select(cls)).first()
        assert group is not None
        loaded = session.get(_MODEL_MAP[group.type], group.id)
        assert loaded is group
