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

"""What the cluster editors show, and which cluster they are looking at.

The member list is checked against the platform and the host OS of the
cluster the group belongs to, and rows that do not match are marked
"Invalid".  Finding that cluster by taking the first one in the library
gives the wrong answer on every file that holds two, which the reference
fixture does.
"""

import os

import pytest
import sqlalchemy

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Cluster,
    FailoverClusterGroup,
    StateSyncClusterGroup,
)

FIXTURE = 'tests/fixtures/cluster-tests.fwb'


@pytest.fixture(scope='module')
def editor():
    """The real editor panel, reached the way the loader registers it."""
    from PySide6.QtWidgets import QApplication

    from firewallfabrik.gui import ui_loader

    QApplication.instance() or QApplication([])
    return ui_loader.CUSTOM_WIDGET_MAP['ClusterGroupDialog']


@pytest.fixture(scope='module')
def database():
    """The reference clusters, each with its name written into its data.

    Every cluster of the fixture runs iptables on linux24, so the two
    settings the editor reads cannot tell them apart on their own and a
    wrong lookup would go unnoticed.  The marker makes the answer name
    the cluster it came from.
    """
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(FIXTURE)
    with dm.session() as session:
        for cluster in session.scalars(sqlalchemy.select(Cluster)).all():
            cluster.data = {**(cluster.data or {}), 'test_marker': cluster.name}
        session.commit()
    return dm


def test_the_fixture_holds_more_than_one_cluster(database):
    """Otherwise the old lookup would have been right by accident."""
    with database.session() as session:
        clusters = session.scalars(sqlalchemy.select(Cluster)).all()
    assert len(clusters) > 1


def test_a_failover_group_finds_the_cluster_of_its_interface(editor, database):
    panel = editor()
    panel.set_db_manager(database)
    with database.session() as session:
        cluster = session.scalars(
            sqlalchemy.select(Cluster).where(Cluster.name == 'vrrp_cluster_2'),
        ).one()
        eth0 = next(i for i in cluster.interfaces if i.name == 'eth0')
        group = eth0.get_failover_group()
        assert isinstance(group, FailoverClusterGroup)

        found = panel._parent_cluster_data(group)

    assert found.get('test_marker') == 'vrrp_cluster_2'
    assert found.get('platform') == 'iptables'


def test_a_state_sync_group_finds_the_cluster_it_hangs_under(editor, database):
    panel = editor()
    panel.set_db_manager(database)
    with database.session() as session:
        cluster = session.scalars(
            sqlalchemy.select(Cluster).where(Cluster.name == 'heartbeat_cluster_2'),
        ).one()
        group = next(
            g for g in cluster.child_groups if isinstance(g, StateSyncClusterGroup)
        )

        found = panel._parent_cluster_data(group)

    assert found.get('test_marker') == 'heartbeat_cluster_2'


def test_the_settings_alone_do_not_tell_the_clusters_apart(database):
    """Which is why the two tests above assert on the marker."""
    with database.session() as session:
        settings = {
            (
                (cluster.data or {}).get('platform'),
                (cluster.data or {}).get('host_OS'),
            )
            for cluster in session.scalars(sqlalchemy.select(Cluster)).all()
        }
    assert len(settings) == 1


def test_a_cluster_has_a_panel_of_its_own():
    """It used to be edited with the firewall's, release combo and all."""
    from firewallfabrik.gui import ui_loader

    cluster_panel = ui_loader.CUSTOM_WIDGET_MAP['ClusterDialog']
    firewall_panel = ui_loader.CUSTOM_WIDGET_MAP['FirewallDialog']

    assert cluster_panel is not firewall_panel


def test_the_cluster_panel_offers_no_release(editor):
    """A member compiles for the release it names itself.

    Firewall Builder writes only `platform` and `host_OS` onto a cluster
    and its panel has no version combo; neither compiler reads one there,
    so a combo would show a setting that changes nothing.
    """
    from firewallfabrik.gui import ui_loader

    panel = ui_loader.CUSTOM_WIDGET_MAP['ClusterDialog']()

    assert panel.version is None
    assert panel.platform is not None
    assert panel.hostOS is not None
    assert panel.inactive.text() == 'Inactive cluster'


def test_the_firewall_panel_still_offers_one(editor):
    from firewallfabrik.gui import ui_loader

    panel = ui_loader.CUSTOM_WIDGET_MAP['FirewallDialog']()

    assert panel.version is not None


def test_a_new_cluster_is_created_without_a_release():
    """`newClusterDialog_create.cpp` sets platform and host OS, nothing else."""
    import inspect

    from firewallfabrik.gui import new_cluster_dialog

    source = inspect.getsource(new_cluster_dialog.NewClusterDialog.get_result)

    assert "'platform'" in source
    assert "'host_OS'" in source
    assert "'version'" not in source
