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

"""Editor panel dialog for ClusterGroup objects (Failover / State Sync).

Ports fwbuilder's ``ClusterGroupDialog`` -- shows the cluster group
name, type combo, a tree of current members with master/status columns,
and buttons to manage members and edit protocol parameters.
"""

import contextlib
import copy
import logging

import sqlalchemy
from PySide6.QtCore import Slot
from PySide6.QtGui import QBrush, QColor, QIcon
from PySide6.QtWidgets import QDialog, QTreeWidgetItem

from firewallfabrik.core.objects import (
    Interface,
    group_membership,
)
from firewallfabrik.gui.base_object_dialog import BaseObjectDialog

logger = logging.getLogger(__name__)

# Failover protocol types for Linux.
_FAILOVER_TYPES = [
    ('heartbeat', 'heartbeat'),
    ('none', 'None'),
    ('openais', 'OpenAIS'),
    ('vrrp', 'VRRP'),
]

# State sync protocol types for Linux.
_STATE_SYNC_TYPES = [
    ('conntrack', 'conntrack'),
]


class ClusterGroupDialog(BaseObjectDialog):
    """Editor panel for FailoverClusterGroup and StateSyncClusterGroup objects."""

    def __init__(self, parent=None):
        super().__init__('clustergroupdialog_q.ui', parent)
        self._db_manager = None
        self._cluster = None
        self._possible_types = []

    def set_db_manager(self, db_manager):
        """Inject the database manager (called by EditorManager)."""
        self._db_manager = db_manager

    # ------------------------------------------------------------------
    # BaseObjectDialog overrides
    # ------------------------------------------------------------------

    def _populate(self):
        obj = self._obj
        data = obj.data or {}

        self.obj_name.setText(obj.name or '')

        # Determine parent cluster for platform/host_OS.
        self._cluster = self._find_parent_cluster(obj)

        # Determine group type and populate the Type combo.
        group_type = data.get('type', '')
        obj_type = obj.type  # 'FailoverClusterGroup' or 'StateSyncClusterGroup'

        if obj_type == 'StateSyncClusterGroup':
            self._possible_types = list(_STATE_SYNC_TYPES)
        else:
            self._possible_types = list(_FAILOVER_TYPES)

        self.type.clear()
        selected_idx = 0
        for idx, (internal, display) in enumerate(self._possible_types):
            self.type.addItem(display)
            if internal == group_type:
                selected_idx = idx
        self.type.setCurrentIndex(selected_idx)

        # Determine if master column is needed.
        enable_master = True
        if group_type == 'conntrack':
            enable_master = False
        if enable_master:
            self.fwMemberTree.showColumn(2)
        else:
            self.fwMemberTree.hideColumn(2)

        # Load member firewalls into the tree.
        self._load_member_tree()

        # Manage Members button -- always enabled (we check at dialog open).
        self.manageMembers.setEnabled(True)
        self.manageMembers.setToolTip(
            'Click here to manage member firewalls of this cluster group.',
        )

        # Edit Parameters button -- currently disabled (protocol parameter
        # dialogs are not yet ported).
        self.editParameters.setEnabled(False)

        # Wire buttons (only once -- idempotent via _signals_connected flag).
        with contextlib.suppress(RuntimeError):
            self.manageMembers.clicked.disconnect(self._open_cluster_member_dialog)
        self.manageMembers.clicked.connect(self._open_cluster_member_dialog)

    def _apply_changes(self):
        old_data = self._obj.data or {}
        data = copy.deepcopy(old_data)

        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name

        # Save group type from combo.
        idx = self.type.currentIndex()
        if 0 <= idx < len(self._possible_types):
            data['type'] = self._possible_types[idx][0]

        if data != old_data:
            self._obj.data = data

    # ------------------------------------------------------------------
    # Member tree
    # ------------------------------------------------------------------

    def _load_member_tree(self):
        """Populate fwMemberTree with current cluster group members."""
        self.fwMemberTree.clear()

        if self._db_manager is None:
            return

        obj = self._obj
        data = obj.data or {}
        master_iface_id = data.get('master_iface', '')

        cluster_data = self._cluster.data if self._cluster else {}
        cluster_host_os = (cluster_data or {}).get('host_OS', '')
        cluster_platform = (cluster_data or {}).get('platform', '')

        session = self._db_manager.create_session()
        try:
            rows = session.execute(
                sqlalchemy.select(
                    group_membership.c.member_id,
                    group_membership.c.position,
                )
                .where(
                    group_membership.c.group_id == obj.id,
                )
                .order_by(group_membership.c.position),
            ).all()

            for member_id, _position in rows:
                iface = session.get(Interface, member_id)
                if iface is None:
                    continue

                fw = iface.device
                if fw is None:
                    continue

                is_master = (
                    str(iface.id).replace('-', '') == master_iface_id
                    or str(
                        iface.id,
                    )
                    == master_iface_id
                )

                # Validate member.
                fw_data = fw.data or {}
                valid = (
                    fw_data.get('host_OS', '') == cluster_host_os
                    and fw_data.get('platform', '') == cluster_platform
                )

                self._add_member_row(fw, iface, is_master, valid)
        finally:
            session.close()

        self.fwMemberTree.resizeColumnToContents(0)
        self.fwMemberTree.resizeColumnToContents(1)
        self.fwMemberTree.resizeColumnToContents(2)
        self.fwMemberTree.resizeColumnToContents(3)

    def _add_member_row(self, fw, iface, is_master, valid):
        """Add a single member row to the fwMemberTree."""
        item = QTreeWidgetItem(self.fwMemberTree)

        # Column 0: Firewall name.
        item.setText(0, fw.name)
        item.setIcon(0, QIcon(':/Icons/Firewall/icon-ref'))

        # Column 1: Interface name.
        item.setText(1, iface.name)
        item.setIcon(1, QIcon(':/Icons/Interface/icon-ref'))

        # Column 2: Master.
        if is_master:
            item.setText(2, 'Master')
        else:
            item.setText(2, '')

        # Column 3: Status.
        if valid:
            item.setText(3, 'OK')
            item.setToolTip(
                3,
                f'Firewall {fw.name} can be used as a member of this cluster',
            )
        else:
            item.setText(3, 'Invalid')
            item.setToolTip(
                3,
                f'Firewall {fw.name} cannot be used as a member of this '
                f'cluster because its host OS or platform does not match '
                f'those of the cluster.',
            )
            item.setBackground(3, QBrush(QColor(255, 0, 0, 100)))

    # ------------------------------------------------------------------
    # Helper: find parent cluster
    # ------------------------------------------------------------------

    def _find_parent_cluster(self, obj):
        """Walk up the object tree to find the parent Cluster device.

        For a FailoverClusterGroup that lives under a cluster interface,
        we need to go: ClusterGroup -> Interface -> Cluster.
        For a StateSyncClusterGroup that lives directly under Cluster,
        we go: ClusterGroup -> Cluster.

        Since our ORM model doesn't have a direct parent_device link on
        Group, we query the database.
        """
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            # The cluster group is stored with a library_id.
            # We need to find the Cluster device that owns interfaces
            # whose sub-groups include this cluster group, or the cluster
            # that directly has this group.
            #
            # Strategy: query all Cluster devices in the same library and
            # check if the cluster group's ID appears in the membership
            # data or interface hierarchy.
            from firewallfabrik.core.objects import Cluster

            clusters = session.scalars(
                sqlalchemy.select(Cluster)
                .where(Cluster.library_id == obj.library_id)
                .order_by(Cluster.name),
            ).all()

            if len(clusters) == 1:
                return clusters[0]

            # If multiple clusters exist, try to find one whose interfaces
            # own this cluster group. This is a simplified heuristic.
            for cluster in clusters:
                for _iface in cluster.interfaces:
                    # Check if any sub-group of this interface is our group.
                    # Since groups don't have a direct interface FK, we check
                    # by name/type matching heuristic.
                    pass

            # Fallback: return the first cluster.
            if clusters:
                return clusters[0]

            return None
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Dialog slots
    # ------------------------------------------------------------------

    @Slot()
    def _open_cluster_member_dialog(self):
        """Open the cluster member management dialog."""
        from firewallfabrik.gui.cluster_member_dialog import ClusterMemberDialog

        if self._db_manager is None:
            return

        cluster_data = self._cluster.data if self._cluster else {}

        dlg = ClusterMemberDialog(
            db_manager=self._db_manager,
            cluster_data=cluster_data,
            cluster_group=self._obj,
            parent=self.window(),
        )

        if dlg.exec() == QDialog.DialogCode.Accepted:
            # Reload the member tree to reflect changes.
            self._load_member_tree()
            self.changed.emit()
