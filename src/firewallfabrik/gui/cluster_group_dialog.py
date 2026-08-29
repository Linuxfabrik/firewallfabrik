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
    Cluster,
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
        self._cluster_data = {}
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
        self._cluster_data = self._parent_cluster_data(obj)

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

        # Edit Parameters -- one dialog per protocol.  "None" has no
        # parameters, which is what leaving the button disabled says.
        # Imported here, not at the top: `ui_loader` registers this class
        # while it is itself being imported, so a module-level import of
        # anything that reaches the loader is a circular one.
        from firewallfabrik.gui.cluster_protocol_dialogs import PROTOCOL_DIALOGS

        self.editParameters.setEnabled(group_type in PROTOCOL_DIALOGS)
        self.editParameters.setToolTip(
            'Address, port and mode of the protocol this group speaks. The '
            'compiler writes the rules that permit the traffic out of these '
            'values, so they have to match what the daemon is configured '
            'with.',
        )

        # Wire buttons (only once -- idempotent via _signals_connected flag).
        with contextlib.suppress(RuntimeError):
            self.manageMembers.clicked.disconnect(self._open_cluster_member_dialog)
        self.manageMembers.clicked.connect(self._open_cluster_member_dialog)
        with contextlib.suppress(RuntimeError):
            self.editParameters.clicked.disconnect(self._open_protocol_dialog)
        self.editParameters.clicked.connect(self._open_protocol_dialog)

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

        cluster_data = self._cluster_data
        cluster_host_os = cluster_data.get('host_OS', '')
        cluster_platform = cluster_data.get('platform', '')

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

    def _parent_cluster_data(self, obj):
        """The settings of the Cluster this group belongs to.

        A FailoverClusterGroup hangs under a cluster interface and a
        StateSyncClusterGroup under the cluster itself, so the link the
        object carries answers it outright.  This used to walk the
        library and return the first Cluster it found, which named the
        wrong one on every file with two: the member list was then
        checked against a platform and a host OS belonging to some other
        cluster, and rows were marked "Invalid" that are not.
        """
        if self._db_manager is None:
            return {}

        session = self._db_manager.create_session()
        try:
            group = session.get(type(obj), obj.id)
            if group is None:
                return {}
            owner = None
            if group.interface_id is not None and group.interface is not None:
                owner = group.interface.device
            elif group.device_id is not None:
                owner = group.device
            if not isinstance(owner, Cluster):
                return {}
            return dict(owner.data or {})
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

        dlg = ClusterMemberDialog(
            db_manager=self._db_manager,
            cluster_data=self._cluster_data,
            cluster_group=self._obj,
            parent=self.window(),
        )

        if dlg.exec() == QDialog.DialogCode.Accepted:
            # Reload the member tree to reflect changes.
            self._load_member_tree()
            self.changed.emit()

    @Slot()
    def _open_protocol_dialog(self):
        """Edit the parameters of the protocol this group speaks.

        The values belong to the group, not to the cluster: two failover
        groups of one cluster may run on different links with different
        addresses.  They are written straight through, because the dialog
        is modal and the editor's own Apply only knows about the name and
        the protocol.
        """
        from firewallfabrik.gui.cluster_protocol_dialogs import PROTOCOL_DIALOGS

        group_type = (self._obj.data or {}).get('type', '')
        dialog_cls = PROTOCOL_DIALOGS.get(group_type)
        if dialog_cls is None:
            return

        dlg = dialog_cls(self._obj.options or {}, parent=self.window())
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        new_options = dlg.get_options()
        if new_options != (self._obj.options or {}):
            self._obj.options = new_options
            self.changed.emit()
