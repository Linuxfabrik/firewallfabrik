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

"""Modal dialog for managing cluster group member firewalls.

Ports fwbuilder's ``clusterMembersDialog`` -- shows available firewalls
(matching platform/host OS) on the left, selected cluster members on the
right, with add/remove buttons in between.

The dialog operates on a :class:`ClusterGroup` (either
``FailoverClusterGroup`` or ``StateSyncClusterGroup``) and persists
membership changes into the ``group_membership`` table on accept.
"""

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QTableWidgetItem,
    QTreeWidgetItem,
)

from firewallfabrik.core.objects import (
    Host,
    Interface,
    group_membership,
)
from firewallfabrik.gui.ui_loader import FWFUiLoader

logger = logging.getLogger(__name__)

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'clustermembersdialog_q.ui'


@dataclass
class _ClusterMember:
    """Temporary helper storing relevant info about a cluster member."""

    fw_id: uuid.UUID
    fw_name: str
    iface_list: list = field(default_factory=list)  # list of (iface_id, name, label)
    iface_map: dict = field(default_factory=dict)  # name -> (iface_id, name, label)
    iface_cluster: tuple | None = None  # (iface_id, name, label) selected for cluster
    is_master: bool = False


class ClusterMemberDialog(QDialog):
    """Modal dialog for managing member firewalls of a cluster group.

    Parameters
    ----------
    db_manager:
        Database manager for querying firewalls and interfaces.
    cluster_group:
        The cluster group ORM object whose members are being managed.
    cluster_data:
        The ``data`` dict of the parent Cluster device (for platform/host_OS matching).
    parent:
        Parent widget.
    """

    members_changed = Signal()

    def __init__(self, db_manager, cluster_group, cluster_data, parent=None):
        super().__init__(parent)

        loader = FWFUiLoader(self)
        loader.load(str(_UI_PATH))
        self.setWindowModality(Qt.WindowModality.WindowModal)

        self._db_manager = db_manager
        self._cluster_group = cluster_group
        self._cluster_data = cluster_data or {}
        self._host_os = self._cluster_data.get('host_OS', '')
        self._platform = self._cluster_data.get('platform', '')

        # Determine if the master column is needed.
        # For now, we always show it (fwbuilder hides it based on
        # protocol-specific resources; we simplify).
        self._enable_master_column = True
        group_data = cluster_group.data or {}
        group_type = group_data.get('type', '')
        # conntrack does not need master; vrrp does.
        if group_type == 'conntrack':
            self._enable_master_column = False
        if not self._enable_master_column:
            self.fwSelectedTable.hideColumn(2)

        self._table_update = False

        # Member lists.
        self._selected: list[_ClusterMember] = []
        self._available: list[_ClusterMember] = []

        self._load_selected_members()
        self._load_available_members()

        self._update_available_tree()
        self._update_selected_table()

        # Connections.
        self.fwAvailableTree.itemClicked.connect(self._on_available_clicked)
        self.buttonAdd.clicked.connect(self._on_add)
        self.buttonRemove.clicked.connect(self._on_remove)
        self.fwSelectedTable.cellClicked.connect(self._on_selected_clicked)
        self.fwSelectedTable.cellChanged.connect(self._on_master_selected)

        self.adjustSize()

        # Center on parent window.
        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    # ------------------------------------------------------------------
    # Loading members
    # ------------------------------------------------------------------

    def _load_selected_members(self):
        """Read currently assigned member interfaces from the database."""
        session = self._db_manager.create_session()
        try:
            group_data = self._cluster_group.data or {}
            master_iface_id = group_data.get('master_iface', '')

            # Get member interface IDs from group_membership table.
            rows = session.execute(
                sqlalchemy.select(
                    group_membership.c.member_id,
                    group_membership.c.position,
                )
                .where(
                    group_membership.c.group_id == self._cluster_group.id,
                )
                .order_by(group_membership.c.position),
            ).all()

            for member_id, _position in rows:
                iface = session.get(Interface, member_id)
                if iface is None:
                    logger.warning(
                        'Cluster member interface %s not found',
                        member_id,
                    )
                    continue

                fw = iface.device
                if fw is None:
                    logger.warning(
                        'Interface %s has no parent device',
                        iface.name,
                    )
                    continue

                is_master = (
                    str(iface.id).replace('-', '') == master_iface_id
                    or str(iface.id) == master_iface_id
                )

                member = self._create_member(
                    fw, session, iface_cluster=iface, is_master=is_master
                )
                if member is not None:
                    self._selected.append(member)
        finally:
            session.close()

    def _load_available_members(self):
        """Find firewalls matching platform/host_OS that are not already selected."""
        selected_fw_names = {m.fw_name for m in self._selected}

        session = self._db_manager.create_session()
        try:
            firewalls = session.scalars(
                sqlalchemy.select(Host)
                .where(Host.type == 'Firewall')
                .order_by(Host.name),
            ).all()

            for fw in firewalls:
                fw_data = fw.data or {}
                # Must match platform and host OS.
                if fw_data.get('host_OS', '') != self._host_os:
                    continue
                if fw_data.get('platform', '') != self._platform:
                    continue

                # Must have at least one interface.
                if not fw.interfaces:
                    continue

                # Skip already selected firewalls.
                if fw.name in selected_fw_names:
                    continue

                member = self._create_member(fw, session)
                if member is not None:
                    self._available.append(member)
        finally:
            session.close()

    def _create_member(
        self,
        fw,
        session,
        iface_cluster=None,
        is_master=False,
    ):
        """Create a _ClusterMember from a Firewall ORM object."""
        iface_list = []
        iface_map = {}

        interfaces = sorted(fw.interfaces or [], key=lambda i: i.name)
        for iface in interfaces:
            iface_data = iface.data or {}
            label = iface_data.get('label', '')
            entry = (iface.id, iface.name, label)
            iface_list.append(entry)
            iface_map[iface.name] = entry

        cluster_entry = None
        if iface_cluster is not None:
            iface_data = iface_cluster.data or {}
            label = iface_data.get('label', '')
            cluster_entry = (iface_cluster.id, iface_cluster.name, label)

        return _ClusterMember(
            fw_id=fw.id,
            fw_name=fw.name,
            iface_cluster=cluster_entry,
            iface_list=iface_list,
            iface_map=iface_map,
            is_master=is_master,
        )

    # ------------------------------------------------------------------
    # View updates
    # ------------------------------------------------------------------

    def _update_available_tree(self):
        """Refresh the tree of available firewalls and their interfaces."""
        self.fwAvailableTree.clear()

        for member in sorted(self._available, key=lambda m: m.fw_name):
            fw_item = QTreeWidgetItem()
            fw_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            fw_item.setText(0, member.fw_name)
            fw_item.setIcon(0, QIcon(':/Icons/Firewall/icon-tree'))

            for _iface_id, iface_name, label in sorted(
                member.iface_list,
                key=lambda x: x[1],
            ):
                iface_item = QTreeWidgetItem(fw_item)
                iface_item.setFlags(
                    Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable,
                )
                iface_item.setText(1, iface_name)
                iface_item.setIcon(1, QIcon(':/Icons/Interface/icon-tree'))
                if label:
                    iface_item.setText(2, label)

            self.fwAvailableTree.addTopLevelItem(fw_item)

        self.fwAvailableTree.resizeColumnToContents(0)
        self.fwAvailableTree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.fwAvailableTree.expandAll()

    def _update_selected_table(self):
        """Refresh the table of selected cluster members."""
        self._table_update = True

        self.fwSelectedTable.setRowCount(len(self._selected))

        for row, member in enumerate(self._selected):
            # Column 0: Firewall name.
            item = self.fwSelectedTable.item(row, 0)
            if item is None:
                item = QTableWidgetItem()
                item.setIcon(QIcon(':/Icons/Firewall/icon-tree'))
                self.fwSelectedTable.setItem(row, 0, item)
            item.setText(member.fw_name)

            # Column 1: Interface name.
            iface_name = member.iface_cluster[1] if member.iface_cluster else ''
            item = self.fwSelectedTable.item(row, 1)
            if item is None:
                item = QTableWidgetItem()
                item.setIcon(QIcon(':/Icons/Interface/icon-tree'))
                self.fwSelectedTable.setItem(row, 1, item)
            item.setText(iface_name)

            # Column 2: Master checkbox.
            item = self.fwSelectedTable.item(row, 2)
            state = (
                Qt.CheckState.Checked if member.is_master else Qt.CheckState.Unchecked
            )
            if item is None:
                item = QTableWidgetItem()
                item.setCheckState(state)
                self.fwSelectedTable.setItem(row, 2, item)
            elif item.checkState() != state:
                item.setCheckState(state)

        self.fwSelectedTable.resizeColumnsToContents()
        self.fwSelectedTable.horizontalHeader().setStretchLastSection(True)

        self._table_update = False

    def _invalidate(self):
        """Update both views and reset button states."""
        self._update_available_tree()
        self._update_selected_table()
        self.buttonAdd.setEnabled(False)
        self.buttonRemove.setEnabled(False)

    # ------------------------------------------------------------------
    # Swap logic
    # ------------------------------------------------------------------

    def _swap(self, from_list, to_list, fw_name, iface_name='', is_master=False):
        """Move a firewall from *from_list* to *to_list*.

        Returns True if successful, False if the firewall was not found.
        """
        member = None
        for m in from_list:
            if m.fw_name == fw_name:
                member = m
                break

        if member is None:
            return False

        from_list.remove(member)

        if iface_name and iface_name in member.iface_map:
            member.iface_cluster = member.iface_map[iface_name]
        member.is_master = is_master

        to_list.append(member)
        return True

    def _set_master(self, fw_name, checked=True):
        """Set master status for a firewall, clearing all others."""
        for member in self._selected:
            if member.fw_name == fw_name:
                member.is_master = checked
            else:
                member.is_master = False
        self._update_selected_table()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @Slot(QTreeWidgetItem, int)
    def _on_available_clicked(self, item, _column):
        """Enable Add button only if a specific interface is selected."""
        if item.text(1):
            self.buttonAdd.setEnabled(True)
        else:
            self.buttonAdd.setEnabled(False)

    @Slot(int, int)
    def _on_selected_clicked(self, _row, _column):
        """Enable the Remove button when a selected member is clicked."""
        if not self.buttonRemove.isEnabled():
            self.buttonRemove.setEnabled(True)

    @Slot(int, int)
    def _on_master_selected(self, row, column):
        """Handle master checkbox changes in the selected table."""
        if self._table_update:
            return

        # Ensure at least one master is always checked.
        no_master = True
        for row_idx in range(self.fwSelectedTable.rowCount()):
            item = self.fwSelectedTable.item(row_idx, 2)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                no_master = False
                break

        if no_master:
            item = self.fwSelectedTable.item(row, 2)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)

        name_item = self.fwSelectedTable.item(row, 0)
        master_item = self.fwSelectedTable.item(row, column)
        if name_item is not None and master_item is not None:
            self._set_master(
                name_item.text(),
                master_item.checkState() == Qt.CheckState.Checked,
            )

    @Slot()
    def _on_add(self):
        """Move selected firewall/interface from available to selected."""
        items = self.fwAvailableTree.selectedItems()
        if not items:
            return

        for item in items:
            iface_name = item.text(1)
            if not iface_name:
                continue

            parent_item = item.parent()
            if parent_item is None:
                continue

            fw_name = parent_item.text(0)
            if not self._swap(self._available, self._selected, fw_name, iface_name):
                logger.warning(
                    'ClusterMemberDialog: swap failed for firewall %s, interface: %s',
                    fw_name,
                    iface_name,
                )
                return

        self._invalidate()

    @Slot()
    def _on_remove(self):
        """Move selected firewall from selected back to available."""
        items = self.fwSelectedTable.selectedItems()
        if not items:
            return

        fw_name = items[0].text()
        if not self._swap(self._selected, self._available, fw_name, '', False):
            logger.warning(
                'ClusterMemberDialog: swap failed for firewall %s',
                fw_name,
            )
            return

        self._invalidate()

    # ------------------------------------------------------------------
    # Accept / Reject
    # ------------------------------------------------------------------

    def accept(self):
        """Persist the member changes to the database."""
        session = self._db_manager.create_session()
        try:
            # Remove all existing memberships for this group.
            session.execute(
                group_membership.delete().where(
                    group_membership.c.group_id == self._cluster_group.id,
                ),
            )

            # Re-fetch the group to update it.
            grp = session.merge(self._cluster_group)

            # Add selected interfaces as group members.
            master_iface_id = ''
            for pos, member in enumerate(self._selected):
                if member.iface_cluster is None:
                    continue
                iface_id = member.iface_cluster[0]
                session.execute(
                    group_membership.insert().values(
                        group_id=self._cluster_group.id,
                        member_id=iface_id,
                        position=pos,
                    ),
                )
                if member.is_master:
                    master_iface_id = str(iface_id).replace('-', '')

            # Update master_iface in group data.
            import copy

            data = copy.deepcopy(grp.data or {})
            if master_iface_id:
                data['master_iface'] = master_iface_id
            elif 'master_iface' in data:
                del data['master_iface']
            grp.data = data

            session.commit()
        except Exception:
            session.rollback()
            logger.exception('Failed to save cluster member changes')
            raise
        finally:
            session.close()

        self.members_changed.emit()
        super().accept()

    # ------------------------------------------------------------------
    # Result accessor
    # ------------------------------------------------------------------

    def get_selected_members(self):
        """Return list of (fw_id, fw_name, iface_id, iface_name, is_master) tuples."""
        result = []
        for member in self._selected:
            if member.iface_cluster is None:
                continue
            result.append(
                (
                    member.fw_id,
                    member.fw_name,
                    member.iface_cluster[0],
                    member.iface_cluster[1],
                    member.is_master,
                )
            )
        return result
