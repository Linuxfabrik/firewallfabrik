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

"""Editor panel dialog for group objects.

Ports fwbuilder's GroupObjectDialog — shows members in icon or list view,
supports drag-drop, remove-from-group, and provides comment/keyword editing.
"""

import json
import uuid

import sqlalchemy
import sqlalchemy.orm
from PySide6.QtCore import QSettings, QSize, Qt, Signal, Slot
from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QTreeWidget,
    QTreeWidgetItem,
)

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interval,
    Service,
    group_membership,
)
from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.platform_settings import HOST_OS
from firewallfabrik.gui.policy_model import FWF_MIME_TYPE

# Allowed child types per group class, matching fwbuilder's
# getAllowedTypesOfChildren() (minus reference types).  Alphabetical.
_ALLOWED_NEW_TYPES = {
    'IntervalGroup': [
        ('Interval', 'Time Interval'),
    ],
    'ObjectGroup': [
        ('AddressRange', 'Address Range'),
        ('AddressTable', 'Address Table'),
        ('Cluster', 'Cluster'),
        ('DNSName', 'DNS Name'),
        ('Firewall', 'Firewall'),
        ('Host', 'Host'),
        ('IPv4', 'Address'),
        ('IPv6', 'Address IPv6'),
        ('Network', 'Network'),
        ('NetworkIPv6', 'Network IPv6'),
    ],
    'ServiceGroup': [
        ('CustomService', 'Custom Service'),
        ('ICMP6Service', 'ICMP6 Service'),
        ('ICMPService', 'ICMP Service'),
        ('IPService', 'IP Service'),
        ('TCPService', 'TCP Service'),
        ('TagService', 'Tag Service'),
        ('UDPService', 'UDP Service'),
        ('UserService', 'User Service'),
    ],
}

# Set of type discriminators accepted as members for each group class.
# Built from _ALLOWED_NEW_TYPES plus the group type itself (groups can
# contain sub-groups of the same kind).  Matches fwbuilder's
# Group::validateChild() / getAllowedTypesOfChildren().
_ALLOWED_MEMBER_TYPES: dict[str, frozenset[str]] = {}
for _gtype, _entries in _ALLOWED_NEW_TYPES.items():
    _types = frozenset({t for t, _ in _entries} | {_gtype})
    _ALLOWED_MEMBER_TYPES[_gtype] = _types


# ------------------------------------------------------------------
# Droppable view widgets
# ------------------------------------------------------------------


class _DroppableListWidget(QListWidget):
    """QListWidget that accepts drops from the object tree."""

    dropped = Signal(list)  # list[dict] with {id, name, type}

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        mime = event.mimeData()
        if not mime.hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return
        try:
            payload = json.loads(bytes(mime.data(FWF_MIME_TYPE)).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            event.ignore()
            return
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            event.ignore()
            return
        self.dropped.emit(payload)
        event.acceptProposedAction()


class _DroppableTreeWidget(QTreeWidget):
    """QTreeWidget that accepts drops from the object tree."""

    dropped = Signal(list)  # list[dict] with {id, name, type}

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        mime = event.mimeData()
        if not mime.hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return
        try:
            payload = json.loads(bytes(mime.data(FWF_MIME_TYPE)).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            event.ignore()
            return
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            event.ignore()
            return
        self.dropped.emit(payload)
        event.acceptProposedAction()


# ------------------------------------------------------------------
# Object properties helper
# ------------------------------------------------------------------


def _get_object_properties(obj):
    """Return a single-line properties string for *obj*.

    Mirrors fwbuilder's ``FWObjectPropertiesFactory::getObjectProperties()``.
    """
    type_str = getattr(obj, 'type', '')

    if type_str in ('IPv4', 'IPv6', 'Network', 'NetworkIPv6'):
        iam = getattr(obj, 'inet_addr_mask', None) or {}
        addr = iam.get('address', '')
        mask = iam.get('netmask', '')
        return f'{addr}/{mask}' if mask else addr

    if type_str == 'AddressRange':
        start = (getattr(obj, 'start_address', None) or {}).get('address', '')
        end = (getattr(obj, 'end_address', None) or {}).get('address', '')
        return f'{start} - {end}'

    if type_str in ('TCPService', 'UDPService'):
        ss = getattr(obj, 'src_range_start', None) or 0
        se = getattr(obj, 'src_range_end', None) or 0
        ds = getattr(obj, 'dst_range_start', None) or 0
        de = getattr(obj, 'dst_range_end', None) or 0
        return f'{ss}:{se} / {ds}:{de}'

    if type_str == 'IPService':
        named = getattr(obj, 'named_protocols', None) or {}
        return f'protocol: {named.get("protocol_num", "")}'

    if type_str in ('ICMP6Service', 'ICMPService'):
        codes = getattr(obj, 'codes', None) or {}
        return f'type: {codes.get("type", "")}  code: {codes.get("code", "")}'

    if type_str == 'CustomService':
        data = getattr(obj, 'data', None) or {}
        platform = data.get('platform', '')
        return f'platform: {platform}' if platform else ''

    if type_str == 'DNSName':
        return f'DNS record: {getattr(obj, "source_name", "") or ""}'

    if type_str == 'AddressTable':
        return f'Address Table: {getattr(obj, "source_name", "") or ""}'

    if type_str == 'TagService':
        data = getattr(obj, 'data', None) or {}
        code = data.get('tagcode', '')
        return f'tag: {code}' if code else ''

    if type_str == 'UserService':
        return f'user: {getattr(obj, "userid", "") or ""}'

    if type_str in ('Cluster', 'Firewall'):
        data = getattr(obj, 'data', None) or {}
        platform = data.get('platform', '')
        host_os = data.get('host_OS', '')
        host_os = HOST_OS.get(host_os, host_os)
        return f'{platform} / {host_os}' if platform else ''

    if type_str == 'Host':
        for iface in getattr(obj, 'interfaces', []):
            for addr in iface.addresses:
                if getattr(addr, 'type', '') == 'PhysAddress':
                    continue
                iam = getattr(addr, 'inet_addr_mask', None) or {}
                a = iam.get('address', '')
                if a:
                    return a
        return ''

    if isinstance(obj, Group):
        session = sqlalchemy.orm.object_session(obj)
        if session:
            count = session.scalar(
                sqlalchemy.select(sqlalchemy.func.count())
                .select_from(group_membership)
                .where(group_membership.c.group_id == obj.id)
            )
            return f'{count} objects'

    return ''


class GroupObjectDialog(BaseObjectDialog):
    """Editor for ObjectGroup, ServiceGroup, and IntervalGroup.

    Displays group members in icon or list view (toggled via the I/L
    buttons).  Members can be added by dragging from the object tree,
    and removed via context menu or Delete key.
    """

    # Emitted when the user picks a type from the "Create new object"
    # button menu.  Carries ``(type_name, group_id_hex)``.  The main
    # window creates the object, adds the group_membership entry, and
    # opens the new object's editor.
    member_create_requested = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__('groupobjectdialog_q.ui', parent)

        self._new_object_menu = QMenu(self)
        self.newButton.setMenu(self._new_object_menu)

        # Icon view — QListWidget in icon mode with drop support.
        self._icon_view = _DroppableListWidget()
        self._icon_view.setViewMode(QListWidget.ViewMode.IconMode)
        self._icon_view.setResizeMode(QListWidget.ResizeMode.Adjust)
        self._icon_view.setGridSize(QSize(80, 50))
        self._icon_view.setIconSize(QSize(25, 25))
        self._icon_view.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self._icon_view.setAcceptDrops(True)
        self._icon_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._icon_view.customContextMenuRequested.connect(self._on_member_context_menu)
        self._icon_view.dropped.connect(self._on_objects_dropped)

        # List view — QTreeWidget with Name + Properties and drop support.
        self._list_view = _DroppableTreeWidget()
        self._list_view.setHeaderLabels(['Name', 'Properties'])
        self._list_view.setRootIsDecorated(False)
        self._list_view.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self._list_view.setAcceptDrops(True)
        self._list_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._list_view.customContextMenuRequested.connect(self._on_member_context_menu)
        self._list_view.dropped.connect(self._on_objects_dropped)

        # Add views to the stacked widget.
        self.objectViewsStack.addWidget(self._icon_view)
        self.objectViewsStack.addWidget(self._list_view)

        # Restore saved view mode (default: list view, matching fwbuilder).
        mode = QSettings().value('UI/GroupViewMode', 'list', type=str)
        if mode == 'icon':
            self.objectViewsStack.setCurrentWidget(self._icon_view)
            self.iconViewBtn.setChecked(True)
        else:
            self.objectViewsStack.setCurrentWidget(self._list_view)
            self.listViewBtn.setChecked(True)

        # Delete key removes selected members from the group.
        delete_action = QAction(self)
        delete_action.setShortcut(QKeySequence.StandardKey.Delete)
        delete_action.triggered.connect(self._remove_selected_members)
        self._icon_view.addAction(delete_action)
        self._list_view.addAction(delete_action)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self._build_new_object_menu()
        self._load_members()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()

    def _build_new_object_menu(self):
        """Populate the 'Create new object' button menu for the current group type."""
        self._new_object_menu.clear()
        group_type = getattr(self._obj, 'type', '')
        allowed = _ALLOWED_NEW_TYPES.get(group_type, [])
        read_only = self._is_read_only()
        self.newButton.setVisible(bool(allowed) and not read_only)
        for type_name, label in allowed:
            icon = QIcon(f':/Icons/{type_name}/icon-tree')
            action = self._new_object_menu.addAction(icon, f'New {label}')
            action.setData(type_name)
            action.triggered.connect(
                lambda checked=False, t=type_name: self._request_new_member(t)
            )

    def _request_new_member(self, type_name):
        """Emit signal so the main window creates the object and adds it."""
        if self._obj is not None:
            self.member_create_requested.emit(type_name, str(self._obj.id))

    @Slot()
    def newObject(self):
        """Show the 'Create new object' popup menu (wired from .ui)."""
        self.newButton.showMenu()

    # ------------------------------------------------------------------
    # Member list
    # ------------------------------------------------------------------

    def _load_members(self):
        """Load group members into both icon and list views."""
        self._icon_view.clear()
        self._list_view.clear()

        session = sqlalchemy.orm.object_session(self._obj)
        if session is None:
            return

        # Query member IDs in position order.
        rows = session.execute(
            sqlalchemy.select(group_membership.c.member_id)
            .where(group_membership.c.group_id == self._obj.id)
            .order_by(group_membership.c.position)
        ).all()

        member_ids = [row.member_id for row in rows]
        if not member_ids:
            return

        # Look up members across all object tables.
        member_map = {}
        for cls in (Address, Group, Host, Interval, Service):
            for obj in (
                session.scalars(sqlalchemy.select(cls).where(cls.id.in_(member_ids)))
                .unique()
                .all()
            ):
                member_map[obj.id] = obj

        # Add members in their original order.
        for mid in member_ids:
            member = member_map.get(mid)
            if member is not None:
                self._add_member(member)

        # Auto-size list view columns.
        self._list_view.resizeColumnToContents(0)
        self._list_view.resizeColumnToContents(1)

    def _add_member(self, obj):
        """Add a single member to both icon and list views."""
        type_str = getattr(obj, 'type', '')
        name = getattr(obj, 'name', '')
        icon = QIcon(f':/Icons/{type_str}/icon')
        obj_id = str(obj.id)

        # Icon view item.
        icon_item = QListWidgetItem(icon, name)
        icon_item.setData(Qt.ItemDataRole.UserRole, obj_id)
        self._icon_view.addItem(icon_item)

        # List view item.
        tree_item = QTreeWidgetItem([name, _get_object_properties(obj)])
        tree_item.setIcon(0, icon)
        tree_item.setData(0, Qt.ItemDataRole.UserRole, obj_id)
        self._list_view.addTopLevelItem(tree_item)

    def _get_existing_member_ids(self):
        """Return a set of member ID strings currently shown in the views."""
        ids = set()
        for i in range(self._icon_view.count()):
            obj_id = self._icon_view.item(i).data(Qt.ItemDataRole.UserRole)
            if obj_id:
                ids.add(obj_id)
        return ids

    # ------------------------------------------------------------------
    # View switching (wired from .ui <connections>)
    # ------------------------------------------------------------------

    @Slot()
    def switchToIconView(self):
        """Switch the member view to icon mode and persist the choice."""
        self.objectViewsStack.setCurrentWidget(self._icon_view)
        QSettings().setValue('UI/GroupViewMode', 'icon')

    @Slot()
    def switchToListView(self):
        """Switch the member view to list mode and persist the choice."""
        self.objectViewsStack.setCurrentWidget(self._list_view)
        QSettings().setValue('UI/GroupViewMode', 'list')

    # ------------------------------------------------------------------
    # Drag & drop — add objects to group
    # ------------------------------------------------------------------

    def _on_objects_dropped(self, entries):
        """Handle objects dropped from the object tree onto a member view.

        Validates each dropped object's type against the group's allowed
        member types, skips duplicates, and inserts group_membership rows.
        Mirrors fwbuilder's ``GroupObjectDialog::dropped()`` →
        ``insertObject()`` flow.
        """
        if self._obj is None or self._is_read_only():
            return

        session = sqlalchemy.orm.object_session(self._obj)
        if session is None:
            return

        group_type = getattr(self._obj, 'type', '')
        allowed = _ALLOWED_MEMBER_TYPES.get(group_type, frozenset())
        existing = self._get_existing_member_ids()

        # Determine next position value.
        max_pos = session.scalar(
            sqlalchemy.select(sqlalchemy.func.max(group_membership.c.position)).where(
                group_membership.c.group_id == self._obj.id
            )
        )
        next_pos = (max_pos or 0) + 1

        added = False
        for entry in entries:
            obj_id_str = entry.get('id', '')
            obj_type = entry.get('type', '')

            if not obj_id_str or not obj_type:
                continue

            # Type validation: only accept types allowed for this group.
            if obj_type not in allowed:
                continue

            # Duplicate check: skip if already a member.
            if obj_id_str in existing:
                continue

            # Prevent adding the group to itself.
            if obj_id_str == str(self._obj.id):
                continue

            member_id = uuid.UUID(obj_id_str)
            session.execute(
                group_membership.insert().values(
                    group_id=self._obj.id,
                    member_id=member_id,
                    position=next_pos,
                )
            )
            existing.add(obj_id_str)
            next_pos += 1
            added = True

        if added:
            self.changed.emit()
            self._load_members()

    # ------------------------------------------------------------------
    # Member removal
    # ------------------------------------------------------------------

    def _on_member_context_menu(self, pos):
        """Show context menu for member views (remove from group)."""
        if self._is_read_only():
            return

        sender = self.sender()
        items = (
            self._icon_view.selectedItems()
            if sender is self._icon_view
            else self._list_view.selectedItems()
        )
        if not items:
            return

        menu = QMenu(self)
        remove_action = menu.addAction('Remove from Group')
        remove_action.triggered.connect(self._remove_selected_members)
        menu.exec(sender.viewport().mapToGlobal(pos))

    def _remove_selected_members(self):
        """Remove selected members from the group."""
        if self._is_read_only():
            return

        session = sqlalchemy.orm.object_session(self._obj)
        if session is None:
            return

        # Collect selected member IDs from the active view.
        current_view = self.objectViewsStack.currentWidget()
        if current_view is self._icon_view:
            items = self._icon_view.selectedItems()
            ids = [item.data(Qt.ItemDataRole.UserRole) for item in items]
        else:
            items = self._list_view.selectedItems()
            ids = [item.data(0, Qt.ItemDataRole.UserRole) for item in items]

        if not ids:
            return

        for obj_id_str in ids:
            member_id = uuid.UUID(obj_id_str)
            session.execute(
                group_membership.delete().where(
                    group_membership.c.group_id == self._obj.id,
                    group_membership.c.member_id == member_id,
                )
            )

        self.changed.emit()
        self._load_members()
