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

"""QTableView wrapper for policy rule display with editing support."""

import json
import uuid

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QMenu,
    QTableView,
)

from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.gui.policy_model import (
    _COL_ACTION,
    _COL_DIRECTION,
    _COL_TO_SLOT,
    _ELEMENT_COLS,
    FWF_MIME_TYPE,
)

_VALID_TYPES_BY_SLOT = {
    'dst': frozenset(
        {
            'AddressRange',
            'Cluster',
            'Firewall',
            'Host',
            'IPv4',
            'IPv6',
            'Interface',
            'Network',
            'NetworkIPv6',
            'ObjectGroup',
            'PhysAddress',
        }
    ),
    'itf': frozenset({'Interface'}),
    'src': frozenset(
        {
            'AddressRange',
            'Cluster',
            'Firewall',
            'Host',
            'IPv4',
            'IPv6',
            'Interface',
            'Network',
            'NetworkIPv6',
            'ObjectGroup',
            'PhysAddress',
        }
    ),
    'srv': frozenset(
        {
            'CustomService',
            'ICMP6Service',
            'ICMPService',
            'IPService',
            'ServiceGroup',
            'TCPService',
            'TagService',
            'UDPService',
            'UserService',
        }
    ),
}


class PolicyView(QTableView):
    """Table view with context menus, keyboard shortcuts, and drop support."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents,
        )
        self.verticalHeader().setVisible(False)

        # Context menu.
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

        # Drop support.
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setDropIndicatorShown(True)

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def _show_context_menu(self, pos):
        index = self.indexAt(pos)
        model = self.model()
        if model is None:
            return

        menu = QMenu(self)

        if not index.isValid():
            # Clicked on empty area.
            menu.addAction(
                'Insert New Rule on Top', lambda: model.insert_rule(at_top=True)
            )
            menu.addAction(
                'Insert New Rule at Bottom', lambda: model.insert_rule(at_bottom=True)
            )
            menu.exec(self.viewport().mapToGlobal(pos))
            return

        row = index.row()
        col = index.column()

        if col == _COL_ACTION:
            self._build_action_menu(menu, model, row)
        elif col == _COL_DIRECTION:
            self._build_direction_menu(menu, model, row)
        elif col in _ELEMENT_COLS:
            self._build_element_menu(menu, model, row, col)
        else:
            self._build_row_menu(menu, model, row)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _build_row_menu(self, menu, model, row):
        """Build standard row-level context menu (# and Comment columns)."""
        menu.addAction('Insert Rule Above', lambda: model.insert_rule(row))
        menu.addAction('Insert Rule Below', lambda: model.insert_rule(row + 1))
        menu.addSeparator()
        menu.addAction('Remove Rule', lambda: model.delete_rules([row]))
        menu.addSeparator()
        up = menu.addAction('Move Up', lambda: model.move_rule_up(row))
        up.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageUp))
        down = menu.addAction('Move Down', lambda: model.move_rule_down(row))
        down.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageDown))

    def _build_action_menu(self, menu, model, row):
        """Build action-selection context menu."""
        for action in (PolicyAction.Accept, PolicyAction.Deny, PolicyAction.Reject):
            icon = QIcon(f':/Icons/{action.name}/icon-tree')
            menu.addAction(icon, action.name, lambda a=action: model.set_action(row, a))

    def _build_direction_menu(self, menu, model, row):
        """Build direction-selection context menu."""
        icons = {
            Direction.Both: ':/Icons/Both/icon-tree',
            Direction.Inbound: ':/Icons/Inbound/icon-tree',
            Direction.Outbound: ':/Icons/Outbound/icon-tree',
        }
        for direction in (Direction.Both, Direction.Inbound, Direction.Outbound):
            icon = QIcon(icons[direction])
            menu.addAction(
                icon,
                direction.name,
                lambda d=direction: model.set_direction(row, d),
            )

    def _build_element_menu(self, menu, model, row, col):
        """Build element column context menu with remove actions."""
        slot = _COL_TO_SLOT[col]
        row_data = model.get_row_data(row)
        if row_data is None:
            return
        elements = getattr(row_data, slot, [])
        if not elements:
            menu.addAction('(empty)').setEnabled(False)
            return
        for target_id, name in elements:
            menu.addAction(
                f'Remove {name}',
                lambda tid=target_id: model.remove_element(row, slot, tid),
            )

    # ------------------------------------------------------------------
    # Keyboard shortcuts
    # ------------------------------------------------------------------

    def keyPressEvent(self, event):
        model = self.model()
        if model is None:
            super().keyPressEvent(event)
            return

        key = event.key()
        modifiers = event.modifiers()

        if modifiers == Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_PageUp:
                row = self._current_row()
                if row >= 0:
                    model.move_rule_up(row)
                    self._select_row(max(row - 1, 0))
                return
            if key == Qt.Key.Key_PageDown:
                row = self._current_row()
                if row >= 0:
                    model.move_rule_down(row)
                    self._select_row(min(row + 1, model.rowCount() - 1))
                return

        if modifiers == Qt.KeyboardModifier.NoModifier:
            if key == Qt.Key.Key_Delete:
                rows = sorted({idx.row() for idx in self.selectedIndexes()})
                if rows:
                    model.delete_rules(rows)
                return
            if key == Qt.Key.Key_Insert:
                row = self._current_row()
                if row >= 0:
                    model.insert_rule(row + 1)
                else:
                    model.insert_rule(at_bottom=True)
                return

        super().keyPressEvent(event)

    def _current_row(self):
        idx = self.currentIndex()
        return idx.row() if idx.isValid() else -1

    def _select_row(self, row):
        model = self.model()
        if model is not None and 0 <= row < model.rowCount():
            idx = model.index(row, 0)
            self.setCurrentIndex(idx)
            self.selectRow(row)

    # ------------------------------------------------------------------
    # Drop support
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if not event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return
        index = self.indexAt(event.position().toPoint())
        if index.isValid() and index.column() in _ELEMENT_COLS:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        mime = event.mimeData()
        if not mime.hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return

        index = self.indexAt(event.position().toPoint())
        if not index.isValid() or index.column() not in _ELEMENT_COLS:
            event.ignore()
            return

        try:
            payload = json.loads(bytes(mime.data(FWF_MIME_TYPE)).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            event.ignore()
            return

        obj_id = payload.get('id')
        obj_type = payload.get('type', '')
        if not obj_id:
            event.ignore()
            return

        slot = _COL_TO_SLOT[index.column()]
        valid_types = _VALID_TYPES_BY_SLOT.get(slot, frozenset())
        if obj_type not in valid_types:
            event.ignore()
            return

        model = self.model()
        if model is not None:
            model.add_element(index.row(), slot, uuid.UUID(obj_id))
        event.acceptProposedAction()
