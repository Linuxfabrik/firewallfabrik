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

"""Table model for displaying policy rules in a QTableView."""

from PySide6.QtCore import QAbstractTableModel, Qt
from PySide6.QtGui import QColor, QIcon

HEADERS = [
    '#',
    'Source',
    'Destination',
    'Service',
    'Interface',
    'Direction',
    'Action',
    'Comment',
]

_COL_DIRECTION = 5
_COL_ACTION = 6

_ACTION_COLORS = {
    'Accept': QColor(200, 255, 200),
    'Deny': QColor(255, 200, 200),
    'Reject': QColor(255, 230, 200),
}

_DIRECTION_ICONS = {
    'Inbound': ':/Icons/Inbound/icon-tree',
    'Outbound': ':/Icons/Outbound/icon-tree',
    'Both': ':/Icons/Both/icon-tree',
}


class PolicyTableModel(QAbstractTableModel):
    """Flat table model for policy rules. Receives pre-built row dicts."""

    def __init__(self, rows, parent=None):
        super().__init__(parent)
        self._rows = rows
        self._keys = [
            'position',
            'src',
            'dst',
            'srv',
            'itf',
            'direction',
            'action',
            'comment',
        ]

    def rowCount(self, parent=None):
        return len(self._rows)

    def columnCount(self, parent=None):
        return len(HEADERS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return self._rows[index.row()].get(self._keys[index.column()], '')

        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.BackgroundRole:
            action = row.get('action', '')
            return _ACTION_COLORS.get(action)

        if role == Qt.ItemDataRole.DecorationRole:
            if col == _COL_ACTION:
                action = row.get('action', '')
                icon_path = f':/Icons/{action}/icon-tree'
                icon = QIcon(icon_path)
                if not icon.isNull():
                    return icon
            elif col == _COL_DIRECTION:
                direction = row.get('direction', '')
                icon_path = _DIRECTION_ICONS.get(direction)
                if icon_path:
                    return QIcon(icon_path)

        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
        ):
            return HEADERS[section]
        return None
