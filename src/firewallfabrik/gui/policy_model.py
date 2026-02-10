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

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

HEADERS = ['#', 'Source', 'Destination', 'Service', 'Interface',
           'Direction', 'Action', 'Comment']


class PolicyTableModel(QAbstractTableModel):
    """Flat table model for policy rules. Receives pre-built row dicts."""

    def __init__(self, rows, parent=None):
        super().__init__(parent)
        self._rows = rows
        self._keys = ['position', 'src', 'dst', 'srv', 'itf',
                      'direction', 'action', 'comment']

    def rowCount(self, parent=QModelIndex()):
        return len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(HEADERS)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole or not index.isValid():
            return None
        return self._rows[index.row()].get(self._keys[index.column()], '')

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return HEADERS[section]
        return None
