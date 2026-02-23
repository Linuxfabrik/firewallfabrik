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

"""Drop area widget for receiving objects dragged from the tree."""

import dataclasses
import json
import uuid

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QFrame, QLabel, QMenu, QVBoxLayout

from firewallfabrik.gui.policy_model import FWF_MIME_TYPE


@dataclasses.dataclass
class _DroppedObject:
    id: uuid.UUID
    name: str
    type: str


class FWObjectDropArea(QFrame):
    """Drop-target that accepts objects dragged from the object tree.

    Displays the dropped object's icon and name, or a helper text when empty.
    """

    objectInserted = Signal()
    objectDeleted = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._obj: _DroppedObject | None = None
        self._helper_text = 'Drop object here'

        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setMinimumSize(100, 80)
        self.setMaximumSize(200, 80)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._icon_label)

        self._text_label = QLabel(self._helper_text)
        self._text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._text_label.setWordWrap(True)
        layout.addWidget(self._text_label)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def insert_object(self, obj_id, name, obj_type):
        """Set the displayed object."""
        self._obj = _DroppedObject(id=obj_id, name=name, type=obj_type)
        icon = QIcon(f':/Icons/{obj_type}/icon')
        pixmap = icon.pixmap(25, 25)
        if not pixmap.isNull():
            self._icon_label.setPixmap(pixmap)
        else:
            self._icon_label.clear()
        self._text_label.setText(name)
        self.objectInserted.emit()

    def delete_object(self):
        """Clear the displayed object."""
        self._obj = None
        self._icon_label.clear()
        self._text_label.setText(self._helper_text)
        self.objectDeleted.emit()

    def is_empty(self):
        """Return True if no object is set."""
        return self._obj is None

    def get_object_id(self):
        """Return the UUID of the dropped object, or None."""
        return self._obj.id if self._obj else None

    def get_object_type(self):
        """Return the type string of the dropped object, or None."""
        return self._obj.type if self._obj else None

    def get_object_name(self):
        """Return the name of the dropped object, or None."""
        return self._obj.name if self._obj else None

    def set_helper_text(self, text):
        """Set the placeholder text shown when no object is dropped."""
        self._helper_text = text
        if self._obj is None:
            self._text_label.setText(text)

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            self.setProperty('dragOver', True)
            self.style().unpolish(self)
            self.style().polish(self)
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.setProperty('dragOver', False)
        self.style().unpolish(self)
        self.style().polish(self)
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        self.setProperty('dragOver', False)
        self.style().unpolish(self)
        self.style().polish(self)

        mime = event.mimeData()
        if not mime.hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return

        try:
            payload = json.loads(bytes(mime.data(FWF_MIME_TYPE)).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            event.ignore()
            return

        # The tree encodes a list of entries; take the first one.
        if isinstance(payload, list):
            if not payload:
                event.ignore()
                return
            payload = payload[0]

        obj_id = payload.get('id')
        obj_type = payload.get('type', '')
        obj_name = payload.get('name', '')
        if not obj_id:
            event.ignore()
            return

        self.insert_object(uuid.UUID(obj_id), obj_name, obj_type)
        event.acceptProposedAction()

    def _show_context_menu(self, pos):
        if self._obj is None:
            return
        menu = QMenu(self)
        delete_action = QAction('Delete', self)
        delete_action.triggered.connect(self.delete_object)
        menu.addAction(delete_action)
        menu.exec(self.mapToGlobal(pos))
