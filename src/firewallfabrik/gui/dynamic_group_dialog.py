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

"""Editor panel dialog for DynamicGroup objects.

Ports fwbuilder's DynamicGroupDialog — three-panel layout with criteria
table, live matched-objects preview, and comment/keywords.
"""

import copy
import logging

import sqlalchemy
import sqlalchemy.orm
from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QIcon, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QComboBox,
    QHeaderView,
    QStyledItemDelegate,
    QToolButton,
    QTreeWidgetItem,
)

from firewallfabrik.core.objects import Address, Group, Host
from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.group_dialog import _get_object_properties

logger = logging.getLogger(__name__)

# fwbuilder constants (DynamicGroup.cpp).
_TYPE_NONE = 'none'
_TYPE_ANY = 'any'
_KEYWORD_NONE = ','
_KEYWORD_ANY = ''

# Object types eligible for dynamic group membership, matching
# fwbuilder's FWBTree::getObjectTypes() — alphabetically sorted.
_OBJECT_TYPES = [
    ('AddressRange', 'Address Range'),
    ('AddressTable', 'Address Table'),
    ('Cluster', 'Cluster'),
    ('DNSName', 'DNS Name'),
    ('DynamicGroup', 'Dynamic Group'),
    ('Firewall', 'Firewall'),
    ('Host', 'Host'),
    ('IPv4', 'Address'),
    ('IPv6', 'Address IPv6'),
    ('Network', 'Network'),
    ('NetworkIPv6', 'Network IPv6'),
    ('ObjectGroup', 'Object Group'),
]

# Types that are considered "Address-like" (Address::cast succeeds)
# or ObjectGroup (ObjectGroup::cast succeeds) in fwbuilder.
_ADDRESS_TYPE_NAMES = frozenset(
    {
        'AddressRange',
        'AddressTable',
        'AttachedNetworks',
        'DNSName',
        'DynamicGroup',
        'IPv4',
        'IPv6',
        'MultiAddress',
        'MultiAddressRunTime',
        'Network',
        'NetworkIPv6',
        'PhysAddress',
    }
)
_GROUP_TYPE_NAMES = frozenset(
    {
        'ObjectGroup',
    }
)
_DEVICE_TYPE_NAMES = frozenset(
    {
        'Cluster',
        'Firewall',
        'Host',
    }
)


class _CriteriaDelegate(QStyledItemDelegate):
    """Delegate that provides delete button / combo editors for the criteria table."""

    def __init__(self, dialog, parent=None):
        super().__init__(parent)
        self._dialog = dialog

    def createEditor(self, parent, option, index):
        col = index.column()

        if col == 0:
            button = QToolButton(parent)
            button.setIcon(QIcon(':/Icons/neg'))
            button.setProperty('row', index.row())
            button.clicked.connect(self._dialog._delete_filter_clicked)
            return button

        combo = QComboBox(parent)
        combo.activated.connect(lambda _idx, c=combo: self.commitData.emit(c))
        return combo

    def setEditorData(self, editor, index):
        if index.column() == 0:
            return

        value = index.model().data(index, Qt.ItemDataRole.EditRole) or ''
        combo = editor
        combo.clear()

        if index.column() == 1:
            # Type column.
            if value == _TYPE_NONE:
                combo.addItem('None selected', _TYPE_NONE)
                combo.setCurrentIndex(0)
            combo.addItem('Any type', _TYPE_ANY)
            if value == _TYPE_ANY:
                combo.setCurrentIndex(combo.count() - 1)
            combo.insertSeparator(combo.count())
            for type_key, type_label in _OBJECT_TYPES:
                combo.addItem(type_label, type_key)
                if value == type_key:
                    combo.setCurrentIndex(combo.count() - 1)

        elif index.column() == 2:
            # Tag column.
            if value == _KEYWORD_NONE:
                combo.addItem('None selected', _KEYWORD_NONE)
                combo.setCurrentIndex(0)
            combo.addItem('Any tag', _KEYWORD_ANY)
            if value == _KEYWORD_ANY:
                combo.setCurrentIndex(combo.count() - 1)
            combo.insertSeparator(combo.count())
            for tag in sorted(self._dialog._all_tags):
                combo.addItem(tag, tag)
                if value == tag:
                    combo.setCurrentIndex(combo.count() - 1)

    def setModelData(self, editor, model, index):
        if index.column() == 0:
            return
        combo = editor
        value = combo.itemData(combo.currentIndex())
        model.setData(index, value, Qt.ItemDataRole.EditRole)


class DynamicGroupDialog(BaseObjectDialog):
    """Editor for DynamicGroup objects with criteria table and matched-objects preview."""

    navigate_to_object = Signal(str, str)  # (obj_id_hex, obj_type)

    def __init__(self, parent=None):
        super().__init__('dynamicgroupdialog_q.ui', parent)

        self._db_manager = None
        self._all_tags = set()

        # Criteria table model: columns Del | Type | Tag.
        self._criteria_model = QStandardItemModel(self)
        self._criteria_model.setHorizontalHeaderLabels(['Del', 'Type', 'Tag'])
        self._criteria_model.dataChanged.connect(self._on_criteria_changed)

        self._delegate = _CriteriaDelegate(self, self.criteriaView)
        self.criteriaView.setItemDelegate(self._delegate)
        self.criteriaView.setModel(self._criteria_model)
        self.criteriaView.verticalHeader().hide()

        # Matched objects tree.
        self.matchedView.itemDoubleClicked.connect(self._on_matched_double_click)

    def set_db_manager(self, db_manager):
        """Set the database manager (called once from EditorManager)."""
        self._db_manager = db_manager

    def load_object(self, obj, *, all_tags=None):
        """Override to store all_tags for tag dropdown."""
        self._all_tags = all_tags or set()
        super().load_object(obj, all_tags=all_tags)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self._load_criteria()
        self._refresh_matched_objects()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()

        # Read criteria from the model, skipping incomplete rows.
        criteria = []
        for row in range(self._criteria_model.rowCount()):
            type_val = (
                self._criteria_model.data(
                    self._criteria_model.index(row, 1),
                    Qt.ItemDataRole.EditRole,
                )
                or _TYPE_NONE
            )
            keyword_val = (
                self._criteria_model.data(
                    self._criteria_model.index(row, 2),
                    Qt.ItemDataRole.EditRole,
                )
                or _KEYWORD_NONE
            )
            # Skip rows where type or keyword is unset (matching
            # fwbuilder's DynamicGroup::makeFilter — returns false
            # when type==TYPE_NONE or keyword==KEYWORD_NONE).
            if type_val == _TYPE_NONE or keyword_val == _KEYWORD_NONE:
                continue
            criteria.append({'keyword': keyword_val, 'type': type_val})

        data = copy.deepcopy(self._obj.data or {})
        data['selection_criteria'] = criteria
        self._obj.data = data

    # ------------------------------------------------------------------
    # Criteria table
    # ------------------------------------------------------------------

    def _load_criteria(self):
        """Populate the criteria table from the current object's data."""
        # Remove rows instead of clear() to avoid header flicker
        # (matching fwbuilder's approach).
        while self._criteria_model.rowCount() > 0:
            self._criteria_model.removeRow(0)
        self._criteria_model.setHorizontalHeaderLabels(['Del', 'Type', 'Tag'])

        criteria = (self._obj.data or {}).get('selection_criteria', [])
        for entry in criteria:
            type_val = entry.get('type', _TYPE_NONE)
            keyword_val = entry.get('keyword', _KEYWORD_NONE)
            self._append_criteria_row(type_val, keyword_val)

        self._resize_criteria_headers()

    def _append_criteria_row(self, type_val, keyword_val):
        """Append a new row to the criteria table and open persistent editors."""
        items = [
            QStandardItem(''),
            QStandardItem(type_val),
            QStandardItem(keyword_val),
        ]
        self._criteria_model.appendRow(items)
        row = self._criteria_model.rowCount() - 1
        self.criteriaView.openPersistentEditor(self._criteria_model.index(row, 0))
        self.criteriaView.openPersistentEditor(self._criteria_model.index(row, 1))
        self.criteriaView.openPersistentEditor(self._criteria_model.index(row, 2))

    def _resize_criteria_headers(self):
        """Configure header resize modes matching fwbuilder."""
        header = self.criteriaView.horizontalHeader()
        header.resizeSection(0, 35)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)

    @Slot()
    def addMatchClicked(self):
        """Add a new empty criteria row (wired from .ui connection)."""
        self._append_criteria_row(_TYPE_NONE, _KEYWORD_NONE)
        self._resize_criteria_headers()
        self.criteriaView.scrollToBottom()
        self.changed.emit()

    @Slot()
    def _delete_filter_clicked(self):
        """Remove the criteria row whose delete button was clicked."""
        button = self.sender()
        if button is None:
            return
        row = button.property('row')
        if row is None:
            return
        self._criteria_model.removeRow(row)
        self._refresh_matched_objects()
        self.changed.emit()

    @Slot()
    def _on_criteria_changed(self):
        """Refresh matched objects when a criterion value changes."""
        if not self._loading:
            self._refresh_matched_objects()

    # ------------------------------------------------------------------
    # Matched objects
    # ------------------------------------------------------------------

    def _refresh_matched_objects(self):
        """Rebuild the matched-objects tree based on current criteria."""
        self.matchedView.clear()

        if self._db_manager is None or self._obj is None:
            return

        # Build current criteria list from the model.
        criteria = []
        for row in range(self._criteria_model.rowCount()):
            type_val = (
                self._criteria_model.data(
                    self._criteria_model.index(row, 1),
                    Qt.ItemDataRole.EditRole,
                )
                or _TYPE_NONE
            )
            keyword_val = (
                self._criteria_model.data(
                    self._criteria_model.index(row, 2),
                    Qt.ItemDataRole.EditRole,
                )
                or _KEYWORD_NONE
            )
            if type_val == _TYPE_NONE or keyword_val == _KEYWORD_NONE:
                continue
            criteria.append((type_val, keyword_val))

        if not criteria:
            return

        session = sqlalchemy.orm.object_session(self._obj)
        if session is None:
            return

        self_id = self._obj.id

        # Query all candidate objects (Address-like, ObjectGroup, and
        # device types) and check each against the criteria.
        for cls in (Address, Group, Host):
            try:
                objs = session.scalars(sqlalchemy.select(cls)).unique().all()
            except Exception:
                logger.debug('Failed to query %s for matched objects', cls.__name__)
                continue
            for obj in objs:
                if obj.id == self_id:
                    continue
                if not self._is_member(obj, criteria):
                    continue
                self._add_matched_item(obj)

        self.matchedView.resizeColumnToContents(0)
        self.matchedView.resizeColumnToContents(1)

    def _is_member(self, obj, criteria):
        """Port of fwbuilder's DynamicGroup::isMemberOfGroup().

        Returns True if *obj* matches any of the given *criteria* tuples
        ``(type_str, keyword_str)``.
        """
        obj_type = getattr(obj, 'type', '')

        # Only Address-like objects, ObjectGroups, and device types are
        # eligible (mirrors the C++ Address::cast / ObjectGroup::cast
        # checks).
        if obj_type not in _ADDRESS_TYPE_NAMES | _GROUP_TYPE_NAMES | _DEVICE_TYPE_NAMES:
            return False

        # Exclude objects in a deleted-objects library.
        lib = getattr(obj, 'library', None)
        if lib is None:
            return False
        lib_name = getattr(lib, 'name', '')
        if lib_name == 'Deleted Objects':
            return False

        # For ObjectGroup types, exclude "standard" groups near the
        # root (distance <= 3).  We approximate fwbuilder's
        # getDistanceFromRoot() by counting parent_group levels + 2
        # (Library → top-level group → child group).
        if obj_type in _GROUP_TYPE_NAMES:
            depth = 2  # Library (1) + the group container itself (2)
            parent = getattr(obj, 'parent_group', None)
            while parent is not None:
                depth += 1
                parent = getattr(parent, 'parent_group', None)
            if depth <= 3:
                return False

        keywords = getattr(obj, 'keywords', None) or set()

        for type_val, keyword_val in criteria:
            type_match = type_val == _TYPE_ANY or obj_type == type_val
            keyword_match = keyword_val == _KEYWORD_ANY or keyword_val in keywords
            if type_match and keyword_match:
                return True

        return False

    def _add_matched_item(self, obj):
        """Add a matched object to the tree widget."""
        obj_type = getattr(obj, 'type', '')
        name = getattr(obj, 'name', '')
        props = _get_object_properties(obj)

        item = QTreeWidgetItem([name, props])
        icon_path = f':/Icons/{obj_type}/icon-ref'
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.ItemDataRole.UserRole, str(obj.id))
        item.setData(0, Qt.ItemDataRole.UserRole + 1, obj_type)
        self.matchedView.addTopLevelItem(item)

    @Slot(QTreeWidgetItem, int)
    def _on_matched_double_click(self, item, _column):
        """Navigate to the double-clicked matched object."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_id and obj_type:
            self.navigate_to_object.emit(obj_id, obj_type)
