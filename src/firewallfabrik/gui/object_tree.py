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

"""Object tree panel for the main window."""

import json
import uuid
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QMimeData, QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QDrag, QFont, QIcon, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    Library,
    RuleSet,
    group_membership,
)
from firewallfabrik.gui.object_tree_data import (
    CATEGORY_ICON,
    ICON_MAP,
    LOCK_ICON,
    LOCKABLE_TYPES,
    MODEL_MAP,
    NEW_TYPES_FOR_FOLDER,
    NO_COPY_TYPES,
    NO_DELETE_TYPES,
    NON_DRAGGABLE_TYPES,
    RULE_SET_TYPES,
    SERVICE_OBJ_TYPES,
    SYSTEM_ROOT_FOLDERS,
    SYSTEM_SUB_FOLDERS,
    create_library_folder_structure,
    is_inactive,
    needs_compile,
    normalize_subfolders,
    obj_brief_attrs,
    obj_display_name,
    obj_sort_key,
    obj_tags,
    tags_to_str,
)
from firewallfabrik.gui.object_tree_menu import (
    build_category_context_menu,
    build_object_context_menu,
)
from firewallfabrik.gui.object_tree_ops import TreeOperations
from firewallfabrik.gui.policy_model import FWF_MIME_TYPE
from firewallfabrik.gui.tooltip_helpers import get_library_name, obj_tooltip

# Re-export for backward compatibility (main_window.py imports these).
__all__ = ['ICON_MAP', 'ObjectTree', 'create_library_folder_structure']

_obj_tooltip = obj_tooltip
_get_library_name = get_library_name

# Module-level clipboard shared across all ObjectTree instances.
_tree_clipboard: list[dict] | None = (
    None  # [{'id': str, 'type': str, 'cut': bool}, ...]
)


class _DraggableTree(QTreeWidget):
    """QTreeWidget subclass with drag & drop support for object items.

    Drag produces a JSON payload under :data:`FWF_MIME_TYPE`.
    Drop is accepted when items are moved within the same tree
    (internal move between folders / groups).
    """

    # Signal emitted on a valid internal drop.
    # Args: (target_item, list_of_payload_dicts)
    items_dropped = Signal(QTreeWidgetItem, list)

    def mimeTypes(self):
        return [FWF_MIME_TYPE]

    def mimeData(self, items):
        if not items:
            return None
        entries = []
        for item in items:
            obj_id = item.data(0, Qt.ItemDataRole.UserRole)
            obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
            if not obj_id or not obj_type or obj_type in NON_DRAGGABLE_TYPES:
                continue
            entries.append(
                {
                    'id': obj_id,
                    'name': item.text(0),
                    'type': obj_type,
                }
            )
        if not entries:
            return None
        payload = json.dumps(entries).encode()
        mime = QMimeData()
        mime.setData(FWF_MIME_TYPE, payload)
        return mime

    def startDrag(self, supported_actions):
        """Start a drag with the object's type icon as cursor pixmap.

        When dragging 2+ items, a red circle with the count number is
        drawn on top of the first item's icon (matches fwbuilder's
        ``ObjectTreeView::startDrag`` badge).
        """
        items = self.selectedItems()
        mime = self.mimeData(items)
        if mime is None:
            return

        # Count valid (non-category, non-structural) items.
        valid_items = [
            it
            for it in items
            if it.data(0, Qt.ItemDataRole.UserRole)
            and it.data(0, Qt.ItemDataRole.UserRole + 1)
            and it.data(0, Qt.ItemDataRole.UserRole + 1) not in NON_DRAGGABLE_TYPES
        ]
        first = valid_items[0] if valid_items else items[0]
        obj_type = first.data(0, Qt.ItemDataRole.UserRole + 1)

        drag = QDrag(self)
        drag.setMimeData(mime)

        icon_path = ICON_MAP.get(obj_type)
        if icon_path:
            pm = QIcon(icon_path).pixmap(25, 25)
            if len(valid_items) > 1:
                # Composite pixmap with red count badge.
                from PySide6.QtGui import QPixmap

                npm = QPixmap(32, 32)
                npm.fill(QColor(0, 0, 0, 0))
                p = QPainter(npm)
                p.drawPixmap(0, 32 - pm.height(), pm)
                p.setPen(QColor('red'))
                p.setBrush(QColor('red'))
                p.drawEllipse(16, 0, 16, 16)
                txt = str(len(valid_items))
                p.setPen(QColor('white'))
                p.setFont(QFont('sans-serif', 8, QFont.Weight.Bold))
                br = p.boundingRect(16, 0, 16, 16, Qt.AlignmentFlag.AlignCenter, txt)
                p.drawText(br, Qt.AlignmentFlag.AlignCenter, txt)
                p.end()
                drag.setPixmap(npm)
            else:
                drag.setPixmap(pm)

        drag.exec(supported_actions)

    # -- Drop handling --------------------------------------------------

    def dragEnterEvent(self, event):
        if event.source() is self and event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return
        dest = self.itemAt(event.position().toPoint())
        if dest is None:
            event.ignore()
            return
        event.acceptProposedAction()

    def dropEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return
        dest = self.itemAt(event.position().toPoint())
        if dest is None:
            event.ignore()
            return
        data = event.mimeData().data(FWF_MIME_TYPE).data()
        try:
            entries = json.loads(data)
        except (ValueError, TypeError):
            event.ignore()
            return
        event.acceptProposedAction()
        self.items_dropped.emit(dest, entries)


class ObjectTree(QWidget):
    """Left-hand object tree panel with filter field and library selector."""

    rule_set_activated = Signal(str, str, str, str)
    """Emitted when a rule set node is double-clicked: (rule_set_id, firewall_name, rule_set_name, rule_set_type)."""

    object_activated = Signal(str, str)
    """Emitted when a non-rule-set object is double-clicked: (obj_id, obj_type)."""

    tree_changed = Signal(str, str)
    """Emitted after a CRUD operation to trigger a tree refresh.

    Args: ``(activate_obj_id, activate_obj_type)``.
    When non-empty, the editor for that object is opened after the rebuild.
    When both are empty strings, no editor is opened.
    """

    find_requested = Signal(str, str, str)
    """Emitted when "Find" is chosen from the context menu: (obj_id, name, obj_type)."""

    where_used_requested = Signal(str, str, str)
    """Emitted when "Where used" is chosen: (obj_id, name, obj_type)."""

    compile_requested = Signal()
    """Emitted when "Compile" is chosen from the context menu."""

    install_requested = Signal()
    """Emitted when "Install" is chosen from the context menu."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText('Filter... (Ctrl+F)')
        self._filter.setClearButtonEnabled(True)

        shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        shortcut.activated.connect(self._filter.setFocus)

        self._tree = _DraggableTree()
        self._tree.setHeaderLabels(['Object', 'Attribute'])
        self._tree.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection,
        )
        self._tree.setDragEnabled(True)
        self._tree.setAcceptDrops(True)
        self._tree.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self._tree.setDefaultDropAction(Qt.DropAction.MoveAction)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)

        self._db_manager = None
        self._ops = TreeOperations()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._filter)
        layout.addWidget(self._tree)

        self._show_attrs = QSettings().value(
            'UI/ShowObjectsAttributesInTree', True, type=bool
        )
        self._tooltips_enabled = QSettings().value('UI/ObjTooltips', True, type=bool)
        self._applying_saved_width = False
        self._apply_column_setup()

        # One-time cleanup of stale keys from an earlier implementation.
        settings = QSettings()
        if settings.value('TreeState') is not None:
            settings.remove('TreeState')
            settings.sync()

        self._tree.header().sectionResized.connect(self._on_section_resized)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        self._tree.items_dropped.connect(self._on_items_dropped)
        self._filter.textChanged.connect(self._apply_filter)

    def populate(self, session, file_key=''):
        """Build the tree from all libraries in *session*.

        *file_key* identifies the loaded file (typically ``str(path)``).
        When set, the expand/collapse state is restored from QSettings
        if no in-memory state exists (i.e. first open of this file in
        the current session).
        """
        had_tree = self._tree.topLevelItemCount() > 0
        expanded = self._save_expanded_state()
        # Detach selection before clearing to prevent a segfault in
        # Shiboken::Object::setParent() when clear() destroys the
        # currently selected QTreeWidgetItem during a nested signal chain.
        self._tree.setCurrentItem(None)
        self._tree.clear()
        self._filter.clear()

        libraries = session.scalars(sqlalchemy.select(Library)).all()

        # Sort so "User" comes first, "Standard" last, others alphabetical.
        def _lib_order(lib):
            if lib.name == 'User':
                return (0, '')
            if lib.name == 'Standard':
                return (2, '')
            return (1, lib.name.lower())

        libraries.sort(key=_lib_order)

        self._building_device_ro = False
        self._building_lib_ro = False

        self._groups_with_members = set(
            session.scalars(
                sqlalchemy.select(group_membership.c.group_id).distinct(),
            ).all()
        )

        root_ids = set(
            session.scalars(
                sqlalchemy.select(Group.id).where(
                    Group.parent_group_id.is_(None),
                ),
            ).all()
        )
        child_ids = (
            set(
                session.scalars(
                    sqlalchemy.select(Group.id).where(
                        Group.parent_group_id.in_(root_ids),
                    ),
                ).all()
            )
            if root_ids
            else set()
        )
        self._system_folder_groups = root_ids | child_ids

        for lib in libraries:
            self._building_lib_ro = getattr(lib, 'ro', False)
            self._building_device_ro = False
            lib_item = self._make_item(
                lib.name,
                'Library',
                str(lib.id),
                attrs=obj_brief_attrs(lib),
                effective_readonly=self._building_lib_ro,
                obj=lib,
                readonly=self._building_lib_ro,
            )
            self._tree.addTopLevelItem(lib_item)
            self._add_children(lib, lib_item)

        if had_tree:
            # In-memory state from a previous populate (e.g. undo/redo).
            self._restore_expanded_state(expanded)
        elif file_key:
            # Try QSettings for this file, otherwise use defaults.
            stored = self._load_tree_state(file_key)
            if stored is not None:
                self._restore_expanded_state(stored)
            else:
                self._apply_default_expand()
        else:
            self._apply_default_expand()

        # Defer column setup so Qt has finished layout/painting first;
        # otherwise ResizeToContents computes zero width for column 1.
        QTimer.singleShot(0, self._apply_column_setup)

    # ------------------------------------------------------------------
    # Tree state persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _item_path(item):
        """Build a stable path key from *item* to the tree root."""
        parts = []
        current = item
        while current:
            parts.append(current.text(0))
            current = current.parent()
        parts.reverse()
        return '/'.join(parts)

    def _save_expanded_state(self):
        """Collect path keys for all currently expanded tree items."""
        expanded = set()

        def _walk(item):
            if not item.isExpanded():
                return
            expanded.add(self._item_path(item))
            for i in range(item.childCount()):
                _walk(item.child(i))

        for i in range(self._tree.topLevelItemCount()):
            _walk(self._tree.topLevelItem(i))
        return expanded

    def _restore_expanded_state(self, expanded_ids):
        """Re-expand items whose path keys are in *expanded_ids*."""

        def _walk(item):
            item.setExpanded(self._item_path(item) in expanded_ids)
            for i in range(item.childCount()):
                _walk(item.child(i))

        for i in range(self._tree.topLevelItemCount()):
            _walk(self._tree.topLevelItem(i))

    def _apply_default_expand(self):
        """Collapse "Standard" library, expand everything else."""
        for i in range(self._tree.topLevelItemCount()):
            item = self._tree.topLevelItem(i)
            item.setExpanded(item.text(0) != 'Standard')

    def save_tree_state(self, file_key):
        """Persist current tree expand/collapse state to QSettings."""
        if not file_key or self._tree.topLevelItemCount() == 0:
            return
        expanded = self._save_expanded_state()
        settings = QSettings()
        all_states = self._read_all_tree_states(settings)
        all_states[file_key] = sorted(expanded)
        settings.setValue('UI/TreeExpandState', json.dumps(all_states))
        settings.sync()

    def _load_tree_state(self, file_key):
        """Load persisted expand state from QSettings, or *None*."""
        all_states = self._read_all_tree_states(QSettings())
        ids = all_states.get(file_key)
        if ids is not None:
            return set(ids)
        return None

    @staticmethod
    def _read_all_tree_states(settings):
        """Return the full ``{file_key: [ids]}`` dict from QSettings."""
        raw = settings.value('UI/TreeExpandState')
        if raw is None:
            return {}
        # QSettings may split comma-containing strings into a list.
        if isinstance(raw, list):
            raw = ','.join(str(x) for x in raw)
        if not isinstance(raw, str) or not raw:
            return {}
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_show_attrs(self, show):
        """Toggle the attribute column visibility."""
        self._show_attrs = show
        self._apply_column_setup()

    def set_db_manager(self, db_manager):
        """Set the database manager for context menu operations."""
        self._db_manager = db_manager
        self._ops = TreeOperations(db_manager)

    def set_tooltips_enabled(self, enabled):
        """Enable or disable tooltips on all existing tree items."""
        self._tooltips_enabled = enabled
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if not enabled:
                item.setToolTip(0, '')
                item.setToolTip(1, '')
            else:
                tip = item.data(0, Qt.ItemDataRole.UserRole + 4) or ''
                if tip:
                    item.setToolTip(0, tip)
                    if self._show_attrs:
                        item.setToolTip(1, tip)

    def _apply_column_setup(self):
        """Apply the current column count / resize mode."""
        if self._show_attrs:
            self._tree.setColumnCount(2)
            self._tree.setHeaderHidden(False)
            header = self._tree.header()
            header.setStretchLastSection(True)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
            saved = QSettings().value('UI/ObjectTreeCol0Width', 0, type=int)
            if saved > 0:
                self._applying_saved_width = True
                header.resizeSection(0, saved)
                self._applying_saved_width = False
        else:
            self._tree.setColumnCount(1)
            self._tree.setHeaderHidden(True)

    def _on_section_resized(self, index, _old_size, new_size):
        """Persist column width when the user drags the header."""
        if index == 0 and not self._applying_saved_width:
            QSettings().setValue('UI/ObjectTreeCol0Width', new_size)

    # ------------------------------------------------------------------
    # Tree building helpers
    # ------------------------------------------------------------------

    def _add_children(self, lib, parent_item):
        """Add orphan objects and root groups from *lib* under *parent_item*."""
        children = [
            obj
            for obj in (
                list(lib.addresses)
                + list(lib.services)
                + list(lib.intervals)
                + list(lib.devices)
            )
            if obj.group_id is None
        ]
        children += [g for g in lib.groups if g.parent_group_id is None]
        children += [i for i in lib.interfaces if i.device_id is None]
        # Include user-created subfolders stored in lib.data.
        user_subfolders = normalize_subfolders(
            (getattr(lib, 'data', None) or {}).get('subfolders', [])
        )
        self._add_objects_with_folders(
            children,
            parent_item,
            extra_folders=user_subfolders,
        )

    def _add_object(self, obj, parent_item):
        """Create a tree item for *obj* and recurse into groups / devices."""
        type_str = getattr(obj, 'type', None) or type(obj).__name__
        obj_ro = getattr(obj, 'ro', False)
        effective_ro = self._building_lib_ro or obj_ro
        item = self._make_item(
            obj_display_name(obj),
            type_str,
            str(obj.id),
            parent_item,
            attrs=obj_brief_attrs(obj),
            effective_readonly=effective_ro,
            inactive=is_inactive(obj),
            obj=obj,
            readonly=obj_ro,
            tags=obj_tags(obj),
        )
        if isinstance(obj, Group):
            self._add_group_children(obj, item)
            if obj.id in self._system_folder_groups and not obj_ro:
                item.setIcon(0, QIcon(CATEGORY_ICON))
        elif isinstance(obj, Host):
            saved_device_ro = self._building_device_ro
            self._building_device_ro = obj_ro
            self._add_device_children(obj, item)
            self._building_device_ro = saved_device_ro

    def _add_group_children(self, group, parent_item):
        """Add child objects and sub-groups of *group*."""
        children = (
            list(group.addresses)
            + list(group.services)
            + list(group.intervals)
            + list(group.devices)
            + list(group.child_groups)
        )
        user_subfolders = normalize_subfolders(
            (getattr(group, 'data', None) or {}).get('subfolders', [])
        )
        self._add_objects_with_folders(
            children, parent_item, extra_folders=user_subfolders
        )

    def _add_objects_with_folders(self, objects, parent_item, *, extra_folders=None):
        """Add *objects* under *parent_item*, grouping by ``data.folder``.

        Folder paths may use ``/`` as a separator (e.g. ``'A/B/C'``)
        to represent nested subfolders.
        """
        sorted_objects = sorted(objects, key=obj_sort_key)
        folder_paths = {self._get_folder_name(obj) for obj in sorted_objects} - {''}
        if extra_folders:
            folder_paths |= set(extra_folders)
        folder_items = self._build_folder_hierarchy(folder_paths, parent_item)
        for obj in sorted_objects:
            folder_name = self._get_folder_name(obj)
            target = folder_items.get(folder_name, parent_item)
            self._add_object(obj, target)

    def _build_folder_hierarchy(self, folder_paths, parent_item):
        """Create nested category items from folder paths.

        Paths using ``/`` as separator (e.g. ``'A/B/C'``) produce a
        nested ``A -> B -> C`` hierarchy.  Intermediate nodes are
        created automatically.

        Returns a dict mapping full path strings to tree items.
        """
        result = {}
        for path in sorted(folder_paths, key=str.casefold):
            parts = path.split('/')
            current_parent = parent_item
            for i, part in enumerate(parts):
                prefix = '/'.join(parts[: i + 1])
                if prefix not in result:
                    result[prefix] = self._make_category(part, current_parent)
                current_parent = result[prefix]
        return result

    @staticmethod
    def _get_folder_name(obj):
        """Return the folder name for *obj*, or empty string."""
        data = getattr(obj, 'data', None) or {}
        return data.get('folder', '')

    def _add_device_children(self, device, parent_item):
        """Add rule sets and interfaces of *device*."""
        effective_ro = self._building_lib_ro or self._building_device_ro
        for rs in sorted(device.rule_sets, key=obj_sort_key):
            self._make_item(
                obj_display_name(rs),
                rs.type,
                str(rs.id),
                parent_item,
                effective_readonly=effective_ro,
                inactive=is_inactive(rs),
                obj=rs,
                readonly=getattr(rs, 'ro', False),
            )
        # Only add top-level interfaces; sub-interfaces are added
        # recursively inside _add_interface().
        top_ifaces = [i for i in device.interfaces if i.parent_interface_id is None]
        for iface in sorted(top_ifaces, key=lambda o: o.name.lower()):
            self._add_interface(iface, parent_item)

    def _add_interface(self, iface, parent_item):
        """Add an Interface node with sub-interfaces and addresses."""
        effective_ro = self._building_lib_ro or self._building_device_ro
        iface_item = self._make_item(
            obj_display_name(iface),
            'Interface',
            str(iface.id),
            parent_item,
            attrs=obj_brief_attrs(iface),
            effective_readonly=effective_ro,
            inactive=is_inactive(iface),
            obj=iface,
            readonly=getattr(iface, 'ro', False),
            tags=obj_tags(iface),
        )
        # Sub-interfaces (recursive).
        for sub in sorted(iface.sub_interfaces, key=lambda o: o.name.lower()):
            self._add_interface(sub, iface_item)
        for addr in sorted(iface.addresses, key=obj_sort_key):
            self._make_item(
                obj_display_name(addr),
                addr.type,
                str(addr.id),
                iface_item,
                attrs=obj_brief_attrs(addr, under_interface=True),
                effective_readonly=effective_ro,
                inactive=is_inactive(addr),
                obj=addr,
                readonly=getattr(addr, 'ro', False),
                tags=obj_tags(addr),
            )

    def _make_category(self, label, parent_item):
        """Create a non-selectable category folder item."""
        item = QTreeWidgetItem(parent_item, [label])
        item.setIcon(0, QIcon(CATEGORY_ICON))
        return item

    def _make_item(
        self,
        name,
        type_str,
        obj_id,
        parent_item=None,
        *,
        attrs=None,
        effective_readonly=False,
        inactive=False,
        obj=None,
        readonly=False,
        tags=None,
    ):
        """Create a tree item storing id, type, tags, and attrs in user roles."""
        item = QTreeWidgetItem([name])
        item.setData(0, Qt.ItemDataRole.UserRole, obj_id)
        item.setData(0, Qt.ItemDataRole.UserRole + 1, type_str)
        item.setData(0, Qt.ItemDataRole.UserRole + 2, tags_to_str(tags))
        item.setData(0, Qt.ItemDataRole.UserRole + 3, attrs or '')
        item.setData(0, Qt.ItemDataRole.UserRole + 5, effective_readonly)
        # Store object's own ro flag (for Lock/Unlock context menu).
        obj_ro = getattr(obj, 'ro', False) if obj is not None else False
        item.setData(0, Qt.ItemDataRole.UserRole + 7, obj_ro)
        if attrs:
            item.setText(1, attrs)
        if readonly:
            item.setIcon(0, QIcon(LOCK_ICON))
        else:
            icon_path = ICON_MAP.get(type_str)
            if icon_path:
                item.setIcon(0, QIcon(icon_path))
        needs_comp = needs_compile(obj) if obj is not None else False
        if inactive or needs_comp:
            font = item.font(0)
            font.setStrikeOut(inactive)
            font.setBold(not inactive and needs_comp)
            item.setFont(0, font)
        if obj is not None:
            tip = _obj_tooltip(obj)
            item.setData(0, Qt.ItemDataRole.UserRole + 4, tip)
            comment = getattr(obj, 'comment', None) or ''
            item.setData(0, Qt.ItemDataRole.UserRole + 6, comment.lower())
            if self._tooltips_enabled:
                item.setToolTip(0, tip)
                if self._show_attrs:
                    item.setToolTip(1, tip)
        if parent_item is not None:
            parent_item.addChild(item)
        return item

    def update_item(self, obj):
        """Refresh the tree item for *obj* (name, attrs, tooltip, tags)."""
        obj_id = str(obj.id)
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) != obj_id:
                continue

            item.setText(0, obj_display_name(obj))

            # Update icon (lock icon for locked objects).
            obj_ro = getattr(obj, 'ro', False)
            item.setData(0, Qt.ItemDataRole.UserRole + 7, obj_ro)
            type_str = item.data(0, Qt.ItemDataRole.UserRole + 1)
            if obj_ro:
                item.setIcon(0, QIcon(LOCK_ICON))
            elif obj.id in self._system_folder_groups:
                item.setIcon(0, QIcon(CATEGORY_ICON))
            else:
                icon_path = ICON_MAP.get(type_str)
                if icon_path:
                    item.setIcon(0, QIcon(icon_path))

            inactive = is_inactive(obj)
            font = item.font(0)
            font.setStrikeOut(inactive)
            font.setBold(not inactive and needs_compile(obj))
            item.setFont(0, font)

            attrs = obj_brief_attrs(obj)
            item.setData(0, Qt.ItemDataRole.UserRole + 3, attrs)
            item.setText(1, attrs)

            item.setData(0, Qt.ItemDataRole.UserRole + 2, tags_to_str(obj_tags(obj)))
            comment = getattr(obj, 'comment', None) or ''
            item.setData(0, Qt.ItemDataRole.UserRole + 6, comment.lower())

            tip = _obj_tooltip(obj)
            item.setData(0, Qt.ItemDataRole.UserRole + 4, tip)
            if self._tooltips_enabled:
                item.setToolTip(0, tip)
                if self._show_attrs:
                    item.setToolTip(1, tip)
            else:
                item.setToolTip(0, '')
                item.setToolTip(1, '')
            return

    def focus_filter(self):
        """Set keyboard focus to the filter input field."""
        self._filter.setFocus()

    def select_object(self, obj_id):
        """Find, expand, scroll to, and select the item with *obj_id*.

        Returns True if the item was found, False otherwise.
        """
        obj_id_str = str(obj_id)
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) == obj_id_str:
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                self._tree.scrollToItem(item)
                self._tree.setCurrentItem(item)
                return True
        return False

    def _expand_by_path(self, path_key):
        """Find the item matching *path_key* and expand it (and its ancestors)."""
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if self._item_path(item) == path_key:
                item.setExpanded(True)
                parent = item.parent()
                while parent:
                    parent.setExpanded(True)
                    parent = parent.parent()
                return

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def _apply_filter(self, text):
        """Hide items whose name does not match *text* (case-insensitive)."""
        text = text.strip().lower()
        if not text:
            self._reset_visibility()
            return

        # First pass: determine direct match per item.
        matched = set()
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) is None:
                continue
            tags_str = item.data(0, Qt.ItemDataRole.UserRole + 2) or ''
            comment_str = item.data(0, Qt.ItemDataRole.UserRole + 6) or ''
            match = (
                text in item.text(0).lower() or text in tags_str or text in comment_str
            )
            if self._show_attrs:
                attrs_str = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
                match = match or text in attrs_str.lower()
            if match:
                matched.add(id(item))

        # Second pass: hide non-matching items, show children of matches.
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            it += 1
            if item.data(0, Qt.ItemDataRole.UserRole) is None:
                continue
            if id(item) in matched or self._has_matched_ancestor(item, matched):
                item.setHidden(False)
            else:
                item.setHidden(True)

        # Ensure parents of visible items are also visible.
        it = QTreeWidgetItemIterator(
            self._tree,
            QTreeWidgetItemIterator.IteratorFlag.NotHidden,
        )
        while it.value():
            item = it.value()
            it += 1
            parent = item.parent()
            while parent:
                parent.setHidden(False)
                parent.setExpanded(True)
                parent = parent.parent()

    @staticmethod
    def _has_matched_ancestor(item, matched):
        """Return True if any ancestor of *item* is in *matched*."""
        parent = item.parent()
        while parent:
            if id(parent) in matched:
                return True
            parent = parent.parent()
        return False

    def _reset_visibility(self):
        """Restore all items to visible."""
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            it.value().setHidden(False)
            it += 1

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _on_double_click(self, item, _column):
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        type_str = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not type_str:
            return
        # System folders (Firewalls, Clusters, Objects, ...) are not editable.
        if self._is_system_group(item):
            return
        if type_str in RULE_SET_TYPES:
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self.rule_set_activated.emit(obj_id, fw_name, item.text(0), type_str)
        else:
            self.object_activated.emit(obj_id, type_str)

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------

    def _get_simplified_selection(self):
        """Return selected object items with redundant children removed."""
        raw = self._tree.selectedItems()
        items = [it for it in raw if it.data(0, Qt.ItemDataRole.UserRole) is not None]
        item_set = {id(it) for it in items}
        result = []
        for it in items:
            parent = it.parent()
            skip = False
            while parent is not None:
                if id(parent) in item_set:
                    skip = True
                    break
                parent = parent.parent()
            if not skip:
                result.append(it)
        return result

    # ------------------------------------------------------------------
    # Context menu dispatch
    # ------------------------------------------------------------------

    def _on_context_menu(self, pos):
        """Build and show the context menu for the right-clicked tree item."""
        item = self._tree.itemAt(pos)
        if item is None:
            return
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)

        # Category folder (no obj_id/obj_type): show only New items.
        if not obj_id or not obj_type:
            self._on_category_context_menu(item, pos)
            return

        selection = self._get_simplified_selection()
        writable_libraries = self._get_writable_libraries()

        # Gather tags for the Tags submenu.
        all_tags = TreeOperations.get_all_tags(self._db_manager)
        selected_tags = self._get_selected_tags(selection)

        # Determine Lock/Unlock state.
        obj_is_locked = item.data(0, Qt.ItemDataRole.UserRole + 7) or False
        lib_is_ro = self._get_library_ro(item)

        # Gather sibling interfaces for "Make subinterface of ...".
        sibling_interfaces = self._get_sibling_interfaces(item, obj_type)

        menu, handlers = build_object_context_menu(
            self,
            item,
            selection,
            all_tags=all_tags,
            clipboard=_tree_clipboard,
            count_selected_firewalls_fn=self._count_selected_firewalls,
            get_item_library_id_fn=self._get_item_library_id,
            is_deletable_fn=self._is_deletable,
            is_system_group_fn=self._is_system_group,
            lib_is_ro=lib_is_ro,
            obj_is_locked=obj_is_locked,
            selected_tags=selected_tags,
            sibling_interfaces=sibling_interfaces,
            writable_libraries=writable_libraries,
        )

        triggered = menu.exec(self._tree.viewport().mapToGlobal(pos))
        handler = handlers.get(triggered)
        # Schedule menu deletion so that Expand/Collapse lambdas
        # (which capture ``item``) release their references before
        # the next populate() → clear() cycle.
        menu.deleteLater()
        if handler is not None:
            method_name, *args = handler
            # Defer to the next event-loop iteration so all local
            # QTreeWidgetItem references (item, selection, handlers)
            # are released before the handler calls populate() →
            # clear().  Running clear() inside the
            # customContextMenuRequested signal chain causes a
            # Shiboken::Object::setParent() segfault.
            QTimer.singleShot(0, lambda m=method_name, a=args: getattr(self, m)(*a))

    def _on_category_context_menu(self, item, pos):
        """Show a context menu for category folder items."""
        has_mixed = any(
            it.data(0, Qt.ItemDataRole.UserRole)
            for it in self._tree.selectedItems()
            if it is not item
        )

        menu, handlers = build_category_context_menu(
            self,
            item,
            clipboard=_tree_clipboard,
            has_mixed_selection=has_mixed,
        )

        triggered = menu.exec(self._tree.viewport().mapToGlobal(pos))
        handler = handlers.get(triggered)
        menu.deleteLater()
        if handler is not None:
            method_name, *args = handler
            # Same deferred dispatch as _on_context_menu — see comment
            # there for the rationale (Shiboken segfault prevention).
            QTimer.singleShot(0, lambda m=method_name, a=args: getattr(self, m)(*a))

    # ------------------------------------------------------------------
    # Drag & drop
    # ------------------------------------------------------------------

    def _on_items_dropped(self, dest_item, entries):
        """Handle an internal drop: move objects into the target folder.

        *dest_item* is the QTreeWidgetItem the objects were dropped on.
        *entries* is a list of ``{'id': ..., 'type': ...}`` dicts from
        the MIME payload.
        """
        if self._db_manager is None or not entries:
            return

        # Determine target folder path.
        dest_type = dest_item.data(0, Qt.ItemDataRole.UserRole + 1)
        if dest_type is None:
            # Dropped on a category folder → set data.folder.
            target_folder = self._get_category_folder_path(dest_item)
        elif dest_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
            # Dropped on the parent group → clear data.folder.
            target_folder = ''
        else:
            # Dropped on a regular object → use its folder (i.e. same
            # folder as the sibling).
            target_folder = ''
            parent = dest_item.parent()
            while parent is not None:
                pt = parent.data(0, Qt.ItemDataRole.UserRole + 1)
                if pt is None:
                    target_folder = self._get_category_folder_path(parent)
                    break
                if pt in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup', 'Library'):
                    break
                parent = parent.parent()

        any_changed = False
        last_id = None
        for entry in entries:
            model_cls = MODEL_MAP.get(entry.get('type'))
            if model_cls is None:
                continue
            obj_id = uuid.UUID(entry['id'])
            if self._ops.set_object_folder(obj_id, model_cls, target_folder):
                any_changed = True
                last_id = obj_id

        if any_changed:
            self.tree_changed.emit('', '')
            if last_id is not None:
                QTimer.singleShot(0, lambda lid=last_id: self.select_object(lid))

    # ------------------------------------------------------------------
    # Context menu helpers
    # ------------------------------------------------------------------

    def _get_selected_tags(self, selection):
        """Return the union of keywords across all selected objects."""
        if self._db_manager is None:
            return set()
        tags = set()
        with self._db_manager.session() as session:
            for it in selection:
                oid = it.data(0, Qt.ItemDataRole.UserRole)
                otype = it.data(0, Qt.ItemDataRole.UserRole + 1)
                if not oid or not otype:
                    continue
                model_cls = MODEL_MAP.get(otype)
                if model_cls is None or not hasattr(model_cls, 'keywords'):
                    continue
                obj = session.get(model_cls, uuid.UUID(oid))
                if obj is not None and obj.keywords:
                    tags.update(obj.keywords)
        return tags

    @staticmethod
    def _get_library_ro(item):
        """Walk up the tree to find the Library and return its ro flag."""
        current = item
        while current is not None:
            if current.data(0, Qt.ItemDataRole.UserRole + 1) == 'Library':
                return current.data(0, Qt.ItemDataRole.UserRole + 7) or False
            current = current.parent()
        return False

    @staticmethod
    def _get_folder_parent_group_id(folder_item):
        """Return the owning group UUID for a virtual folder item, or None.

        Walks up through nested category items (those without an
        ``obj_type``) until a real Group is found.  Returns the
        group's UUID so subfolder operations target the group's
        ``data['subfolders']`` list.  Returns ``None`` if the owner
        is a Library (or not found).
        """
        current = folder_item.parent()
        while current is not None:
            current_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            current_id = current.data(0, Qt.ItemDataRole.UserRole)
            if (
                current_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup')
                and current_id
            ):
                return uuid.UUID(current_id)
            if current_type == 'Library':
                return None
            current = current.parent()
        return None

    @staticmethod
    def _get_category_folder_path(item):
        """Return the full folder path for a category item.

        Walks up through parent category items (those without an
        ``obj_type``) until a real object is reached.  Returns
        components joined with ``/``, e.g. ``'SubA/SubB'``.
        """
        parts = []
        current = item
        while current is not None:
            if current.data(0, Qt.ItemDataRole.UserRole + 1):
                break  # Real object — stop.
            parts.append(current.text(0))
            current = current.parent()
        parts.reverse()
        return '/'.join(parts)

    @staticmethod
    def _get_sibling_interfaces(item, obj_type):
        """Return ``[(iface_id, iface_name), ...]`` for "Make subinterface of ..." menu.

        Collects all top-level Interface siblings under the same device,
        excluding the current interface.
        """
        if obj_type != 'Interface':
            return []
        parent = item.parent()
        if parent is None:
            return []
        parent_type = parent.data(0, Qt.ItemDataRole.UserRole + 1)
        if parent_type not in ('Cluster', 'Firewall', 'Host'):
            return []
        current_id = item.data(0, Qt.ItemDataRole.UserRole)
        result = []
        for i in range(parent.childCount()):
            child = parent.child(i)
            child_type = child.data(0, Qt.ItemDataRole.UserRole + 1)
            child_id = child.data(0, Qt.ItemDataRole.UserRole)
            if child_type == 'Interface' and child_id and child_id != current_id:
                result.append((child_id, child.text(0)))
        result.sort(key=lambda t: t[1].casefold())
        return result

    # ------------------------------------------------------------------
    # Context menu action handlers
    # ------------------------------------------------------------------

    def _ctx_edit(self, item):
        """Open the editor for the context-menu item (Edit / Inspect)."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type in RULE_SET_TYPES:
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self.rule_set_activated.emit(obj_id, fw_name, item.text(0), obj_type)
        else:
            self.object_activated.emit(obj_id, obj_type)

    def _ctx_open_ruleset(self, item):
        """Open a rule set (distinct from Edit — shows the rule editor)."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type in RULE_SET_TYPES:
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self.rule_set_activated.emit(obj_id, fw_name, item.text(0), obj_type)

    # -- Find / Where used --

    def _ctx_find(self, item):
        """Emit find_requested for the given item."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole) or ''
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        name = item.text(0)
        self.find_requested.emit(obj_id, name, obj_type)

    def _ctx_where_used(self, item):
        """Emit where_used_requested for the given item."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole) or ''
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        name = item.text(0)
        self.where_used_requested.emit(obj_id, name, obj_type)

    # -- Compile / Install --

    def _ctx_compile(self):
        """Emit compile_requested."""
        self.compile_requested.emit()

    def _ctx_install(self):
        """Emit install_requested."""
        self.install_requested.emit()

    # -- Lock / Unlock --

    def _ctx_lock(self):
        """Lock all selected objects that support locking."""
        selection = self._get_simplified_selection()
        items = [
            (
                it.data(0, Qt.ItemDataRole.UserRole),
                it.data(0, Qt.ItemDataRole.UserRole + 1),
            )
            for it in selection
            if it.data(0, Qt.ItemDataRole.UserRole)
            and it.data(0, Qt.ItemDataRole.UserRole + 1) in LOCKABLE_TYPES
        ]
        if items and self._ops.lock_objects(items):
            self.tree_changed.emit('', '')

    def _ctx_unlock(self):
        """Unlock all selected objects that support locking."""
        selection = self._get_simplified_selection()
        items = [
            (
                it.data(0, Qt.ItemDataRole.UserRole),
                it.data(0, Qt.ItemDataRole.UserRole + 1),
            )
            for it in selection
            if it.data(0, Qt.ItemDataRole.UserRole)
            and it.data(0, Qt.ItemDataRole.UserRole + 1) in LOCKABLE_TYPES
        ]
        if items and self._ops.unlock_objects(items):
            self.tree_changed.emit('', '')

    # -- Tags --

    def _ctx_new_keyword(self):
        """Prompt for a new tag and add it to all selected objects."""
        keyword, ok = QInputDialog.getText(
            self._tree,
            'New Tag',
            'Enter tag:',
        )
        keyword = keyword.strip() if ok else ''
        if not keyword:
            return
        self._ctx_add_keyword(keyword)

    def _ctx_add_keyword(self, keyword):
        """Add *keyword* to all selected objects."""
        selection = self._get_simplified_selection()
        items = [
            (
                it.data(0, Qt.ItemDataRole.UserRole),
                it.data(0, Qt.ItemDataRole.UserRole + 1),
            )
            for it in selection
            if it.data(0, Qt.ItemDataRole.UserRole)
            and it.data(0, Qt.ItemDataRole.UserRole + 1)
        ]
        if items and self._ops.add_keyword(items, keyword):
            self.tree_changed.emit('', '')

    def _ctx_remove_keyword(self, keyword):
        """Remove *keyword* from all selected objects."""
        selection = self._get_simplified_selection()
        items = [
            (
                it.data(0, Qt.ItemDataRole.UserRole),
                it.data(0, Qt.ItemDataRole.UserRole + 1),
            )
            for it in selection
            if it.data(0, Qt.ItemDataRole.UserRole)
            and it.data(0, Qt.ItemDataRole.UserRole + 1)
        ]
        if items and self._ops.remove_keyword(items, keyword):
            self.tree_changed.emit('', '')

    # -- Make subinterface --

    def _ctx_make_subinterface(self, item, target_iface_id):
        """Move *item*'s interface under *target_iface_id* as a subinterface."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not obj_id:
            return
        if self._ops.make_subinterface(uuid.UUID(obj_id), uuid.UUID(target_iface_id)):
            self.tree_changed.emit('', '')

    # -- Duplicate --

    def _get_writable_libraries(self):
        """Return [(lib_id, lib_name), ...] for non-read-only libraries."""
        return TreeOperations.get_writable_libraries(self._db_manager)

    def _ctx_duplicate(self, item, target_lib_id):
        """Duplicate the object referenced by *item* into *target_lib_id*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        model_cls = MODEL_MAP.get(obj_type)
        if model_cls is None:
            return

        # When duplicating within the same library, preserve the parent
        # context so the clone appears at the same hierarchy level.
        kwargs = {}
        source_lib_id = self._get_item_library_id(item)
        if source_lib_id is not None and source_lib_id == target_lib_id:
            with self._db_manager.session() as session:
                source = session.get(model_cls, uuid.UUID(obj_id))
                if source is not None:
                    if hasattr(source, 'interface_id') and source.interface_id:
                        kwargs['target_interface_id'] = source.interface_id
                    elif hasattr(source, 'group_id') and source.group_id:
                        kwargs['target_group_id'] = source.group_id
                    elif hasattr(source, 'parent_group_id') and source.parent_group_id:
                        kwargs['target_group_id'] = source.parent_group_id

        prefix = self._get_device_prefix(item)
        new_id = self._ops.duplicate_object(
            uuid.UUID(obj_id),
            model_cls,
            target_lib_id,
            prefix=prefix,
            **kwargs,
        )
        if new_id is not None:
            self.tree_changed.emit(str(new_id), obj_type)
            QTimer.singleShot(0, lambda: self.select_object(new_id))

    # -- Move --

    @staticmethod
    def _get_item_library_id(item):
        """Walk up the tree to find the Library ancestor and return its UUID."""
        current = item
        while current is not None:
            if current.data(0, Qt.ItemDataRole.UserRole + 1) == 'Library':
                obj_id = current.data(0, Qt.ItemDataRole.UserRole)
                if obj_id:
                    return uuid.UUID(obj_id)
                return None
            current = current.parent()
        return None

    @staticmethod
    def _get_device_prefix(item):
        """Walk up the tree and return ``'device_name: '`` if under a device."""
        _DEVICE_TYPES = frozenset({'Cluster', 'Firewall', 'Host'})
        current = item.parent() if item else None
        while current is not None:
            obj_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            if obj_type in _DEVICE_TYPES:
                return f'{current.text(0)}: '
            if obj_type == 'Library':
                return ''
            current = current.parent()
        return ''

    @staticmethod
    def _get_paste_context(item):
        """Determine the paste target from *item*'s position in the tree.

        Returns ``(interface_id, group_id)`` — at most one is non-None.
        """
        current = item
        while current is not None:
            obj_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            obj_id = current.data(0, Qt.ItemDataRole.UserRole)
            if obj_type == 'Interface' and obj_id:
                return uuid.UUID(obj_id), None
            if obj_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup') and obj_id:
                return None, uuid.UUID(obj_id)
            if obj_type == 'Library':
                break
            if obj_type in (
                'Cluster',
                'Firewall',
                'Host',
                'NAT',
                'Policy',
                'Routing',
            ):
                break
            current = current.parent()
        return None, None

    def _ctx_move(self, item, target_lib_id):
        """Move the object referenced by *item* to *target_lib_id*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        model_cls = MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        if self._ops.move_object(uuid.UUID(obj_id), model_cls, target_lib_id):
            self.tree_changed.emit(obj_id, obj_type)
            QTimer.singleShot(0, lambda: self.select_object(uuid.UUID(obj_id)))

    # -- Copy / Cut / Paste --

    def _ctx_copy(self):
        """Copy all selected object references to the tree clipboard."""
        global _tree_clipboard
        selection = self._get_simplified_selection()
        entries = []
        for it in selection:
            oid = it.data(0, Qt.ItemDataRole.UserRole)
            otype = it.data(0, Qt.ItemDataRole.UserRole + 1)
            if oid and otype and otype not in NO_COPY_TYPES:
                entries.append({'id': oid, 'type': otype, 'cut': False})
        if not entries:
            return
        _tree_clipboard = entries
        # Policy-view clipboard stays single-item for rule cell paste.
        first = selection[0]
        from firewallfabrik.gui.policy_view import PolicyView

        PolicyView._object_clipboard = {
            'id': first.data(0, Qt.ItemDataRole.UserRole),
            'name': first.text(0),
            'type': first.data(0, Qt.ItemDataRole.UserRole + 1),
        }

    def _ctx_cut(self):
        """Cut all selected object references to the tree clipboard."""
        global _tree_clipboard
        selection = self._get_simplified_selection()
        entries = []
        for it in selection:
            oid = it.data(0, Qt.ItemDataRole.UserRole)
            otype = it.data(0, Qt.ItemDataRole.UserRole + 1)
            ro = it.data(0, Qt.ItemDataRole.UserRole + 5) or False
            if oid and otype and otype not in NO_COPY_TYPES and not ro:
                entries.append({'id': oid, 'type': otype, 'cut': True})
        if not entries:
            return
        _tree_clipboard = entries
        first = selection[0]
        from firewallfabrik.gui.policy_view import PolicyView

        PolicyView._object_clipboard = {
            'id': first.data(0, Qt.ItemDataRole.UserRole),
            'name': first.text(0),
            'type': first.data(0, Qt.ItemDataRole.UserRole + 1),
        }

    def _ctx_paste(self, item):
        """Paste all clipboard objects relative to *item*."""
        global _tree_clipboard
        if _tree_clipboard is None or self._db_manager is None:
            return

        target_lib_id = self._get_item_library_id(item)
        if target_lib_id is None:
            return

        target_iface_id, target_group_id = self._get_paste_context(item)
        prefix = self._get_device_prefix(item)

        # When pasting into a category folder, store the folder path
        # on the pasted object so it appears in the correct subfolder.
        # When pasting into a real group/object, clear any existing
        # folder (empty string) so the object moves to the group root.
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type is None:
            target_folder = self._get_category_folder_path(item)
        elif target_group_id is not None:
            target_folder = ''
        else:
            target_folder = None

        any_cut = False
        last_id = None

        for cb in _tree_clipboard:
            cb_id = uuid.UUID(cb['id'])
            cb_type = cb['type']
            model_cls = MODEL_MAP.get(cb_type)
            if model_cls is None:
                continue

            if cb['cut']:
                any_cut = True
                if self._ops.move_object(
                    cb_id,
                    model_cls,
                    target_lib_id,
                    folder=target_folder,
                    target_group_id=target_group_id,
                ):
                    last_id = cb_id
            else:
                new_id = self._ops.duplicate_object(
                    cb_id,
                    model_cls,
                    target_lib_id,
                    folder=target_folder,
                    prefix=prefix,
                    target_interface_id=target_iface_id,
                    target_group_id=target_group_id,
                )
                if new_id is not None:
                    last_id = new_id

        if any_cut:
            _tree_clipboard = None

        if last_id is not None:
            self.tree_changed.emit('', '')
            QTimer.singleShot(0, lambda lid=last_id: self.select_object(lid))

    def _shortcut_copy(self):
        """Handle Ctrl+C — copy all selected objects."""
        selection = self._get_simplified_selection()
        if not selection:
            return
        if any(
            (it.data(0, Qt.ItemDataRole.UserRole + 1) or '') not in NO_COPY_TYPES
            for it in selection
        ):
            self._ctx_copy()

    def _shortcut_cut(self):
        """Handle Ctrl+X — cut all selected objects."""
        selection = self._get_simplified_selection()
        if not selection:
            return
        if any(
            (it.data(0, Qt.ItemDataRole.UserRole + 1) or '') not in NO_COPY_TYPES
            and not (it.data(0, Qt.ItemDataRole.UserRole + 5) or False)
            for it in selection
        ):
            self._ctx_cut()

    def _shortcut_paste(self):
        """Handle Ctrl+V — paste into the selected item's library."""
        item = self._tree.currentItem()
        if item is None:
            return
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if not effective_ro:
            self._ctx_paste(item)

    # -- Delete --

    def _ctx_delete(self, item):
        """Delete the object referenced by *item*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        if obj_type == 'Library':
            if self._delete_library(item):
                self.tree_changed.emit('', '')
            return
        model_cls = MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        obj_name = item.text(0)
        prefix = self._get_device_prefix(item)

        if self._ops.delete_object(
            uuid.UUID(obj_id),
            model_cls,
            obj_name,
            obj_type,
            prefix=prefix,
        ):
            self.tree_changed.emit('', '')

    def _delete_selected(self):
        """Delete all selected objects, filtering out non-deletable and read-only items."""
        selection = self._get_simplified_selection()
        any_deleted = False
        for it in selection:
            obj_id = it.data(0, Qt.ItemDataRole.UserRole)
            obj_type = it.data(0, Qt.ItemDataRole.UserRole + 1)
            if not obj_id or not obj_type:
                continue
            if not self._is_deletable(it):
                continue
            if obj_type == 'Library':
                if self._delete_library(it):
                    any_deleted = True
                continue
            model_cls = MODEL_MAP.get(obj_type)
            if model_cls is None:
                continue
            prefix = self._get_device_prefix(it)
            if self._ops.delete_object(
                uuid.UUID(obj_id),
                model_cls,
                it.text(0),
                obj_type,
                prefix=prefix,
            ):
                any_deleted = True
        if any_deleted:
            self.tree_changed.emit('', '')

    def _delete_library(self, item):
        """Delete a library after confirmation.  Returns True on success."""
        if self._db_manager is None:
            return False
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not obj_id:
            return False
        lib_name = item.text(0)
        result = QMessageBox.warning(
            self._tree,
            'FirewallFabrik',
            f'When you delete a library, all objects that belong to it '
            f'disappear from the tree and all groups and rules that '
            f'reference them.\n\n'
            f'Do you still want to delete library "{lib_name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return False

        return self._ops.delete_library(uuid.UUID(obj_id), lib_name)

    def _ctx_delete_folder(self, item):
        """Delete a user-created subfolder (and all nested children)."""
        lib_id = self._get_item_library_id(item)
        if lib_id is None:
            return
        folder_path = self._get_category_folder_path(item)
        parent_group_id = self._get_folder_parent_group_id(item)
        self._ops.delete_folder(lib_id, folder_path, parent_group_id=parent_group_id)
        self.tree_changed.emit('', '')

    def _shortcut_delete(self):
        """Handle Delete key — delete all selected objects."""
        self._delete_selected()

    @staticmethod
    def _is_system_group(item):
        """Return True if *item* represents a system-structure group."""
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        if obj_type not in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
            return False
        name = item.text(0)
        parent = item.parent()
        if parent is None:
            return False
        parent_type = parent.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        if parent_type == 'Library' and name in SYSTEM_ROOT_FOLDERS:
            return True
        parent_name = parent.text(0)
        if parent_type in ('ObjectGroup', 'ServiceGroup'):
            allowed = SYSTEM_SUB_FOLDERS.get(parent_name)
            if allowed and name in allowed:
                return True
        return False

    def _is_deletable(self, item):
        """Return True if *item* can be deleted."""
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if effective_ro:
            return False
        if obj_type in NO_DELETE_TYPES:
            return False
        return not self._is_system_group(item)

    # -- New [Type] --

    def _count_selected_firewalls(self):
        """Return the number of currently selected Firewall items in the tree."""
        count = 0
        for sel_item in self._tree.selectedItems():
            if sel_item.data(0, Qt.ItemDataRole.UserRole + 1) == 'Firewall':
                count += 1
        return count

    def _get_selected_firewall_ids(self):
        """Return a list of obj_id strings for selected Firewall items."""
        ids = []
        for sel_item in self._tree.selectedItems():
            if sel_item.data(0, Qt.ItemDataRole.UserRole + 1) == 'Firewall':
                obj_id = sel_item.data(0, Qt.ItemDataRole.UserRole)
                if obj_id:
                    ids.append(obj_id)
        return ids

    def _ctx_group_objects(self):
        """Create a new group containing all selected objects."""
        if self._db_manager is None:
            return
        selection = self._get_simplified_selection()
        if len(selection) < 2:
            return

        # Determine group type from the first selected item.
        first_type = selection[0].data(0, Qt.ItemDataRole.UserRole + 1) or ''
        if first_type in SERVICE_OBJ_TYPES:
            group_type = 'ServiceGroup'
        elif first_type in ('Interval', 'IntervalGroup'):
            group_type = 'IntervalGroup'
        else:
            group_type = 'ObjectGroup'

        # Show the New Group dialog.
        from PySide6.QtWidgets import QComboBox

        from firewallfabrik.gui.ui_loader import FWFUiLoader

        ui_path = Path(__file__).resolve().parent / 'ui' / 'newgroupdialog_q.ui'
        dlg = QDialog(self._tree.window())
        loader = FWFUiLoader(dlg)
        loader.load(str(ui_path))

        # Fill the library combo with writable libraries.
        libs_combo = dlg.findChild(QComboBox, 'libs')
        writable_libs = self._get_writable_libraries()
        for lib_id, lib_name in writable_libs:
            libs_combo.addItem(lib_name, lib_id)

        obj_name_widget = dlg.findChild(QLineEdit, 'obj_name')
        obj_name_widget.setFocus()

        # Center on parent window.
        parent_geom = self._tree.window().geometry()
        dlg.move(
            parent_geom.center().x() - dlg.width() // 2,
            parent_geom.center().y() - dlg.height() // 2,
        )

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        group_name = obj_name_widget.text().strip() if obj_name_widget else ''
        if not group_name:
            return

        lib_id = libs_combo.currentData()
        if lib_id is None and writable_libs:
            lib_id = writable_libs[0][0]
        if lib_id is None:
            return

        member_ids = []
        for it in selection:
            mid = it.data(0, Qt.ItemDataRole.UserRole)
            if mid:
                member_ids.append(mid)

        new_id = self._ops.group_objects(group_type, group_name, lib_id, member_ids)
        if new_id is not None:
            self.tree_changed.emit(str(new_id), group_type)
            QTimer.singleShot(0, lambda: self.select_object(new_id))

    def _ctx_new_cluster_from_selected(self):
        """Open the New Cluster wizard with the currently selected firewalls."""
        if self._db_manager is None:
            return
        fw_ids = self._get_selected_firewall_ids()
        if len(fw_ids) < 2:
            return

        from firewallfabrik.gui.new_cluster_dialog import NewClusterDialog

        dlg = NewClusterDialog(
            db_manager=self._db_manager,
            parent=self._tree.window(),
            preselected_fw_ids=fw_ids,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        name, extra_data = dlg.get_result()

        # Place the new cluster in the first writable library.
        libs = self._get_writable_libraries()
        if not libs:
            return
        lib_id = libs[0][0]

        new_id = self._ops.create_new_object(
            MODEL_MAP['Cluster'],
            'Cluster',
            lib_id,
            extra_data=extra_data,
            folder='Clusters',
            name=name,
        )
        if new_id is not None:
            self.tree_changed.emit(str(new_id), 'Cluster')
            QTimer.singleShot(0, lambda: self.select_object(new_id))

    def _ctx_new_object(self, item, type_name):
        """Create a new object of *type_name* in the context of *item*."""
        if self._db_manager is None:
            return
        model_cls = MODEL_MAP.get(type_name)
        if model_cls is None:
            return

        # Firewall/Cluster/Host: show creation dialog first.
        extra_data = None
        name = None
        if type_name == 'Cluster':
            from firewallfabrik.gui.new_cluster_dialog import NewClusterDialog

            dlg = NewClusterDialog(
                db_manager=self._db_manager,
                parent=self._tree.window(),
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()
        elif type_name == 'Host':
            from firewallfabrik.gui.new_host_dialog import NewHostDialog

            dlg = NewHostDialog(parent=self._tree.window())
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, interfaces = dlg.get_result()

            lib_id = self._get_item_library_id(item)
            if lib_id is None:
                return

            obj_type_item = item.data(0, Qt.ItemDataRole.UserRole + 1)
            folder = None
            if obj_type_item is None:
                folder = self._get_category_folder_path(item)
            if folder is None:
                folder = 'Hosts'

            prefix = self._get_device_prefix(item)
            new_id = self._ops.create_host_with_interfaces(
                lib_id,
                name=name,
                interfaces=interfaces,
                folder=folder,
                prefix=prefix,
            )
            if new_id is not None:
                self.tree_changed.emit(str(new_id), type_name)
                QTimer.singleShot(0, lambda: self.select_object(new_id))
            return
        elif type_name == 'Firewall':
            from firewallfabrik.gui.new_device_dialog import NewDeviceDialog

            dlg = NewDeviceDialog(type_name, parent=self._tree.window())
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()

        # Determine where to place the new object.
        lib_id = self._get_item_library_id(item)
        if lib_id is None:
            return

        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)

        # Figure out the parent context.
        interface_id = None
        parent_interface_id = None
        device_id = None
        folder = None

        if obj_type == 'Interface' and obj_id:
            if issubclass(model_cls, Address):
                interface_id = uuid.UUID(obj_id)
            elif issubclass(model_cls, Interface):
                parent_interface_id = uuid.UUID(obj_id)
                parent = item.parent()
                if parent:
                    pid = parent.data(0, Qt.ItemDataRole.UserRole)
                    if pid:
                        device_id = uuid.UUID(pid)
        elif obj_type in ('Cluster', 'Firewall', 'Host') and obj_id:
            if issubclass(model_cls, Interface) or issubclass(model_cls, RuleSet):
                device_id = uuid.UUID(obj_id)
        elif obj_type == 'Library':
            pass
        elif obj_type is None:
            folder = self._get_category_folder_path(item)
        else:
            parent = item.parent()
            while parent is not None:
                pt = parent.data(0, Qt.ItemDataRole.UserRole + 1)
                pid = parent.data(0, Qt.ItemDataRole.UserRole)
                if pt == 'Interface' and pid and issubclass(model_cls, Address):
                    interface_id = uuid.UUID(pid)
                    break
                if pt in ('Cluster', 'Firewall', 'Host') and pid:
                    if issubclass(model_cls, Interface):
                        device_id = uuid.UUID(pid)
                    break
                if pt == 'Library':
                    break
                if pt is None:
                    folder = self._get_category_folder_path(parent)
                parent = parent.parent()

        # If no explicit folder, derive from type.
        if folder is None and interface_id is None and device_id is None:
            for f, type_list in NEW_TYPES_FOR_FOLDER.items():
                if any(tn == type_name for tn, _dn in type_list):
                    folder = f
                    break

        prefix = self._get_device_prefix(item)
        new_id = self._ops.create_new_object(
            model_cls,
            type_name,
            lib_id,
            device_id=device_id,
            extra_data=extra_data,
            folder=folder,
            interface_id=interface_id,
            name=name,
            parent_interface_id=parent_interface_id,
            prefix=prefix,
        )
        if new_id is not None:
            self.tree_changed.emit(str(new_id), type_name)
            QTimer.singleShot(0, lambda: self.select_object(new_id))

    # -- New Subfolder --

    def _ctx_new_subfolder(self, item):
        """Prompt for a subfolder name and create it under *item*.

        Works for both real objects (groups / libraries) and virtual
        category folders (user subfolders).  Nested subfolders are
        stored as path strings (``'A/B'``) in the owning group's
        ``data['subfolders']`` list.
        """
        if self._db_manager is None:
            return

        name, ok = QInputDialog.getText(
            self._tree,
            'New Subfolder',
            'Enter subfolder name:',
        )
        name = name.strip() if ok else ''
        if not name:
            return
        if ',' in name:
            QMessageBox.warning(
                self._tree,
                'New Subfolder',
                'Subfolder name cannot contain a comma.',
            )
            return

        # Split on '/' to allow creating nested subfolders in one go
        # (e.g. "a/b/c" creates three levels).  Strip and filter empty
        # segments so that leading/trailing/double slashes are ignored.
        segments = [s.strip() for s in name.split('/') if s.strip()]
        if not segments:
            return
        if any(',' in s for s in segments):
            QMessageBox.warning(
                self._tree,
                'New Subfolder',
                'Subfolder name cannot contain a comma.',
            )
            return

        lib_id = self._get_item_library_id(item)
        if lib_id is None:
            return

        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)

        if obj_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup') and obj_id:
            parent_group_id = uuid.UUID(obj_id)
            base_path = ''
        elif obj_type == 'Library':
            parent_group_id = None
            base_path = ''
        else:
            # Category folder — compute full path and find owner group.
            base_path = self._get_category_folder_path(item) or ''
            parent_group_id = self._get_folder_parent_group_id(item)

        # Create each intermediate path segment.
        for seg in segments:
            folder_path = f'{base_path}/{seg}' if base_path else seg
            self._ops.create_subfolder(
                lib_id,
                folder_path,
                parent_group_id=parent_group_id,
            )
            base_path = folder_path

        # Remember the parent's path key so we can expand it after the
        # tree rebuild to make the new subfolder immediately visible.
        parent_path_key = self._item_path(item)

        self.tree_changed.emit('', '')
        QTimer.singleShot(0, lambda: self._expand_by_path(parent_path_key))

    def _ctx_rename_folder(self, item):
        """Rename a category folder (updates nested child paths too)."""
        if self._db_manager is None:
            return

        old_leaf = item.text(0)
        new_leaf, ok = QInputDialog.getText(
            self._tree,
            'Rename Folder',
            'Enter new folder name:',
            QLineEdit.EchoMode.Normal,
            old_leaf,
        )
        new_leaf = new_leaf.strip() if ok else ''
        if not new_leaf or new_leaf == old_leaf:
            return
        if ',' in new_leaf or '/' in new_leaf:
            QMessageBox.warning(
                self._tree,
                'Rename Folder',
                'Folder name cannot contain a comma or slash.',
            )
            return

        lib_id = self._get_item_library_id(item)
        if lib_id is None:
            return

        old_path = self._get_category_folder_path(item)
        # Replace only the last component of the path.
        parts = old_path.rsplit('/', 1)
        new_path = f'{parts[0]}/{new_leaf}' if len(parts) == 2 else new_leaf

        parent_group_id = self._get_folder_parent_group_id(item)
        self._ops.rename_folder(
            lib_id, old_path, new_path, parent_group_id=parent_group_id
        )
        self.tree_changed.emit('', '')

    # ------------------------------------------------------------------
    # Public API (toolbar / menu)
    # ------------------------------------------------------------------

    def create_new_object_in_library(
        self, type_name, lib_id, *, extra_data=None, name=None
    ):
        """Create a new object of *type_name* in library *lib_id*.

        This is the toolbar/menu variant of ``_ctx_new_object()`` — it
        does not require a tree selection.

        Returns the new object's UUID, or ``None`` on failure.
        """
        model_cls = MODEL_MAP.get(type_name)
        if model_cls is None:
            return None

        # Library creation has no folder.
        folder = None
        if model_cls is not Library:
            for f, type_list in NEW_TYPES_FOR_FOLDER.items():
                if any(tn == type_name for tn, _dn in type_list):
                    folder = f
                    break

        new_id = self._ops.create_new_object(
            model_cls,
            type_name,
            lib_id,
            extra_data=extra_data,
            folder=folder,
            name=name,
        )
        if new_id is not None:
            self.tree_changed.emit(str(new_id), type_name)
            QTimer.singleShot(0, lambda: self.select_object(new_id))
        return new_id

    def create_host_in_library(self, lib_id, *, name=None, interfaces=None):
        """Create a new Host (with interfaces) in library *lib_id*.

        Returns the new Host's UUID, or ``None`` on failure.
        """
        new_id = self._ops.create_host_with_interfaces(
            lib_id,
            name=name,
            interfaces=interfaces or [],
            folder='Hosts',
        )
        if new_id is not None:
            self.tree_changed.emit(str(new_id), 'Host')
            QTimer.singleShot(0, lambda: self.select_object(new_id))
        return new_id
