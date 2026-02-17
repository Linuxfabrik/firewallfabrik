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

import sqlalchemy
from PySide6.QtCore import QMimeData, QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QDrag, QFont, QIcon, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.core.objects import (
    Group,
    Host,
    Library,
    group_membership,
)
from firewallfabrik.gui.object_tree_actions import TreeActionHandler
from firewallfabrik.gui.object_tree_data import (
    CATEGORY_ICON,
    ICON_MAP,
    LOCK_ICON,
    MODEL_MAP,
    NON_DRAGGABLE_TYPES,
    RULE_SET_TYPES,
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
        self._actions = TreeActionHandler(self)

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
        self._actions.set_db_manager(db_manager)

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
        """Hide items whose name does not match *text* (case-insensitive).

        Multiple space-separated tokens are matched with AND logic so
        that e.g. ``"4 http"`` finds ``"HTTPS 443"``.
        """
        text = text.strip().lower()
        if not text:
            self._reset_visibility()
            return

        tokens = text.split()

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
            attrs_str = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
            haystack = (
                f'{item.text(0).lower()} {tags_str} {comment_str} {attrs_str.lower()}'
            )
            if all(tok in haystack for tok in tokens):
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
        writable_libraries = self._actions._get_writable_libraries()

        # Gather tags for the Tags submenu.
        all_tags = TreeOperations.get_all_tags(self._db_manager)
        selected_tags = self._get_selected_tags(selection)

        # Determine Lock/Unlock state.
        obj_is_locked = item.data(0, Qt.ItemDataRole.UserRole + 7) or False
        lib_is_ro = self._get_library_ro(item)

        # Gather sibling interfaces for "Make subinterface of ...".
        sibling_interfaces = self._get_sibling_interfaces(item, obj_type)

        resolved = self._actions._resolve_paste_item(item)
        allowed = self._actions._get_allowed_paste_types(resolved)
        compat_clip = (
            [
                cb
                for cb in self._actions._tree_clipboard
                if allowed is None or cb['type'] in allowed
            ]
            if self._actions._tree_clipboard is not None
            else None
        ) or None

        menu, handlers = build_object_context_menu(
            self,
            item,
            selection,
            all_tags=all_tags,
            clipboard=compat_clip,
            count_selected_firewalls_fn=self._actions._count_selected_firewalls,
            get_item_library_id_fn=self._get_item_library_id,
            is_deletable_fn=self._actions._is_deletable,
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
            QTimer.singleShot(
                0, lambda m=method_name, a=args: getattr(self._actions, m)(*a)
            )

    def _on_category_context_menu(self, item, pos):
        """Show a context menu for category folder items."""
        has_mixed = any(
            it.data(0, Qt.ItemDataRole.UserRole)
            for it in self._tree.selectedItems()
            if it is not item
        )

        allowed = self._actions._get_allowed_paste_types(item)
        compat_clip = (
            [
                cb
                for cb in self._actions._tree_clipboard
                if allowed is None or cb['type'] in allowed
            ]
            if self._actions._tree_clipboard is not None
            else None
        ) or None

        menu, handlers = build_category_context_menu(
            self,
            item,
            clipboard=compat_clip,
            has_mixed_selection=has_mixed,
        )

        triggered = menu.exec(self._tree.viewport().mapToGlobal(pos))
        handler = handlers.get(triggered)
        menu.deleteLater()
        if handler is not None:
            method_name, *args = handler
            # Same deferred dispatch as _on_context_menu — see comment
            # there for the rationale (Shiboken segfault prevention).
            QTimer.singleShot(
                0, lambda m=method_name, a=args: getattr(self._actions, m)(*a)
            )

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
        dest_prefix = self._get_device_prefix(dest_item)
        for entry in entries:
            model_cls = MODEL_MAP.get(entry.get('type'))
            if model_cls is None:
                continue
            obj_id = uuid.UUID(entry['id'])
            if self._ops.set_object_folder(
                obj_id,
                model_cls,
                target_folder,
                prefix=dest_prefix,
            ):
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
