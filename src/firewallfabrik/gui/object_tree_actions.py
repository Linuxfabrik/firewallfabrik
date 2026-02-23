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

"""Context-menu and keyboard-shortcut action handlers for the object tree."""

import uuid
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QDialog, QInputDialog, QLineEdit, QMessageBox

from firewallfabrik.core.objects import Address, Host, Interface, Library, RuleSet
from firewallfabrik.gui.confirm_delete_dialog import ConfirmDeleteDialog
from firewallfabrik.gui.object_tree_data import (
    LOCKABLE_TYPES,
    MODEL_MAP,
    NEW_TYPES_FOR_FOLDER,
    NEW_TYPES_FOR_GROUP_NODE,
    NO_COPY_TYPES,
    NO_DELETE_TYPES,
    RULE_SET_TYPES,
    SERVICE_OBJ_TYPES,
)
from firewallfabrik.gui.object_tree_ops import TreeOperations


class TreeActionHandler:
    """Context-menu and keyboard-shortcut action handlers for the object tree.

    Extracted from :class:`ObjectTree` to keep the tree widget focused on
    display and layout.  All methods access the tree via ``self._ot``
    (the :class:`ObjectTree` instance).
    """

    _PASTE_CONTAINER_TYPES = frozenset(
        {
            'IntervalGroup',
            'Interface',
            'Library',
            'ObjectGroup',
            'ServiceGroup',
        }
    )

    def __init__(self, object_tree, clipboard_store):
        self._ot = object_tree
        self._clipboard_store = clipboard_store
        self._ops = TreeOperations()
        self._db_manager = None

    def set_db_manager(self, db_manager):
        """Set the database manager and re-create the ops helper."""
        self._db_manager = db_manager
        self._ops = TreeOperations(db_manager)

    # ------------------------------------------------------------------
    # Edit / Navigate
    # ------------------------------------------------------------------

    def _ctx_edit(self, item):
        """Open the editor for the context-menu item (Edit / Inspect)."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type in RULE_SET_TYPES:
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self._ot.rule_set_activated.emit(obj_id, fw_name, item.text(0), obj_type)
        self._ot.object_activated.emit(obj_id, obj_type)

    def _ctx_open_ruleset(self, item):
        """Open a rule set (distinct from Edit — shows the rule editor)."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type in RULE_SET_TYPES:
            fw_item = item.parent()
            fw_name = fw_item.text(0) if fw_item else ''
            self._ot.rule_set_activated.emit(obj_id, fw_name, item.text(0), obj_type)

    # -- Find / Where used --

    def _ctx_find(self, item):
        """Emit find_requested for the given item."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole) or ''
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        name = item.text(0)
        self._ot.find_requested.emit(obj_id, name, obj_type)

    def _ctx_where_used(self, item):
        """Emit where_used_requested for the given item."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole) or ''
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        name = item.text(0)
        self._ot.where_used_requested.emit(obj_id, name, obj_type)

    # -- Compile / Install --

    def _ctx_compile(self):
        """Emit compile_requested with selected firewall names."""
        self._ot.compile_requested.emit(self._selected_firewall_names())

    def _ctx_install(self):
        """Emit install_requested with selected firewall names."""
        self._ot.install_requested.emit(self._selected_firewall_names())

    def _selected_firewall_names(self):
        """Return names of Firewall objects in the current selection."""
        selection = self._ot._get_simplified_selection()
        return [
            it.text(0)
            for it in selection
            if (it.data(0, Qt.ItemDataRole.UserRole + 1) or '')
            in ('Firewall', 'Cluster')
        ]

    # -- Lock / Unlock --

    def _ctx_lock(self):
        """Lock all selected objects that support locking."""
        selection = self._ot._get_simplified_selection()
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
            self._ot.tree_changed.emit('', '')

    def _ctx_unlock(self):
        """Unlock all selected objects that support locking."""
        selection = self._ot._get_simplified_selection()
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
            self._ot.tree_changed.emit('', '')

    # -- Tags --

    def _ctx_new_keyword(self):
        """Prompt for a new tag and add it to all selected objects."""
        keyword, ok = QInputDialog.getText(
            self._ot._tree,
            'New Tag',
            'Enter tag:',
        )
        keyword = keyword.strip() if ok else ''
        if not keyword:
            return
        self._ctx_add_keyword(keyword)

    def _ctx_add_keyword(self, keyword):
        """Add *keyword* to all selected objects."""
        selection = self._ot._get_simplified_selection()
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
            self._ot.tree_changed.emit('', '')

    def _ctx_remove_keyword(self, keyword):
        """Remove *keyword* from all selected objects."""
        selection = self._ot._get_simplified_selection()
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
            self._ot.tree_changed.emit('', '')

    # -- Make subinterface --

    def _ctx_make_subinterface(self, item, target_iface_id):
        """Move *item*'s interface under *target_iface_id* as a subinterface."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not obj_id:
            return
        prefix = self._ot._get_device_prefix(item)
        if self._ops.make_subinterface(
            uuid.UUID(obj_id),
            uuid.UUID(target_iface_id),
            prefix=prefix,
        ):
            self._ot.tree_changed.emit('', '')

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
        source_lib_id = self._ot._get_item_library_id(item)
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

        prefix = self._ot._get_device_prefix(item)
        new_id = self._ops.duplicate_object(
            uuid.UUID(obj_id),
            model_cls,
            target_lib_id,
            prefix=prefix,
            **kwargs,
        )
        if new_id is not None:
            self._ot.tree_changed.emit(str(new_id), obj_type)
            QTimer.singleShot(0, lambda: self._ot.select_object(new_id))

    # -- Move --

    def _ctx_move(self, item, target_lib_id):
        """Move the object referenced by *item* to *target_lib_id*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        model_cls = MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        prefix = self._ot._get_device_prefix(item)
        if self._ops.move_object(
            uuid.UUID(obj_id),
            model_cls,
            target_lib_id,
            prefix=prefix,
        ):
            self._ot.tree_changed.emit(obj_id, obj_type)
            QTimer.singleShot(0, lambda: self._ot.select_object(uuid.UUID(obj_id)))

    # -- Copy / Cut / Paste --

    @staticmethod
    def _resolve_paste_item(item):
        """Walk up from *item* to the nearest valid paste container.

        If *item* is already a category folder (``obj_type is None``) or
        a container type (group, interface, library), return it as-is.
        Otherwise walk up to the first such ancestor so that pasting
        creates a sibling rather than placing the clone at the library
        root.
        """
        current = item
        while current is not None:
            obj_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            if obj_type is None or obj_type in TreeActionHandler._PASTE_CONTAINER_TYPES:
                return current
            current = current.parent()
        return item  # fallback — should not happen

    @staticmethod
    def _get_allowed_paste_types(item):
        """Return the set of allowed object types for pasting into *item*.

        Walks up from *item* through category folders until a real group
        or library is found.  Returns ``None`` when any type is accepted
        (e.g. the library root or an unknown user-created group).
        """
        current = item
        while current is not None:
            obj_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
            if obj_type == 'Interface':
                return frozenset({'IPv4', 'IPv6', 'physAddress'})
            if obj_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
                group_name = current.text(0)
                entries = NEW_TYPES_FOR_GROUP_NODE.get(
                    (obj_type, group_name),
                )
                if entries is not None:
                    return frozenset(e[0] for e in entries)
                return None  # user-created group — no restriction
            if obj_type == 'Library':
                return None
            current = current.parent()
        return None

    def _ctx_copy(self):
        """Copy all selected object references to the tree clipboard."""
        selection = self._ot._get_simplified_selection()
        entries = []
        for it in selection:
            oid = it.data(0, Qt.ItemDataRole.UserRole)
            otype = it.data(0, Qt.ItemDataRole.UserRole + 1)
            if oid and otype and otype not in NO_COPY_TYPES:
                entries.append({'id': oid, 'type': otype, 'cut': False})
        if not entries:
            return
        self._clipboard_store.set_tree(entries)
        # Policy-view clipboard stays single-item for rule cell paste.
        first = selection[0]
        self._clipboard_store.set_object(
            first.data(0, Qt.ItemDataRole.UserRole),
            first.text(0),
            first.data(0, Qt.ItemDataRole.UserRole + 1),
        )

    def _ctx_cut(self):
        """Cut all selected object references to the tree clipboard."""
        selection = self._ot._get_simplified_selection()
        entries = []
        for it in selection:
            oid = it.data(0, Qt.ItemDataRole.UserRole)
            otype = it.data(0, Qt.ItemDataRole.UserRole + 1)
            ro = it.data(0, Qt.ItemDataRole.UserRole + 5) or False
            if oid and otype and otype not in NO_COPY_TYPES and not ro:
                entries.append({'id': oid, 'type': otype, 'cut': True})
        if not entries:
            return
        self._clipboard_store.set_tree(entries)
        first = selection[0]
        self._clipboard_store.set_object(
            first.data(0, Qt.ItemDataRole.UserRole),
            first.text(0),
            first.data(0, Qt.ItemDataRole.UserRole + 1),
        )

    def _ctx_paste(self, item):
        """Paste all clipboard objects relative to *item*."""
        if self._clipboard_store.tree_entries is None or self._db_manager is None:
            return

        # When pasting onto a leaf object (e.g. a Firewall), resolve
        # upward to the nearest container so the clone becomes a sibling.
        item = self._resolve_paste_item(item)

        target_lib_id = self._ot._get_item_library_id(item)
        if target_lib_id is None:
            return

        # Validate type compatibility — skip entries that don't belong.
        allowed = self._get_allowed_paste_types(item)
        entries = [
            cb
            for cb in self._clipboard_store.tree_entries
            if allowed is None or cb['type'] in allowed
        ]
        if not entries:
            return

        target_iface_id, target_group_id = self._ot._get_paste_context(item)
        prefix = self._ot._get_device_prefix(item)

        # When pasting into a category folder, store the folder path
        # on the pasted object so it appears in the correct subfolder.
        # When pasting into a real group/object, clear any existing
        # folder (empty string) so the object moves to the group root.
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_type is None:
            target_folder = self._ot._get_category_folder_path(item)
        elif target_group_id is not None:
            target_folder = ''
        else:
            target_folder = None

        any_cut = False
        last_id = None

        for cb in entries:
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
                    prefix=prefix,
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
            self._clipboard_store.clear_tree()

        if last_id is not None:
            self._ot.tree_changed.emit('', '')
            QTimer.singleShot(0, lambda lid=last_id: self._ot.select_object(lid))

    def _shortcut_copy(self):
        """Handle Ctrl+C — copy all selected objects."""
        selection = self._ot._get_simplified_selection()
        if not selection:
            return
        if any(
            (it.data(0, Qt.ItemDataRole.UserRole + 1) or '') not in NO_COPY_TYPES
            for it in selection
        ):
            self._ctx_copy()

    def _shortcut_cut(self):
        """Handle Ctrl+X — cut all selected objects."""
        selection = self._ot._get_simplified_selection()
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
        item = self._ot._tree.currentItem()
        if item is None:
            return
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if not effective_ro:
            self._ctx_paste(item)

    # -- Delete --

    def _confirm_delete(self, objects):
        """Show the confirm-delete dialog for *objects*.

        Parameters
        ----------
        objects : list[tuple[str, str, str]]
            Each entry is ``(obj_id, obj_name, obj_type)``.

        Returns ``True`` if the user clicks Delete, ``False`` on Cancel.
        """
        if not objects or self._db_manager is None:
            return False

        dlg = ConfirmDeleteDialog(self._ot._tree.window())
        dlg.load(objects, self._db_manager)

        # Center on parent window.
        parent_geom = self._ot._tree.window().geometry()
        dlg.move(
            parent_geom.center().x() - dlg.width() // 2,
            parent_geom.center().y() - dlg.height() // 2,
        )

        return dlg.exec() == QDialog.DialogCode.Accepted

    def _ctx_delete(self, item):
        """Delete the object referenced by *item*."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if not obj_id or not obj_type:
            return
        if obj_type == 'Library':
            if self._delete_library(item):
                self._ot.tree_changed.emit('', '')
            return
        model_cls = MODEL_MAP.get(obj_type)
        if model_cls is None:
            return
        obj_name = item.text(0)

        if not self._confirm_delete([(obj_id, obj_name, obj_type)]):
            return

        prefix = self._ot._get_device_prefix(item)
        if self._ops.delete_object(
            uuid.UUID(obj_id),
            model_cls,
            obj_name,
            obj_type,
            prefix=prefix,
        ):
            self._ot.tree_changed.emit('', '')

    def _delete_selected(self):
        """Delete all selected objects, filtering out non-deletable and read-only items."""
        selection = self._ot._get_simplified_selection()

        # Separate libraries (which have their own confirmation dialog)
        # from regular objects (which go through the confirm-delete dialog).
        library_items = []
        regular_items = []
        for it in selection:
            obj_id = it.data(0, Qt.ItemDataRole.UserRole)
            obj_type = it.data(0, Qt.ItemDataRole.UserRole + 1)
            if not obj_id or not obj_type:
                continue
            if not self._is_deletable(it):
                continue
            if obj_type == 'Library':
                library_items.append(it)
            elif MODEL_MAP.get(obj_type) is not None:
                regular_items.append(it)

        any_deleted = False

        # Show the confirm-delete dialog for regular objects.
        if regular_items:
            objects = [
                (
                    it.data(0, Qt.ItemDataRole.UserRole),
                    it.text(0),
                    it.data(0, Qt.ItemDataRole.UserRole + 1),
                )
                for it in regular_items
            ]
            if not self._confirm_delete(objects):
                # User cancelled — still process library deletes below
                # (they have their own confirmation).
                regular_items = []

        for it in regular_items:
            obj_id = it.data(0, Qt.ItemDataRole.UserRole)
            obj_type = it.data(0, Qt.ItemDataRole.UserRole + 1)
            model_cls = MODEL_MAP.get(obj_type)
            prefix = self._ot._get_device_prefix(it)
            if self._ops.delete_object(
                uuid.UUID(obj_id),
                model_cls,
                it.text(0),
                obj_type,
                prefix=prefix,
            ):
                any_deleted = True

        for it in library_items:
            if self._delete_library(it):
                any_deleted = True

        if any_deleted:
            self._ot.tree_changed.emit('', '')

    def _delete_library(self, item):
        """Delete a library after confirmation.  Returns True on success."""
        if self._db_manager is None:
            return False
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not obj_id:
            return False
        lib_name = item.text(0)
        result = QMessageBox.warning(
            self._ot._tree,
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
        lib_id = self._ot._get_item_library_id(item)
        if lib_id is None:
            return
        folder_path = self._ot._get_category_folder_path(item)
        parent_group_id = self._ot._get_folder_parent_group_id(item)
        self._ops.delete_folder(lib_id, folder_path, parent_group_id=parent_group_id)
        self._ot.tree_changed.emit('', '')

    def _shortcut_delete(self):
        """Handle Delete key — delete all selected objects."""
        self._delete_selected()

    def _is_deletable(self, item):
        """Return True if *item* can be deleted."""
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
        effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
        if effective_ro:
            return False
        if obj_type in NO_DELETE_TYPES:
            return False
        return not self._ot._is_system_group(item)

    # -- New [Type] --

    def _count_selected_firewalls(self):
        """Return the number of currently selected Firewall items in the tree."""
        count = 0
        for sel_item in self._ot._tree.selectedItems():
            if sel_item.data(0, Qt.ItemDataRole.UserRole + 1) == 'Firewall':
                count += 1
        return count

    def _get_selected_firewall_ids(self):
        """Return a list of obj_id strings for selected Firewall items."""
        ids = []
        for sel_item in self._ot._tree.selectedItems():
            if sel_item.data(0, Qt.ItemDataRole.UserRole + 1) == 'Firewall':
                obj_id = sel_item.data(0, Qt.ItemDataRole.UserRole)
                if obj_id:
                    ids.append(obj_id)
        return ids

    def _ctx_group_objects(self):
        """Create a new group containing all selected objects."""
        if self._db_manager is None:
            return
        selection = self._ot._get_simplified_selection()
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
        dlg = QDialog(self._ot._tree.window())
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
        parent_geom = self._ot._tree.window().geometry()
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
            self._ot.tree_changed.emit(str(new_id), group_type)
            QTimer.singleShot(0, lambda: self._ot.select_object(new_id))

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
            parent=self._ot._tree.window(),
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
            self._ot.tree_changed.emit(str(new_id), 'Cluster')
            QTimer.singleShot(0, lambda: self._ot.select_object(new_id))

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
                parent=self._ot._tree.window(),
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()
        elif type_name == 'Host':
            from firewallfabrik.gui.new_host_dialog import NewHostDialog

            dlg = NewHostDialog(parent=self._ot._tree.window())
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, interfaces = dlg.get_result()

            lib_id = self._ot._get_item_library_id(item)
            if lib_id is None:
                return

            obj_type_item = item.data(0, Qt.ItemDataRole.UserRole + 1)
            folder = None
            if obj_type_item is None:
                folder = self._ot._get_category_folder_path(item)
            if folder is None:
                folder = 'Hosts'

            prefix = self._ot._get_device_prefix(item)
            new_id = self._ops.create_host_with_interfaces(
                lib_id,
                name=name,
                interfaces=interfaces,
                folder=folder,
                prefix=prefix,
            )
            if new_id is not None:
                self._ot.tree_changed.emit(str(new_id), type_name)
                QTimer.singleShot(0, lambda: self._ot.select_object(new_id))
            return
        elif type_name == 'Firewall':
            from firewallfabrik.gui.new_device_dialog import NewDeviceDialog

            dlg = NewDeviceDialog(type_name, parent=self._ot._tree.window())
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()

        # Determine where to place the new object.
        lib_id = self._ot._get_item_library_id(item)
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
            folder = self._ot._get_category_folder_path(item)
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
                    folder = self._ot._get_category_folder_path(parent)
                parent = parent.parent()

        # If no explicit folder, derive from type.
        if folder is None and interface_id is None and device_id is None:
            for f, type_list in NEW_TYPES_FOR_FOLDER.items():
                if any(tn == type_name for tn, _dn in type_list):
                    folder = f
                    break

        # Build fwbuilder-style default name for address children of
        # interfaces: "hostname:ifacename:ip" / "hostname:ifacename:ip6".
        if name is None and interface_id is not None and type_name in ('IPv4', 'IPv6'):
            name = self._standard_address_name(item, type_name)

        prefix = self._ot._get_device_prefix(item)
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
            self._ot.tree_changed.emit(str(new_id), type_name)
            QTimer.singleShot(0, lambda: self._ot.select_object(new_id))

    def _standard_address_name(self, item, type_name):
        """Build a fwbuilder-style default name for a new address.

        Walks up the tree from *item* collecting object **names** (not
        labels) until a Host/Firewall/Cluster node is reached, producing
        ``hostname:ifacename:ip`` (IPv4) or ``hostname:ifacename:ip6`` (IPv6).
        """
        suffix = 'ip' if type_name == 'IPv4' else 'ip6'
        parts = []
        node = item
        session = self._db_manager.create_session() if self._db_manager else None
        try:
            while node is not None:
                node_type = node.data(0, Qt.ItemDataRole.UserRole + 1)
                if node_type in ('Cluster', 'Firewall', 'Host', 'Interface'):
                    node_id = node.data(0, Qt.ItemDataRole.UserRole)
                    obj_name = None
                    if session and node_id:
                        uid = uuid.UUID(node_id)
                        if node_type == 'Interface':
                            obj = session.get(Interface, uid)
                        else:
                            obj = session.get(Host, uid)
                        if obj:
                            obj_name = obj.name
                    parts.insert(0, obj_name or node.text(0))
                if node_type in ('Cluster', 'Firewall', 'Host'):
                    break
                node = node.parent()
        finally:
            if session:
                session.close()
        parts.append(suffix)
        return ':'.join(parts)

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
            self._ot._tree,
            'New Subfolder',
            'Enter subfolder name:',
        )
        name = name.strip() if ok else ''
        if not name:
            return
        if ',' in name:
            QMessageBox.warning(
                self._ot._tree,
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
                self._ot._tree,
                'New Subfolder',
                'Subfolder name cannot contain a comma.',
            )
            return

        lib_id = self._ot._get_item_library_id(item)
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
            base_path = self._ot._get_category_folder_path(item) or ''
            parent_group_id = self._ot._get_folder_parent_group_id(item)

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
        parent_path_key = self._ot._item_path(item)

        self._ot.tree_changed.emit('', '')
        QTimer.singleShot(0, lambda: self._ot._expand_by_path(parent_path_key))

    def _ctx_rename_folder(self, item):
        """Rename a category folder (updates nested child paths too)."""
        if self._db_manager is None:
            return

        old_leaf = item.text(0)
        new_leaf, ok = QInputDialog.getText(
            self._ot._tree,
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
                self._ot._tree,
                'Rename Folder',
                'Folder name cannot contain a comma or slash.',
            )
            return

        lib_id = self._ot._get_item_library_id(item)
        if lib_id is None:
            return

        old_path = self._ot._get_category_folder_path(item)
        # Replace only the last component of the path.
        parts = old_path.rsplit('/', 1)
        new_path = f'{parts[0]}/{new_leaf}' if len(parts) == 2 else new_leaf

        parent_group_id = self._ot._get_folder_parent_group_id(item)
        self._ops.rename_folder(
            lib_id, old_path, new_path, parent_group_id=parent_group_id
        )
        self._ot.tree_changed.emit('', '')

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
            self._ot.tree_changed.emit(str(new_id), type_name)
            QTimer.singleShot(0, lambda: self._ot.select_object(new_id))
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
            self._ot.tree_changed.emit(str(new_id), 'Host')
            QTimer.singleShot(0, lambda: self._ot.select_object(new_id))
        return new_id
