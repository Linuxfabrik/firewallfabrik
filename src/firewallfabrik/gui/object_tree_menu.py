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

"""Context menu builders for the object tree.

Both functions return ``(QMenu, dict[QAction, tuple])`` where the dict
maps triggered actions to ``('handler_name', *args)`` tuples that
:class:`ObjectTree` dispatches via ``getattr(self, name)(*args)``.

Menu order matches fwbuilder's ``ObjectManipulator::contextMenuRequested()``
exactly.
"""

from PySide6.QtGui import QIcon, QKeySequence
from PySide6.QtWidgets import QMenu

from firewallfabrik.gui.object_tree_data import (
    CATEGORY_ICON,
    COMPILABLE_TYPES,
    ICON_MAP,
    LOCKABLE_TYPES,
    NEW_TYPES_FOR_FOLDER,
    NEW_TYPES_FOR_GROUP_NODE,
    NEW_TYPES_FOR_PARENT,
    NO_COPY_TYPES,
    NO_DUPLICATE_TYPES,
    NO_MOVE_TYPES,
    RULE_SET_TYPES,
    SUBFOLDER_TYPES,
)


def _get_new_object_types(item, obj_type):
    """Return a list of ``(type_name, display_name)`` for the New menu.

    Matches fwbuilder's context menu logic strictly:

    - Devices (Cluster/Firewall/Host) -> fixed child types only.
    - Interface -> dynamic list (addresses, subinterface, etc.).
    - Rule sets (Policy/NAT/Routing) -> no "New" items.
    - Library -> no "New" items (only subfolder, handled elsewhere).
    - Group types -> folder-based items matching the group name.
    - Objects in category folders -> folder-based items.
    - Objects under devices/interfaces -> no "New" items.
    """
    # Devices: fixed child types only.
    if obj_type in ('Cluster', 'Firewall', 'Host'):
        return list(NEW_TYPES_FOR_PARENT.get(obj_type, []))

    # Interface: dynamic list based on parent and existing children.
    if obj_type == 'Interface':
        return _get_interface_new_types(item)

    # Rule sets and Library: no "New" items.
    if obj_type in ('Library', *RULE_SET_TYPES):
        return []

    # Group types: offer new items based on (group_type, group_name).
    if obj_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
        name = item.text(0)
        types = NEW_TYPES_FOR_GROUP_NODE.get((obj_type, name))
        if types is not None:
            return list(types)
        # Fall back to folder-name-only lookup.
        types = NEW_TYPES_FOR_FOLDER.get(name, [])
        if types:
            return list(types)

    # All other objects: only get folder-based items if they live
    # directly under a category folder or group.
    folder_info = _find_folder_context(item)
    if folder_info is not None:
        folder_name, folder_type = folder_info
        if folder_type is not None:
            types = NEW_TYPES_FOR_GROUP_NODE.get((folder_type, folder_name))
            if types is not None:
                return list(types)
        return list(NEW_TYPES_FOR_FOLDER.get(folder_name, []))

    return []


def _find_folder_context(item):
    """Walk up the tree to find the enclosing category folder or group.

    Returns ``(folder_name, group_type)`` where *group_type* is the
    STI discriminator (e.g. ``'ObjectGroup'``, ``'ServiceGroup'``)
    for real group folders, or ``None`` for virtual category folders.
    Returns ``None`` if the item lives under a device or interface
    (where no folder-based "New" items are offered).
    """
    from PySide6.QtCore import Qt

    current = item.parent()
    while current is not None:
        current_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
        if current_type is None:
            # Virtual category folder (no obj_id/obj_type).
            return (current.text(0), None)
        if current_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
            # Real group acting as a folder container.
            return (current.text(0), current_type)
        if current_type in ('Cluster', 'Firewall', 'Host', 'Interface'):
            # Under a device or interface — no folder-based items.
            return None
        if current_type == 'Library':
            # Directly under library without a category folder.
            return None
        current = current.parent()

    return None


def _get_interface_new_types(item):
    """Build the dynamic "New" list for an Interface item.

    Matches fwbuilder's logic:
    - New Interface (subinterface): only for Firewall interfaces
    - New Address (IPv4), New Address IPv6 (IPv6): always
    - New MAC Address (PhysAddress): always
    - New Attached Networks: only if not already present
    - New Failover Group: only for Cluster interfaces, if not
      already present
    """
    from PySide6.QtCore import Qt

    result = []

    # Determine parent device type.
    parent = item.parent()
    parent_type = parent.data(0, Qt.ItemDataRole.UserRole + 1) if parent else None

    # Subinterface: only for Firewall interfaces.
    if parent_type == 'Firewall':
        result.append(('Interface', 'Interface'))

    # Standard address types — always offered.
    result.append(('IPv4', 'Address'))
    result.append(('IPv6', 'Address IPv6'))
    result.append(('PhysAddress', 'MAC Address'))

    # Check existing children in the tree to suppress singleton items.
    has_attached = False
    has_failover = False
    for i in range(item.childCount()):
        child_type = item.child(i).data(0, Qt.ItemDataRole.UserRole + 1)
        if child_type == 'AttachedNetworks':
            has_attached = True
        elif child_type == 'FailoverClusterGroup':
            has_failover = True

    if not has_attached:
        result.append(('AttachedNetworks', 'Attached Networks'))

    if parent_type == 'Cluster' and not has_failover:
        result.append(('FailoverClusterGroup', 'Failover Group'))

    return result


def build_object_context_menu(
    parent_widget,
    item,
    selection,
    *,
    all_tags,
    clipboard,
    count_selected_firewalls_fn,
    get_item_library_id_fn,
    is_deletable_fn,
    is_system_group_fn,
    lib_is_ro,
    obj_is_locked,
    selected_tags,
    sibling_interfaces,
    writable_libraries,
):
    """Build context menu for an object item.

    Menu order matches fwbuilder's ``contextMenuRequested()`` exactly.

    Returns ``(menu, handlers)`` where *handlers* maps
    ``QAction -> ('method_name', *args)`` tuples.
    """
    from PySide6.QtCore import Qt

    obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
    effective_ro = item.data(0, Qt.ItemDataRole.UserRole + 5) or False
    num_selected = len(selection)
    multi = num_selected > 1
    is_sys = is_system_group_fn(item)
    is_firewalls_folder = (
        obj_type == 'ObjectGroup' and item.text(0) == 'Firewalls' and is_sys
    )

    menu = QMenu(parent_widget)
    handlers = {}

    # ── 1. Expand / Collapse ──────────────────────────────────────────
    if item.childCount() > 0:
        if item.isExpanded():
            act = menu.addAction('Collapse')
            act.triggered.connect(lambda: item.setExpanded(False))
        else:
            act = menu.addAction('Expand')
            act.triggered.connect(lambda: item.setExpanded(True))
        menu.addSeparator()

    # ── 2. Edit / Inspect — always shown; disabled if multi or system group
    label = 'Inspect' if effective_ro else 'Edit'
    act = menu.addAction(label)
    act.setEnabled(not multi and not is_sys)
    handlers[act] = ('_ctx_edit', item)

    # ── 3. Open (RuleSet only) ────────────────────────────────────────
    if not multi and obj_type in RULE_SET_TYPES:
        act = menu.addAction('Open')
        handlers[act] = ('_ctx_open_ruleset', item)

    # ── 4. Duplicate ... — hidden for system groups ───────────────────
    if not multi and obj_type not in NO_DUPLICATE_TYPES and not is_sys:
        if len(writable_libraries) == 1:
            act = menu.addAction('Duplicate ...')
            lib_id = writable_libraries[0][0]
            handlers[act] = ('_ctx_duplicate', item, lib_id)
        elif writable_libraries:
            dup_menu = menu.addMenu('Duplicate ...')
            for lib_id, lib_name in writable_libraries:
                act = dup_menu.addAction(f'place in library {lib_name}')
                handlers[act] = ('_ctx_duplicate', item, lib_id)
        else:
            act = menu.addAction('Duplicate ...')
            act.setEnabled(False)

    # ── 5. Move ... — hidden for system groups ────────────────────────
    if not multi and obj_type not in NO_MOVE_TYPES and not effective_ro and not is_sys:
        current_lib_id = get_item_library_id_fn(item)
        move_libs = [
            (lid, lname) for lid, lname in writable_libraries if lid != current_lib_id
        ]
        if len(move_libs) == 1:
            act = menu.addAction('Move ...')
            lib_id = move_libs[0][0]
            handlers[act] = ('_ctx_move', item, lib_id)
        elif move_libs:
            move_menu = menu.addMenu('Move ...')
            for lib_id, lib_name in move_libs:
                act = move_menu.addAction(f'to library {lib_name}')
                handlers[act] = ('_ctx_move', item, lib_id)
        else:
            act = menu.addAction('Move ...')
            act.setEnabled(False)

    # ── 6. Copy / Cut / Paste ─────────────────────────────────────────
    menu.addSeparator()

    # Copy — disabled for NO_COPY_TYPES + system groups.
    if multi:
        can_copy = all(
            (it.data(0, Qt.ItemDataRole.UserRole + 1) or '') not in NO_COPY_TYPES
            and not is_system_group_fn(it)
            for it in selection
        )
    else:
        can_copy = obj_type not in NO_COPY_TYPES and not is_sys

    act = menu.addAction('Copy')
    act.setShortcut(QKeySequence.StandardKey.Copy)
    act.setEnabled(can_copy)
    handlers[act] = ('_ctx_copy',)

    # Cut — same enabled state as Delete.
    if multi:
        can_cut = any(is_deletable_fn(it) for it in selection)
    else:
        can_cut = is_deletable_fn(item)

    act = menu.addAction('Cut')
    act.setShortcut(QKeySequence.StandardKey.Cut)
    act.setEnabled(can_cut)
    handlers[act] = ('_ctx_cut',)

    can_paste = clipboard is not None and not effective_ro
    act = menu.addAction('Paste')
    act.setShortcut(QKeySequence.StandardKey.Paste)
    act.setEnabled(can_paste)
    handlers[act] = ('_ctx_paste', item)

    # ── 7. Delete ─────────────────────────────────────────────────────
    menu.addSeparator()
    if multi:
        can_delete = any(is_deletable_fn(it) for it in selection)
        act = menu.addAction('Delete')
        act.setShortcut(QKeySequence.StandardKey.Delete)
        act.setEnabled(can_delete)
        handlers[act] = ('_delete_selected',)
    else:
        can_delete = is_deletable_fn(item)
        act = menu.addAction('Delete')
        act.setShortcut(QKeySequence.StandardKey.Delete)
        act.setEnabled(can_delete)
        handlers[act] = ('_ctx_delete', item)

    # ── 8. New [Type] + New Subfolder (single-select only) ────────────
    if not multi:
        new_types = _get_new_object_types(item, obj_type)
        show_subfolder = obj_type == 'Library' or obj_type in SUBFOLDER_TYPES
        # Path exception: user ObjectGroup under "Groups" → no subfolder.
        if show_subfolder and obj_type == 'ObjectGroup' and not is_sys:
            folder_info = _find_folder_context(item)
            if folder_info is not None and folder_info[0] == 'Groups':
                show_subfolder = False
        if new_types or show_subfolder:
            menu.addSeparator()
        for type_name, display_name in new_types:
            icon_path = ICON_MAP.get(type_name, '')
            act = menu.addAction(QIcon(icon_path), f'New {display_name}')
            act.setEnabled(not effective_ro)
            handlers[act] = ('_ctx_new_object', item, type_name)
        if show_subfolder:
            act = menu.addAction(QIcon(CATEGORY_ICON), 'New Subfolder')
            act.setEnabled(not effective_ro)
            handlers[act] = ('_ctx_new_subfolder', item)

    # ── 9. Find / Where used ──────────────────────────────────────────
    menu.addSeparator()
    can_find = not multi and not is_sys

    act = menu.addAction('Find')
    act.setEnabled(can_find)
    handlers[act] = ('_ctx_find', item)

    act = menu.addAction('Where used')
    act.setEnabled(can_find)
    handlers[act] = ('_ctx_where_used', item)

    # ── 10. Group (multi-select >= 2) ─────────────────────────────────
    menu.addSeparator()
    group_act = menu.addAction('Group')
    group_act.setEnabled(num_selected >= 2)
    handlers[group_act] = ('_ctx_group_objects',)

    # ── 11. Tags (Add / Remove submenus) ────────────────────────────
    kw_menu = menu.addMenu('Tags')
    kw_menu.setEnabled(not effective_ro)

    add_kw_menu = kw_menu.addMenu('Add')
    act = add_kw_menu.addAction('New Tag...')
    handlers[act] = ('_ctx_new_keyword',)
    if all_tags:
        add_kw_menu.addSeparator()
        for tag in sorted(all_tags, key=str.casefold):
            act = add_kw_menu.addAction(tag)
            handlers[act] = ('_ctx_add_keyword', tag)

    remove_kw_menu = kw_menu.addMenu('Remove')
    if selected_tags:
        for tag in sorted(selected_tags, key=str.casefold):
            act = remove_kw_menu.addAction(tag)
            handlers[act] = ('_ctx_remove_keyword', tag)
    else:
        remove_kw_menu.setEnabled(False)

    # ── 12. New Cluster from selected firewalls ───────────────────────
    if obj_type == 'Firewall' or is_firewalls_folder:
        act = menu.addAction(
            QIcon(ICON_MAP.get('Cluster', '')),
            'New Cluster from selected firewalls',
        )
        can_cluster = not effective_ro and count_selected_firewalls_fn() >= 2
        act.setEnabled(can_cluster)
        handlers[act] = ('_ctx_new_cluster_from_selected',)

    # ── 13. Compile / Install ─────────────────────────────────────────
    if obj_type in COMPILABLE_TYPES or is_firewalls_folder:
        menu.addSeparator()
        act = menu.addAction('Compile')
        act.setEnabled(not effective_ro)
        handlers[act] = ('_ctx_compile',)

        act = menu.addAction('Install')
        act.setEnabled(not effective_ro)
        handlers[act] = ('_ctx_install',)

    # ── 14. Make subinterface of ... (Interface only) ─────────────────
    if not multi and obj_type == 'Interface' and sibling_interfaces:
        menu.addSeparator()
        sub_menu = menu.addMenu('Make subinterface of ...')
        sub_menu.setEnabled(not effective_ro)
        for iface_id, iface_name in sibling_interfaces:
            act = sub_menu.addAction(iface_name)
            handlers[act] = ('_ctx_make_subinterface', item, iface_id)

    # ── 15. Lock / Unlock — always shown; enabled per lockability ─────
    menu.addSeparator()
    can_lock = obj_type in LOCKABLE_TYPES
    lock_act = menu.addAction('Lock')
    lock_act.setEnabled(can_lock and not lib_is_ro and not obj_is_locked)
    handlers[lock_act] = ('_ctx_lock',)

    unlock_act = menu.addAction('Unlock')
    unlock_act.setEnabled(can_lock and not lib_is_ro and obj_is_locked)
    handlers[unlock_act] = ('_ctx_unlock',)

    return menu, handlers


def _resolve_category_folder(item):
    """Resolve the effective system folder name for a category item.

    If the item itself is a known system folder (e.g. "Firewalls"),
    return its name directly.  Otherwise walk up the tree to find the
    enclosing system group or category folder whose name appears in
    ``NEW_TYPES_FOR_FOLDER``.  This lets user-created subfolders
    inherit the "New [Type]" actions from their parent system folder,
    matching fwbuilder's ``path.find("Firewalls") == 0`` logic.
    """
    from PySide6.QtCore import Qt

    # Check the item's own name first.
    name = item.text(0)
    if name in NEW_TYPES_FOR_FOLDER:
        return name

    # Walk up to find the enclosing system folder / group.
    current = item.parent()
    while current is not None:
        current_type = current.data(0, Qt.ItemDataRole.UserRole + 1)
        if current_type is None:
            # Another virtual folder — check its name.
            parent_name = current.text(0)
            if parent_name in NEW_TYPES_FOR_FOLDER:
                return parent_name
        elif current_type in ('IntervalGroup', 'ObjectGroup', 'ServiceGroup'):
            parent_name = current.text(0)
            if parent_name in NEW_TYPES_FOR_FOLDER:
                return parent_name
        elif current_type == 'Library':
            break
        current = current.parent()
    return None


def build_category_context_menu(parent_widget, item, *, has_mixed_selection):
    """Build context menu for a user subfolder item.

    Matches fwbuilder's subfolder menu: Delete, Rename, New [types].

    Returns ``(menu, handlers)`` where *handlers* maps
    ``QAction -> ('method_name', *args)`` tuples.
    """
    from PySide6.QtCore import Qt

    effective_folder = _resolve_category_folder(item)
    new_types = (
        NEW_TYPES_FOR_FOLDER.get(effective_folder, []) if effective_folder else []
    )

    # Determine read-only state from parent library.
    effective_ro = False
    parent = item.parent()
    while parent is not None:
        if parent.data(0, Qt.ItemDataRole.UserRole + 1) == 'Library':
            effective_ro = parent.data(0, Qt.ItemDataRole.UserRole + 5) or False
            break
        parent = parent.parent()

    disabled = has_mixed_selection or effective_ro

    menu = QMenu(parent_widget)
    handlers = {}

    # Delete folder.
    act = menu.addAction('Delete')
    act.setShortcut(QKeySequence.StandardKey.Delete)
    act.setEnabled(not disabled)
    handlers[act] = ('_ctx_delete_folder', item)

    # Rename folder.
    act = menu.addAction('Rename')
    act.setEnabled(not disabled)
    handlers[act] = ('_ctx_rename_folder', item)

    # New [types].
    if new_types:
        menu.addSeparator()
    for type_name, display_name in new_types:
        icon_path = ICON_MAP.get(type_name, '')
        act = menu.addAction(QIcon(icon_path), f'New {display_name}')
        act.setEnabled(not effective_ro)
        handlers[act] = ('_ctx_new_object', item, type_name)

    return menu, handlers
