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

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QMenu

from firewallfabrik.gui.iface_opts_dialog import SUBINTERFACE_TYPES
from firewallfabrik.gui.object_tree_data import (
    CATEGORY_ICON,
    COMPILABLE_TYPES,
    ICON_MAP,
    LOCKABLE_TYPES,
    NEW_TYPES_FOR_PARENT,
    NO_COPY_TYPES,
    NO_DUPLICATE_TYPES,
    NO_MOVE_TYPES,
    RULE_SET_TYPES,
    SUBFOLDER_TYPES,
    path_allows_subfolder,
    path_new_types,
)


def _set_expanded_recursive(item, expanded):
    """Expand or collapse *item* and every descendant.

    Plain ``setExpanded`` only affects the clicked node, leaving deeper
    children in their previous state — which is what makes the tree pop
    open again after the filter cleared.  Walking the whole subtree
    fixes that.
    """
    stack = [item]
    while stack:
        node = stack.pop()
        node.setExpanded(expanded)
        for i in range(node.childCount()):
            stack.append(node.child(i))


def _get_new_object_types(item, obj_type, interface_state=None):
    """Return a list of ``(type_name, display_name)`` for the New menu.

    Matches fwbuilder's context menu: the entries of a device or an
    interface, then those ``addSubfolderActions`` derives from the item's
    path (``path_new_types``).
    """
    # Device and interface entries come first, the way
    # contextMenuRequested adds them before addSubfolderActions.
    if obj_type in ('Cluster', 'Firewall', 'Host'):
        result = list(NEW_TYPES_FOR_PARENT.get(obj_type, []))
    elif obj_type == 'Interface':
        result = _get_interface_new_types(item, interface_state)
    else:
        result = []
    # getMenuState turns every entry of AddObjectActions off for an
    # interface that carries no address of its own - dynamic, unnumbered
    # or a bridge port (fwbuilder5 ObjectManipulator.cpp:1166); the path
    # entries are among them.
    path_enabled = (interface_state or {}).get('takes_addresses', True)
    offered = {entry[0] for entry in result}
    for type_name, label in path_new_types(item_path(item)):
        if type_name not in offered:
            result.append((type_name, label, path_enabled))
            offered.add(type_name)
    return result


def item_path(item):
    """Return *item*'s path below its library, like ``getPath(true)``.

    "Objects/Hosts" for the standard folder, "Objects/Hosts/web" for a host
    in it, '' for the library itself.  ``None`` when the item is not inside
    a library.
    """
    from PySide6.QtCore import Qt

    parts = []
    current = item
    while current is not None:
        if current.data(0, Qt.ItemDataRole.UserRole + 1) == 'Library':
            return '/'.join(reversed(parts))
        parts.append(current.text(0))
        current = current.parent()
    return None


def _get_interface_new_types(item, interface_state=None):
    """Build the dynamic "New" list for an Interface item.

    Matches fwbuilder's ``contextMenuRequested()`` for the parts that are
    wired through:

    - New Interface (subinterface): only for Firewall interfaces
    - New Address (IPv4), New Address IPv6 (IPv6): always
    - New MAC Address (PhysAddress): always
    - New Attached Networks: greyed out once the interface has one,
      because the object stands for the subnets of that one interface and
      a second copy would say the same thing.
    - New Failover Group: only on an interface of a Cluster, and greyed
      out once the interface has one, because a failover group describes
      the one protocol that interface fails over with.

    An entry may carry a third element saying whether it is enabled; a
    two-element entry is enabled.
    """
    from PySide6.QtCore import Qt

    result = []

    # Determine parent device type.
    parent = item.parent()
    parent_type = parent.data(0, Qt.ItemDataRole.UserRole + 1) if parent else None

    state = interface_state or {}

    # Subinterface: only on an interface of a Firewall whose type can have
    # sub-interfaces (``getSubInterfaceTypes``, linux24.xml
    # ``subinterfaces``: ethernet, bridge and bonding, not a VLAN).
    if parent_type == 'Firewall' and SUBINTERFACE_TYPES.get(
        state.get('type') or 'ethernet'
    ):
        result.append(('Interface', 'Interface'))

    # The addresses and the MAC address are turned off on an interface
    # that carries no address of its own (getMenuState,
    # ObjectManipulator.cpp:1166).
    takes_addresses = state.get('takes_addresses', True)
    result.append(('IPv4', 'Address', takes_addresses))
    result.append(('IPv6', 'Address IPv6', takes_addresses))
    result.append(('PhysAddress', 'MAC Address', takes_addresses))

    # One per interface, the way `ObjectManipulator::contextMenuRequested`
    # offers it only while `getFirstByType(AttachedNetworks)` finds none.
    has_attached = any(
        item.child(i).data(0, Qt.ItemDataRole.UserRole + 1) == 'AttachedNetworks'
        for i in range(item.childCount())
    )
    result.append(('AttachedNetworks', 'Attached Networks', not has_attached))

    if parent_type == 'Cluster':
        has_group = any(
            item.child(i).data(0, Qt.ItemDataRole.UserRole + 1)
            == 'FailoverClusterGroup'
            for i in range(item.childCount())
        )
        result.append(('FailoverClusterGroup', 'Failover Group', not has_group))

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
    interface_state=None,
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
    # Static alphabetical order so positions don't shift with the
    # item's current expand state — preserves muscle memory.  The
    # base-name actions are no-ops when the item is already in the
    # requested state.
    if item.childCount() > 0:
        act = menu.addAction('Collapse')
        act.triggered.connect(lambda: item.setExpanded(False))
        act = menu.addAction('Collapse All')
        act.triggered.connect(lambda: _set_expanded_recursive(item, False))
        act = menu.addAction('Expand')
        act.triggered.connect(lambda: item.setExpanded(True))
        act = menu.addAction('Expand All')
        act.triggered.connect(lambda: _set_expanded_recursive(item, True))
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

    act = menu.addAction('Copy\tCtrl+C')
    act.setEnabled(can_copy)
    handlers[act] = ('_ctx_copy',)

    # Cut — same enabled state as Delete.
    if multi:
        can_cut = any(is_deletable_fn(it) for it in selection)
    else:
        can_cut = is_deletable_fn(item)

    act = menu.addAction('Cut\tCtrl+X')
    act.setEnabled(can_cut)
    handlers[act] = ('_ctx_cut',)

    can_paste = clipboard is not None and not effective_ro
    act = menu.addAction('Paste\tCtrl+V')
    act.setEnabled(can_paste)
    handlers[act] = ('_ctx_paste', item)

    # ── 7. Delete ─────────────────────────────────────────────────────
    menu.addSeparator()
    if multi:
        can_delete = any(is_deletable_fn(it) for it in selection)
        act = menu.addAction('Delete\tDel')
        act.setEnabled(can_delete)
        handlers[act] = ('_delete_selected',)
    else:
        can_delete = is_deletable_fn(item)
        act = menu.addAction('Delete\tDel')
        act.setEnabled(can_delete)
        handlers[act] = ('_ctx_delete', item)

    # ── 8. New [Type] + New Subfolder (single-select only) ────────────
    if not multi:
        new_types = _get_new_object_types(item, obj_type, interface_state)
        show_subfolder = obj_type in SUBFOLDER_TYPES and path_allows_subfolder(
            item_path(item)
        )
        if new_types or show_subfolder:
            menu.addSeparator()
        for entry in new_types:
            type_name, display_name = entry[0], entry[1]
            offered = entry[2] if len(entry) > 2 else True
            icon_path = ICON_MAP.get(type_name, '')
            act = menu.addAction(QIcon(icon_path), f'New {display_name}')
            act.setEnabled(offered and not effective_ro)
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


def build_category_context_menu(parent_widget, item, *, clipboard, has_mixed_selection):
    """Build context menu for a user subfolder item.

    Matches fwbuilder's subfolder menu: Delete, Rename, Paste, New [types].

    Returns ``(menu, handlers)`` where *handlers* maps
    ``QAction -> ('method_name', *args)`` tuples.
    """
    from PySide6.QtCore import Qt

    path = item_path(item)
    new_types = path_new_types(path)

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

    # Expand / Collapse — same static alphabetical order as the object menu.
    if item.childCount() > 0:
        act = menu.addAction('Collapse')
        act.triggered.connect(lambda: item.setExpanded(False))
        act = menu.addAction('Collapse All')
        act.triggered.connect(lambda: _set_expanded_recursive(item, False))
        act = menu.addAction('Expand')
        act.triggered.connect(lambda: item.setExpanded(True))
        act = menu.addAction('Expand All')
        act.triggered.connect(lambda: _set_expanded_recursive(item, True))
        menu.addSeparator()

    # Delete folder.
    act = menu.addAction('Delete\tDel')
    act.setEnabled(not disabled)
    handlers[act] = ('_ctx_delete_folder', item)

    # Rename folder.
    act = menu.addAction('Rename')
    act.setEnabled(not disabled)
    handlers[act] = ('_ctx_rename_folder', item)

    # Paste.
    menu.addSeparator()
    can_paste = clipboard is not None and not effective_ro
    act = menu.addAction('Paste\tCtrl+V')
    act.setEnabled(can_paste)
    handlers[act] = ('_ctx_paste', item)

    # New [types] + New Subfolder.
    menu.addSeparator()
    for type_name, display_name in new_types:
        icon_path = ICON_MAP.get(type_name, '')
        act = menu.addAction(QIcon(icon_path), f'New {display_name}')
        act.setEnabled(not effective_ro)
        handlers[act] = ('_ctx_new_object', item, type_name)

    if path_allows_subfolder(path):
        act = menu.addAction(QIcon(CATEGORY_ICON), 'New Subfolder')
        act.setEnabled(not effective_ro)
        handlers[act] = ('_ctx_new_subfolder', item)

    return menu, handlers
