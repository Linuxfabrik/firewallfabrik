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

"""Context-menu builder functions for PolicyView.

All functions accept a ``view`` parameter (the :class:`PolicyView` instance)
so they can access action handlers, selection state, and the object clipboard
without being methods on the view itself.
"""

import contextlib

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import QInputDialog

from firewallfabrik.core.objects import Direction, NATAction, PolicyAction
from firewallfabrik.gui.label_settings import (
    LABEL_KEYS,
    get_label_color,
    get_label_text,
)
from firewallfabrik.gui.policy_model import PolicyTreeModel

# ------------------------------------------------------------------
# Type-set constants (shared with policy_view drag-drop code)
# ------------------------------------------------------------------

ADDRESS_TYPES = frozenset(
    {
        'AddressRange',
        'AddressTable',
        'AttachedNetworks',
        'Cluster',
        'DNSName',
        'DynamicGroup',
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
)

SERVICE_TYPES = frozenset(
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
)

VALID_TYPES_BY_SLOT = {
    'dst': ADDRESS_TYPES,
    'itf': frozenset({'Interface'}),
    'itf_inb': frozenset({'Interface'}),
    'itf_outb': frozenset({'Interface'}),
    'odst': ADDRESS_TYPES,
    'osrc': ADDRESS_TYPES,
    'osrv': SERVICE_TYPES,
    'rdst': ADDRESS_TYPES,
    'rgtw': ADDRESS_TYPES,
    'ritf': frozenset({'Interface'}),
    'src': ADDRESS_TYPES,
    'srv': SERVICE_TYPES,
    'tdst': ADDRESS_TYPES,
    'tsrc': ADDRESS_TYPES,
    'tsrv': SERVICE_TYPES,
    'when': frozenset({'Interval', 'IntervalGroup'}),
}

# ------------------------------------------------------------------
# Action menu constants
# ------------------------------------------------------------------

# Actions whose Parameters entry should be enabled (have a dialog in fwbuilder).
ACTIONS_WITH_PARAMS = frozenset(
    {
        PolicyAction.Accounting,
        PolicyAction.Branch,
        PolicyAction.Custom,
        PolicyAction.Reject,
    }
)

# Action entries shown in the menu: (enum, display_label, icon_name).
ACTION_MENU_ENTRIES = (
    (PolicyAction.Accept, 'Accept', 'Accept'),
    (PolicyAction.Deny, 'Deny', 'Deny'),
    (PolicyAction.Reject, 'Reject', 'Reject'),
    (PolicyAction.Accounting, 'Accounting', 'Accounting'),
    (PolicyAction.Pipe, 'Queue', 'Pipe'),
    (PolicyAction.Custom, 'Custom', 'Custom'),
    (PolicyAction.Branch, 'Branch', 'Branch'),
    (PolicyAction.Continue, 'Continue', 'Continue'),
)

NAT_ACTION_MENU_ENTRIES = (
    (NATAction.Translate, 'Translate', 'Translate'),
    (NATAction.Branch, 'Branch', 'Branch'),
)

# ------------------------------------------------------------------
# Menu builder functions
# ------------------------------------------------------------------


def build_group_header_menu(menu, view, model, group_index):
    """Build context menu for a group header row."""
    menu.addAction(
        'Rename Group',
        lambda: view._rename_group_dialog(model, group_index),
    )


def build_row_menu(menu, view, model, index):
    """Build standard row-level context menu (# and Comment columns)."""
    selected = view._selected_rule_indices()
    if not selected:
        selected = [index]
    multi = len(selected) > 1
    rule_label = 'Rules' if multi else 'Rule'

    menu.addAction(
        'Insert Rule Above',
        lambda: view._insert_and_scroll(model, index=index, before=True),
    )
    menu.addAction(
        'Insert Rule Below',
        lambda: view._insert_and_scroll(model, index=index),
    )
    menu.addAction('Remove Rule', lambda: model.delete_rules([index]))
    menu.addSeparator()
    up = menu.addAction(
        'Move Rule Up',
        lambda: view._move_and_select(model.move_rule_up(index)),
    )
    up.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageUp))
    down = menu.addAction(
        'Move Rule Down',
        lambda: view._move_and_select(model.move_rule_down(index)),
    )
    down.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageDown))
    menu.addSeparator()
    copy_act = menu.addAction(
        f'Copy {rule_label}',
        lambda sel=selected: model.copy_rules(sel),
    )
    copy_act.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_C))
    cut_act = menu.addAction(
        f'Cut {rule_label}',
        lambda sel=selected: model.cut_rules(sel),
    )
    cut_act.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_X))
    clipboard_count = len(PolicyTreeModel._clipboard)
    paste_label = 'Rules' if clipboard_count > 1 else 'Rule'
    paste_above = menu.addAction(
        f'Paste {paste_label} Above',
        lambda: view._paste_and_scroll(model, index, before=True),
    )
    paste_below = menu.addAction(
        f'Paste {paste_label} Below',
        lambda: view._paste_and_scroll(model, index),
    )
    paste_below.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_V))
    paste_above.setEnabled(clipboard_count > 0)
    paste_below.setEnabled(clipboard_count > 0)
    menu.addSeparator()
    add_disable_action(menu, view, model, index)
    menu.addSeparator()
    add_compile_action(menu, view, model, index)


def build_action_menu(menu, view, model, index):
    """Build action-selection context menu matching fwbuilder."""
    rs_type = model.rule_set_type

    if rs_type == 'NAT':
        for action, label, icon_name in NAT_ACTION_MENU_ENTRIES:
            icon = QIcon(f':/Icons/{icon_name}/icon-tree')
            menu.addAction(
                icon,
                label,
                lambda a=action: view._change_action_and_edit(model, index, a),
            )
    elif rs_type == 'Routing':
        # Routing has no action menu entries.
        pass
    else:
        for action, label, icon_name in ACTION_MENU_ENTRIES:
            icon = QIcon(f':/Icons/{icon_name}/icon-tree')
            menu.addAction(
                icon,
                label,
                lambda a=action: view._change_action_and_edit(model, index, a),
            )

    if rs_type == 'Policy':
        menu.addSeparator()
        row_data = model.get_row_data(index)
        current_action = None
        if row_data is not None:
            with contextlib.suppress(TypeError, ValueError):
                current_action = PolicyAction(row_data.action_int)
        params_act = menu.addAction(
            'Parameters',
            lambda: view._open_action_editor(model, index),
        )
        params_act.setEnabled(current_action in ACTIONS_WITH_PARAMS)

    menu.addSeparator()
    add_compile_action(menu, view, model, index)


def build_direction_menu(menu, view, model, index):
    """Build direction-selection context menu."""
    rs_type = model.rule_set_type
    if rs_type != 'Policy':
        return  # Direction is Policy-only.

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
            lambda d=direction: model.set_direction(index, d),
        )


def build_metric_menu(menu, view, model, index):
    """Build Metric column context menu for routing rules."""
    menu.addAction(
        'Edit',
        lambda: view._open_metric_editor(model, index),
    )
    menu.addSeparator()
    add_compile_action(menu, view, model, index)


def build_element_menu(menu, view, model, index, col):
    """Build element column context menu matching fwbuilder's layout."""
    col_to_slot = model.col_to_slot
    slot = col_to_slot.get(col)
    if not slot:
        return
    row_data = model.get_row_data(index)
    if row_data is None:
        return
    elements = getattr(row_data, slot, [])

    # Determine the target element (clicked or first).
    target_id = target_name = target_type = None
    if elements:
        target_id, target_name, target_type, *_ = elements[0]
        if view._selected_element is not None:
            sel_rid, sel_slot, sel_tid = view._selected_element
            if sel_rid == row_data.rule_id and sel_slot == slot:
                for eid, ename, etype, *_ in elements:
                    if eid == sel_tid:
                        target_id, target_name, target_type = eid, ename, etype
                        break

    has_element = target_id is not None

    # Edit.
    edit_act = menu.addAction(
        'Edit',
        lambda oid=target_id, otype=target_type: view._open_element_editor(
            str(oid), otype
        ),
    )
    edit_act.setEnabled(has_element)
    menu.addSeparator()

    # Copy.
    copy_act = menu.addAction(
        'Copy',
        lambda tid=target_id, n=target_name, t=target_type: view._copy_element(
            tid, n, t
        ),
    )
    copy_act.setEnabled(has_element)

    # Cut.
    cut_act = menu.addAction(
        'Cut',
        lambda tid=target_id, n=target_name, t=target_type: view._cut_element(
            model, index, slot, tid, n, t
        ),
    )
    cut_act.setEnabled(has_element)

    # Paste.
    paste_act = menu.addAction(
        'Paste',
        lambda: view._paste_element(model, index, slot),
    )
    valid_types = VALID_TYPES_BY_SLOT.get(slot, frozenset())
    can_paste = (
        view._object_clipboard is not None
        and view._object_clipboard.get('type', '') in valid_types
    )
    paste_act.setEnabled(can_paste)

    # Delete.
    delete_act = menu.addAction(
        'Delete',
        lambda tid=target_id: model.remove_element(index, slot, tid),
    )
    delete_act.setEnabled(has_element)
    menu.addSeparator()

    # Where Used.
    where_act = menu.addAction(
        'Where Used',
        lambda oid=target_id, n=target_name, ot=target_type: view._show_where_used(
            str(oid), n, ot
        ),
    )
    where_act.setEnabled(has_element)

    # Reveal in Tree.
    reveal_act = menu.addAction(
        'Reveal in Tree',
        lambda oid=target_id: view._reveal_in_tree(str(oid)),
    )
    reveal_act.setEnabled(has_element)
    menu.addSeparator()

    # Negate toggle.
    negated = bool(row_data.negations.get(slot))
    negate_action = menu.addAction(
        'Negate',
        lambda: model.toggle_negation(index, slot),
    )
    negate_action.setCheckable(True)
    negate_action.setChecked(negated)
    negate_action.setEnabled(has_element)
    menu.addSeparator()

    # Compile Rule.
    add_compile_action(menu, view, model, index)


def build_comment_menu(menu, view, model, index):
    """Build Comment column context menu."""
    menu.addAction('Edit', lambda: view._open_comment_editor(model, index))
    menu.addSeparator()
    add_compile_action(menu, view, model, index)


def build_options_menu(menu, view, model, index):
    """Build Options column context menu."""
    menu.addAction(
        QIcon(':/Icons/Options/icon-tree'),
        'Rule Options',
        lambda: view._open_rule_options_dialog(model, index),
    )
    if model.rule_set_type == 'Policy':
        row_data = model.get_row_data(index)
        log_on = row_data is not None and bool(
            (row_data.options_display or [])
            and any(label == 'log' for _, label, _ in row_data.options_display)
        )
        on_action = menu.addAction(
            QIcon(':/Icons/Log/icon-tree'),
            'Logging On',
            lambda: model.set_logging(index, True),
        )
        off_action = menu.addAction(
            'Logging Off',
            lambda: model.set_logging(index, False),
        )
        on_action.setEnabled(not log_on)
        off_action.setEnabled(log_on)
    menu.addSeparator()
    add_compile_action(menu, view, model, index)


# ------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------


def add_new_group_action(menu, view, model, index):
    """Add 'New Group' action + separator for top-level rules."""
    selected = view._selected_rule_indices()
    if not selected:
        selected = [index]

    def _do_create():
        name, ok = QInputDialog.getText(
            view,
            'New Group',
            'Group name:',
        )
        if ok and name:
            model.create_group(name, selected)

    menu.addAction('New Group', _do_create)
    menu.addSeparator()


def add_to_adjacent_group_actions(menu, view, model, index):
    """Add 'Add to the Group <name>' actions for adjacent groups."""
    selected = view._selected_rule_indices()
    if not selected:
        selected = [index]
    above, below = model.adjacent_group_names(
        selected[0] if len(selected) == 1 else index,
    )
    if above:
        menu.addAction(
            f'Add to the Group {above}',
            lambda g=above: model.add_to_group(selected, g),
        )
    if below:
        menu.addAction(
            f'Add to the Group {below}',
            lambda g=below: model.add_to_group(selected, g),
        )
    if above or below:
        menu.addSeparator()


def add_disable_action(menu, view, model, index):
    """Add 'Disable Rule' or 'Enable Rule' action to the menu."""
    selected = view._selected_rule_indices()
    if not selected:
        selected = [index]
    multi = len(selected) > 1
    rule_label = 'Rules' if multi else 'Rule'
    any_enabled = any(
        not (rd := model.get_row_data(idx)) or not rd.disabled for idx in selected
    )
    any_disabled = any(
        (rd := model.get_row_data(idx)) is not None and rd.disabled for idx in selected
    )
    if any_disabled:
        menu.addAction(
            f'Enable {rule_label}',
            lambda sel=selected: view._set_disabled_on_selection(
                model, sel, disabled=False
            ),
        )
    if any_enabled:
        menu.addAction(
            f'Disable {rule_label}',
            lambda sel=selected: view._set_disabled_on_selection(
                model, sel, disabled=True
            ),
        )


def add_compile_action(menu, view, model, index):
    """Add 'Compile Rule' action, disabled for multi-select or disabled rules."""
    selected = view._selected_rule_indices()
    if not selected:
        selected = [index]
    row_data = model.get_row_data(index)
    enabled = len(selected) == 1 and row_data is not None and not row_data.disabled
    action = menu.addAction(
        'Compile Rule',
        lambda: view._do_compile_rule(model, index),
    )
    action.setShortcut(QKeySequence('X'))
    action.setEnabled(enabled)


def add_color_submenu(menu, view, model, index):
    """Add a 'Color' submenu with 7 label entries + 'No Color'."""
    color_menu = menu.addMenu('Change Color')
    selected = view._selected_rule_indices()
    if not selected:
        selected = [index]
    for key in LABEL_KEYS:
        pixmap = QPixmap(16, 16)
        pixmap.fill(QColor(get_label_color(key)))
        icon = QIcon(pixmap)
        color_menu.addAction(
            icon,
            get_label_text(key),
            lambda k=key: view._set_label_on_selection(model, selected, k),
        )
    color_menu.addSeparator()
    color_menu.addAction(
        'No Color',
        lambda: view._set_label_on_selection(model, selected, ''),
    )
