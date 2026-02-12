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

"""QTreeView wrapper for policy rule display with group and editing support."""

import json
import uuid

from PySide6.QtCore import QModelIndex, QRect, QSettings, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QKeySequence, QPalette, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QInputDialog,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QTreeView,
)

from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.gui.label_settings import (
    LABEL_KEYS,
    get_label_color,
    get_label_text,
)
from firewallfabrik.gui.policy_model import (
    _COL_ACTION,
    _COL_DIRECTION,
    _COL_TO_SLOT,
    _ELEMENT_COLS,
    ELEMENTS_ROLE,
    FWF_MIME_TYPE,
    NEGATED_ROLE,
)

_VALID_TYPES_BY_SLOT = {
    'dst': frozenset(
        {
            'AddressRange',
            'Cluster',
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
    ),
    'itf': frozenset({'Interface'}),
    'src': frozenset(
        {
            'AddressRange',
            'Cluster',
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
    ),
    'srv': frozenset(
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
    ),
    'when': frozenset({'Interval', 'IntervalGroup'}),
}


class _CellBorderDelegate(QStyledItemDelegate):
    """Delegate that draws lightgray cell borders, vertical padding, and
    renders element columns with per-object icons stacked vertically.

    Matches fwbuilder's ``RuleSetViewDelegate`` look.
    """

    _BORDER_COLOR = QColor('lightgray')
    _H_PAD = 2
    _HIGHLIGHT_BG = QColor(0xE8, 0xE8, 0xE8)  # discrete light gray, like fwbuilder
    _ICON_TEXT_GAP = 2
    _V_PAD = 2

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.decorationAlignment = (
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )

    def _icon_size(self):
        """Return the configured icon size (16 or 25)."""
        return QSettings().value('UI/IconSizeInRules', 25, type=int)

    def _icon_suffix(self, negated=False):
        """Return the QRC alias suffix for the configured size."""
        if self._icon_size() == 16:
            return 'icon-neg-tree' if negated else 'icon-tree'
        return 'icon-neg' if negated else 'icon'

    def sizeHint(self, option, index):
        icon_sz = self._icon_size()
        fm = option.fontMetrics
        line_h = max(icon_sz, fm.height())
        elements = index.data(ELEMENTS_ROLE)
        if elements:
            height = line_h * len(elements) + 2 * self._V_PAD
            max_text_w = max(fm.horizontalAdvance(name) for _, name, _ in elements)
            width = icon_sz + self._ICON_TEXT_GAP + max_text_w + 2 * self._H_PAD
            return QSize(width, height)
        return QSize(super().sizeHint(option, index).width(), line_h + 2 * self._V_PAD)

    def paint(self, painter, option, index):
        # Draw selection/background only — suppress text and icon so we
        # can render everything ourselves with consistent top-alignment.
        self.initStyleOption(option, index)
        option.text = ''
        option.icon = QIcon()
        # Use a discrete light gray for selection instead of the system blue.
        option.palette.setColor(QPalette.ColorRole.Highlight, self._HIGHLIGHT_BG)
        option.palette.setColor(
            QPalette.ColorRole.HighlightedText,
            option.palette.color(QPalette.ColorRole.Text),
        )
        style = option.widget.style() if option.widget else None
        if style:
            style.drawControl(
                QStyle.ControlElement.CE_ItemViewItem,
                option,
                painter,
                option.widget,
            )

        elements = index.data(ELEMENTS_ROLE)
        if elements:
            self._paint_elements(painter, option, index, elements)
        else:
            self._paint_cell(painter, option, index)

        # Cell border.
        painter.save()
        painter.setPen(self._BORDER_COLOR)
        painter.drawRect(option.rect.adjusted(0, 0, -1, -1))
        painter.restore()

    def _paint_cell(self, painter, option, index):
        """Paint a single-value cell (icon + text) top-aligned."""
        icon_sz = self._icon_size()
        rect = option.rect.adjusted(self._H_PAD, self._V_PAD, -self._H_PAD, 0)
        line_h = max(icon_sz, painter.fontMetrics().height())
        fg = index.data(Qt.ItemDataRole.ForegroundRole)
        alignment = index.data(Qt.ItemDataRole.TextAlignmentRole)
        h_align = Qt.AlignmentFlag.AlignLeft
        if alignment and alignment & Qt.AlignmentFlag.AlignRight:
            h_align = Qt.AlignmentFlag.AlignRight

        painter.save()
        if fg:
            painter.setPen(fg.color() if hasattr(fg, 'color') else fg)

        x = rect.left()
        icon = index.data(Qt.ItemDataRole.DecorationRole)
        if isinstance(icon, QIcon) and not icon.isNull():
            icon.paint(painter, QRect(x, rect.top(), icon_sz, line_h))
            x += icon_sz + self._ICON_TEXT_GAP

        text = index.data(Qt.ItemDataRole.DisplayRole)
        if text:
            text_rect = QRect(x, rect.top(), rect.right() - x, line_h)
            painter.drawText(
                text_rect,
                h_align | Qt.AlignmentFlag.AlignVCenter,
                str(text),
            )
        painter.restore()

    def _paint_elements(self, painter, option, index, elements):
        """Paint a list of (id, name, type) elements with icons."""
        icon_sz = self._icon_size()
        negated = index.data(NEGATED_ROLE)
        icon_suffix = self._icon_suffix(negated=negated)
        rect = option.rect.adjusted(self._H_PAD, self._V_PAD, -self._H_PAD, 0)
        line_h = max(icon_sz, painter.fontMetrics().height())
        fg = index.data(Qt.ItemDataRole.ForegroundRole)

        painter.save()
        if fg:
            painter.setPen(fg.color() if hasattr(fg, 'color') else fg)
        for _target_id, name, obj_type in elements:
            icon_path = f':/Icons/{obj_type}/{icon_suffix}' if obj_type else ''
            x = rect.left()
            if icon_path:
                icon = QIcon(icon_path)
                if not icon.isNull():
                    icon.paint(
                        painter,
                        QRect(x, rect.top(), icon_sz, line_h),
                    )
                x += icon_sz + self._ICON_TEXT_GAP
            text_rect = QRect(x, rect.top(), rect.right() - x, line_h)
            painter.drawText(
                text_rect,
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                name,
            )
            rect.setTop(rect.top() + line_h)
        painter.restore()


class PolicyView(QTreeView):
    """Tree view with context menus, keyboard shortcuts, and drop support."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setRootIsDecorated(True)
        self.setItemDelegate(_CellBorderDelegate(self))
        self._apply_icon_size()
        self.header().setStretchLastSection(True)
        self.header().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive,
        )
        self.header().sectionHandleDoubleClicked.connect(
            self.resizeColumnToContents,
        )

        # Context menu.
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

        # Double-click on group header → rename.
        self.doubleClicked.connect(self._on_double_clicked)

        # Drop support.
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setDropIndicatorShown(True)

    # ------------------------------------------------------------------
    # Model setup
    # ------------------------------------------------------------------

    def setModel(self, model):
        super().setModel(model)
        if model is not None:
            model.modelReset.connect(self._configure_groups)
            self._configure_groups()

    def _apply_icon_size(self):
        """Set the view's icon size from the user preference."""
        sz = QSettings().value('UI/IconSizeInRules', 25, type=int)
        self.setIconSize(QSize(sz, sz))

    def _configure_groups(self):
        """Mark group rows as first-column-spanned, expand, and fit columns."""
        model = self.model()
        if model is None:
            return
        self._apply_icon_size()
        for row in range(model.rowCount(QModelIndex())):
            idx = model.index(row, 0, QModelIndex())
            if model.is_group(idx):
                self.setFirstColumnSpanned(row, QModelIndex(), True)
        self.expandAll()
        for col in range(model.columnCount()):
            self.resizeColumnToContents(col)

    # ------------------------------------------------------------------
    # Double-click to rename group
    # ------------------------------------------------------------------

    def _on_double_clicked(self, index):
        model = self.model()
        if model is None or not model.is_group(index):
            return
        old_name = model.group_name(index)
        new_name, ok = QInputDialog.getText(
            self,
            'Rename Group',
            'Group name:',
            text=old_name,
        )
        if ok and new_name and new_name != old_name:
            model.rename_group(index, new_name)

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def _show_context_menu(self, pos):
        index = self.indexAt(pos)
        model = self.model()
        if model is None:
            return

        menu = QMenu(self)

        if not index.isValid():
            # Clicked on empty area.
            menu.addAction(
                'Insert New Rule on Top', lambda: model.insert_rule(at_top=True)
            )
            menu.addAction(
                'Insert New Rule at Bottom', lambda: model.insert_rule(at_bottom=True)
            )
            menu.exec(self.viewport().mapToGlobal(pos))
            return

        if model.is_group(index):
            self._build_group_header_menu(menu, model, index)
            menu.exec(self.viewport().mapToGlobal(pos))
            return

        col = index.column()

        # Check if this rule is inside a group or at top level.
        row_data = model.get_row_data(index)
        in_group = row_data is not None and row_data.group

        if in_group:
            menu.addAction(
                'Remove From Group',
                lambda: model.remove_from_group([index]),
            )
            menu.addSeparator()
        elif not in_group:
            self._add_new_group_action(menu, model, index)

        self._add_color_submenu(menu, model, index)
        menu.addSeparator()

        if col == _COL_ACTION:
            self._build_action_menu(menu, model, index)
        elif col == _COL_DIRECTION:
            self._build_direction_menu(menu, model, index)
        elif col in _ELEMENT_COLS:
            self._build_element_menu(menu, model, index, col)
        else:
            self._build_row_menu(menu, model, index)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _add_new_group_action(self, menu, model, index):
        """Add 'New Group' action + separator for top-level rules."""
        selected = self._selected_rule_indices()
        if not selected:
            selected = [index]

        def _do_create():
            name, ok = QInputDialog.getText(
                self,
                'New Group',
                'Group name:',
            )
            if ok and name:
                model.create_group(name, selected)

        menu.addAction('New Group', _do_create)
        menu.addSeparator()

    def _build_group_header_menu(self, menu, model, group_index):
        """Build context menu for a group header row."""
        menu.addAction(
            'Rename Group',
            lambda: self._rename_group_dialog(model, group_index),
        )

    def _rename_group_dialog(self, model, group_index):
        old_name = model.group_name(group_index)
        new_name, ok = QInputDialog.getText(
            self,
            'Rename Group',
            'Group name:',
            text=old_name,
        )
        if ok and new_name and new_name != old_name:
            model.rename_group(group_index, new_name)

    def _build_row_menu(self, menu, model, index):
        """Build standard row-level context menu (# and Comment columns)."""
        menu.addAction('Insert Rule Above', lambda: model.insert_rule(index))
        menu.addAction(
            'Insert Rule Below',
            lambda: self._insert_below(model, index),
        )
        menu.addSeparator()
        menu.addAction('Remove Rule', lambda: model.delete_rules([index]))
        menu.addSeparator()
        up = menu.addAction(
            'Move Up',
            lambda: self._move_and_select(model.move_rule_up(index)),
        )
        up.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageUp))
        down = menu.addAction(
            'Move Down',
            lambda: self._move_and_select(model.move_rule_down(index)),
        )
        down.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageDown))

    @staticmethod
    def _insert_below(model, index):
        """Insert a rule below *index* by creating a sibling index at row+1."""
        parent = index.parent()
        next_row = index.row() + 1
        # Create an index at the next row if it exists, otherwise pass None.
        if next_row < model.rowCount(parent):
            next_idx = model.index(next_row, 0, parent)
        else:
            next_idx = index
        # Use a position-based insert: the new rule goes at position + 1.
        rd = model.get_row_data(index)
        if rd is not None:
            # Directly insert at the rule's position + 1 via a temporary index.
            model.insert_rule(next_idx)
        else:
            model.insert_rule(at_bottom=True)

    def _build_action_menu(self, menu, model, index):
        """Build action-selection context menu."""
        for action in (PolicyAction.Accept, PolicyAction.Deny, PolicyAction.Reject):
            icon = QIcon(f':/Icons/{action.name}/icon-tree')
            menu.addAction(
                icon,
                action.name,
                lambda a=action: model.set_action(index, a),
            )

    def _build_direction_menu(self, menu, model, index):
        """Build direction-selection context menu."""
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

    def _build_element_menu(self, menu, model, index, col):
        """Build element column context menu with remove actions."""
        slot = _COL_TO_SLOT[col]
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        elements = getattr(row_data, slot, [])
        if not elements:
            menu.addAction('(empty)').setEnabled(False)
            return
        for target_id, name, _type in elements:
            menu.addAction(
                f'Remove {name}',
                lambda tid=target_id: model.remove_element(index, slot, tid),
            )

    def _add_color_submenu(self, menu, model, index):
        """Add a 'Color' submenu with 7 label entries + 'No Color'."""
        color_menu = menu.addMenu('Change Color')
        selected = self._selected_rule_indices()
        if not selected:
            selected = [index]
        for key in LABEL_KEYS:
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(get_label_color(key)))
            icon = QIcon(pixmap)
            color_menu.addAction(
                icon,
                get_label_text(key),
                lambda k=key: self._set_label_on_selection(model, selected, k),
            )
        color_menu.addSeparator()
        color_menu.addAction(
            'No Color',
            lambda: self._set_label_on_selection(model, selected, ''),
        )

    @staticmethod
    def _set_label_on_selection(model, indices, label_key):
        """Apply *label_key* to all rules in *indices*."""
        for idx in indices:
            model.set_label(idx, label_key)

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------

    def _selected_rule_indices(self):
        """Return unique QModelIndex list for selected rule rows."""
        seen = set()
        result = []
        for idx in self.selectedIndexes():
            model = self.model()
            if model is None:
                continue
            # Normalize to column 0.
            idx0 = model.index(idx.row(), 0, idx.parent())
            key = (idx0.row(), idx0.internalPointer())
            if key not in seen and not model.is_group(idx0):
                seen.add(key)
                result.append(idx0)
        return result

    def _move_and_select(self, rule_id):
        """Re-select the moved rule after a move operation."""
        if rule_id is None:
            return
        model = self.model()
        if model is None:
            return
        new_idx = model.index_for_rule(rule_id)
        if new_idx.isValid():
            self.setCurrentIndex(new_idx)

    # ------------------------------------------------------------------
    # Keyboard shortcuts
    # ------------------------------------------------------------------

    def keyPressEvent(self, event):
        model = self.model()
        if model is None:
            super().keyPressEvent(event)
            return

        key = event.key()
        modifiers = event.modifiers()

        if modifiers == Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_PageUp:
                idx = self.currentIndex()
                if idx.isValid() and not model.is_group(idx):
                    self._move_and_select(model.move_rule_up(idx))
                return
            if key == Qt.Key.Key_PageDown:
                idx = self.currentIndex()
                if idx.isValid() and not model.is_group(idx):
                    self._move_and_select(model.move_rule_down(idx))
                return

        if modifiers == Qt.KeyboardModifier.NoModifier:
            if key == Qt.Key.Key_Delete:
                indices = self._selected_rule_indices()
                if indices:
                    model.delete_rules(indices)
                return
            if key == Qt.Key.Key_Insert:
                idx = self.currentIndex()
                if idx.isValid() and not model.is_group(idx):
                    model.insert_rule(idx)
                else:
                    model.insert_rule(at_bottom=True)
                return

        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    # Drop support
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if not event.mimeData().hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return
        index = self.indexAt(event.position().toPoint())
        model = self.model()
        if (
            index.isValid()
            and index.column() in _ELEMENT_COLS
            and model is not None
            and not model.is_group(index)
        ):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        mime = event.mimeData()
        if not mime.hasFormat(FWF_MIME_TYPE):
            event.ignore()
            return

        index = self.indexAt(event.position().toPoint())
        model = self.model()
        if (
            not index.isValid()
            or index.column() not in _ELEMENT_COLS
            or model is None
            or model.is_group(index)
        ):
            event.ignore()
            return

        try:
            payload = json.loads(bytes(mime.data(FWF_MIME_TYPE)).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            event.ignore()
            return

        obj_id = payload.get('id')
        obj_type = payload.get('type', '')
        if not obj_id:
            event.ignore()
            return

        slot = _COL_TO_SLOT[index.column()]
        valid_types = _VALID_TYPES_BY_SLOT.get(slot, frozenset())
        if obj_type not in valid_types:
            event.ignore()
            return

        model.add_element(index, slot, uuid.UUID(obj_id))
        event.acceptProposedAction()
