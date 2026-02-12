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

import contextlib
import json
import uuid

from PySide6.QtCore import (
    QItemSelectionModel,
    QMimeData,
    QModelIndex,
    QRect,
    QSettings,
    QSize,
    Qt,
)
from PySide6.QtGui import QColor, QDrag, QIcon, QKeySequence, QPalette, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
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
    _COL_COMMENT,
    _COL_DIRECTION,
    _COL_OPTIONS,
    _COL_TO_SLOT,
    _ELEMENT_COLS,
    _SELECTABLE_COLS,
    _SLOT_TO_COL,
    ELEMENTS_ROLE,
    FWF_MIME_TYPE,
    NEGATED_ROLE,
    PolicyTreeModel,
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
    _HIGHLIGHT_COLOR = QColor(255, 255, 150, 100)
    _ICON_TEXT_GAP = 2
    _V_PAD = 2

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
        # Manual background painting matching fwbuilder's RuleSetViewDelegate:
        # flat fillRect instead of styled CE_ItemViewItem to avoid platform
        # selection effects (gradients, rounded corners, etc.).
        bg = index.data(Qt.ItemDataRole.BackgroundRole)
        if bg:
            painter.fillRect(option.rect, bg)
        elif option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(
                option.rect,
                option.palette.color(QPalette.ColorRole.Highlight),
            )

        # Highlight matched cell (Find / Where Used navigation).
        view = self.parent()
        if (
            isinstance(view, PolicyView)
            and view._highlight_rule_id is not None
            and view._highlight_col is not None
            and index.column() == view._highlight_col
        ):
            rd = index.model().get_row_data(index)
            if rd is not None and rd.rule_id == view._highlight_rule_id:
                painter.fillRect(option.rect, self._HIGHLIGHT_COLOR)

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
        # Per-element highlight for non-element columns (Action, Direction, Options).
        cell_highlighted = False
        view = self.parent()
        if hasattr(view, '_selected_element') and view._selected_element is not None:
            sel_index = view._selected_index
            if (
                index.row() == sel_index.row()
                and index.column() == sel_index.column()
                and index.parent() == sel_index.parent()
            ):
                if view.hasFocus():
                    painter.fillRect(
                        option.rect,
                        option.palette.color(QPalette.ColorRole.Highlight),
                    )
                    cell_highlighted = True
                else:
                    painter.save()
                    painter.setPen(QColor('red'))
                    painter.drawRect(option.rect.adjusted(0, 0, -1, -1))
                    painter.restore()

        icon_sz = self._icon_size()
        rect = option.rect.adjusted(self._H_PAD, self._V_PAD, -self._H_PAD, 0)
        line_h = max(icon_sz, painter.fontMetrics().height())
        fg = index.data(Qt.ItemDataRole.ForegroundRole)
        alignment = index.data(Qt.ItemDataRole.TextAlignmentRole)
        h_align = Qt.AlignmentFlag.AlignLeft
        if alignment and alignment & Qt.AlignmentFlag.AlignRight:
            h_align = Qt.AlignmentFlag.AlignRight

        painter.save()
        if cell_highlighted:
            painter.setPen(
                option.palette.color(QPalette.ColorRole.HighlightedText),
            )
        elif fg:
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

        # Per-element highlight from the view's selection.
        view = self.parent()
        sel_target_id = None
        if hasattr(view, '_selected_element') and view._selected_element is not None:
            sel_index = view._selected_index
            if (
                index.row() == sel_index.row()
                and index.column() == sel_index.column()
                and index.parent() == sel_index.parent()
            ):
                sel_target_id = view._selected_element[2]
        has_focus = view.hasFocus() if sel_target_id is not None else False

        painter.save()
        if fg:
            painter.setPen(fg.color() if hasattr(fg, 'color') else fg)
        default_pen = painter.pen()
        for target_id, name, obj_type in elements:
            # Draw per-element selection highlight.
            if sel_target_id is not None and target_id == sel_target_id:
                elem_rect = QRect(rect.left(), rect.top(), rect.width(), line_h)
                if has_focus:
                    painter.fillRect(
                        elem_rect,
                        option.palette.color(QPalette.ColorRole.Highlight),
                    )
                    painter.setPen(
                        option.palette.color(QPalette.ColorRole.HighlightedText),
                    )
                else:
                    painter.save()
                    painter.setPen(QColor('red'))
                    painter.drawRect(elem_rect.adjusted(0, 0, -1, -1))
                    painter.restore()

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
            # Restore default pen after highlighted element.
            if sel_target_id is not None and target_id == sel_target_id and has_focus:
                painter.setPen(default_pen)
            rect.setTop(rect.top() + line_h)
        painter.restore()


class PolicyView(QTreeView):
    """Tree view with context menus, keyboard shortcuts, and drop support."""

    _object_clipboard = None  # {'id': str, 'name': str, 'type': str} or None

    def __init__(self, parent=None):
        super().__init__(parent)
        self._highlight_rule_id = None
        self._highlight_col = None
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

        # Context menu (handled via contextMenuEvent override).

        # Double-click on group header → rename.
        self.doubleClicked.connect(self._on_double_clicked)

        # Drop support.
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setDropIndicatorShown(True)

        # Per-element selection state.
        self._selected_element = None  # (rule_id, slot, target_id) or None
        self._selected_index = QModelIndex()  # cell containing selected element
        self._drag_start_pos = None  # QPoint for drag threshold

    def set_highlight(self, rule_id, col):
        """Mark a single cell for visual emphasis."""
        self._highlight_rule_id = rule_id
        self._highlight_col = col
        self.viewport().update()

    def clear_highlight(self):
        """Remove cell highlight."""
        if self._highlight_rule_id is not None:
            self._highlight_rule_id = None
            self._highlight_col = None
            self.viewport().update()

    # ------------------------------------------------------------------
    # Model setup
    # ------------------------------------------------------------------

    def setModel(self, model):
        super().setModel(model)
        if model is not None:
            model.modelAboutToBeReset.connect(self._save_selection)
            model.modelReset.connect(self._configure_groups)
            self._configure_groups()

    def _apply_icon_size(self):
        """Set the view's icon size from the user preference."""
        sz = QSettings().value('UI/IconSizeInRules', 25, type=int)
        self.setIconSize(QSize(sz, sz))

    def _configure_groups(self):
        """Mark group rows as first-column-spanned, expand, fit columns, and restore selection."""
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
        self._restore_selection()

    # ------------------------------------------------------------------
    # Selection save / restore across model resets
    # ------------------------------------------------------------------

    def _save_selection(self):
        """Snapshot row and element selections before a model reset."""
        model = self.model()
        self._saved_row_rule_ids = []
        self._saved_current_rule_id = None
        if model is not None:
            for idx in self.selectionModel().selectedRows():
                rd = model.get_row_data(idx)
                if rd is not None:
                    self._saved_row_rule_ids.append(rd.rule_id)
            cur = self.currentIndex()
            if cur.isValid():
                rd = model.get_row_data(cur)
                if rd is not None:
                    self._saved_current_rule_id = rd.rule_id
        self._saved_element = self._selected_element  # (rule_id, slot, target_id)
        # Clear stale index references (they become invalid after reset).
        self._selected_element = None
        self._selected_index = QModelIndex()
        self._drag_start_pos = None

    def _restore_selection(self):
        """Re-select rows and the per-element highlight after a model reset."""
        model = self.model()
        if model is None:
            return

        sel_model = self.selectionModel()

        # Restore current index (needed for keyboard shortcuts like X to compile).
        saved_current = getattr(self, '_saved_current_rule_id', None)
        if saved_current is not None:
            idx = model.index_for_rule(saved_current)
            if idx.isValid():
                sel_model.setCurrentIndex(
                    idx,
                    QItemSelectionModel.SelectionFlag.NoUpdate,
                )
            self._saved_current_rule_id = None

        # Restore row selection.
        saved_ids = getattr(self, '_saved_row_rule_ids', [])
        if saved_ids:
            for rule_id in saved_ids:
                idx = model.index_for_rule(rule_id)
                if idx.isValid():
                    sel_model.select(
                        idx,
                        QItemSelectionModel.SelectionFlag.Select
                        | QItemSelectionModel.SelectionFlag.Rows,
                    )
            self._saved_row_rule_ids = []

        # Restore per-element selection.
        saved_elem = getattr(self, '_saved_element', None)
        if saved_elem is not None:
            rule_id, slot, _target_id = saved_elem
            idx = model.index_for_rule(rule_id)
            if idx.isValid():
                col = _SLOT_TO_COL.get(slot)
                if col is not None:
                    cell_idx = model.index(idx.row(), col, idx.parent())
                    self._selected_element = saved_elem
                    self._selected_index = cell_idx
            self._saved_element = None

    # ------------------------------------------------------------------
    # Per-element selection
    # ------------------------------------------------------------------

    def _clear_element_selection(self):
        """Clear the per-element selection and repaint the old cell."""
        if self._selected_element is not None:
            old_index = self._selected_index
            self._selected_element = None
            self._selected_index = QModelIndex()
            self._drag_start_pos = None
            if old_index.isValid():
                self.update(old_index)

    def _select_element(self, index, target_id, slot, rule_id):
        """Set the per-element selection and repaint affected cells."""
        old_index = self._selected_index
        self._selected_element = (rule_id, slot, target_id)
        self._selected_index = index
        if old_index.isValid() and old_index != index:
            self.update(old_index)
        self.update(index)

    def _select_element_at(self, index, vp_pos, model):
        """Select the element at *vp_pos* for any selectable column."""
        col = index.column()
        elem = self._element_at_pos(index, vp_pos)
        if elem is not None:
            tid, _n, _t = elem
            rd = model.get_row_data(index)
            if rd is not None:
                self._select_element(
                    index,
                    tid,
                    _COL_TO_SLOT[col],
                    rd.rule_id,
                )
        elif col not in _ELEMENT_COLS:
            rd = model.get_row_data(index)
            if rd is not None:
                self._select_element(
                    index,
                    f'__{_COL_TO_SLOT[col]}__',
                    _COL_TO_SLOT[col],
                    rd.rule_id,
                )

    def _element_at_pos(self, index, viewport_pos):
        """Return the ``(target_id, name, type)`` element at *viewport_pos*, or ``None``."""
        elements = index.data(ELEMENTS_ROLE)
        if not elements:
            return None
        vrect = self.visualRect(index)
        if not vrect.isValid():
            return None
        delegate = self.itemDelegate()
        icon_sz = delegate._icon_size()
        fm = self.fontMetrics()
        line_h = max(icon_sz, fm.height())
        relative_y = viewport_pos.y() - vrect.top() - delegate._V_PAD
        if relative_y < 0:
            return None
        elem_index = int(relative_y // line_h)
        if 0 <= elem_index < len(elements):
            return elements[elem_index]
        return None

    # ------------------------------------------------------------------
    # Mouse events for per-element selection and drag
    # ------------------------------------------------------------------

    def mousePressEvent(self, event):
        self.clear_highlight()
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            index = self.indexAt(pos)
            model = self.model()
            if (
                index.isValid()
                and model is not None
                and not model.is_group(index)
                and index.column() in _SELECTABLE_COLS
            ):
                col = index.column()
                elem = self._element_at_pos(index, pos)
                if elem is not None:
                    target_id, _name, _obj_type = elem
                    slot = _COL_TO_SLOT[col]
                    row_data = model.get_row_data(index)
                    if row_data is not None:
                        self._select_element(
                            index,
                            target_id,
                            slot,
                            row_data.rule_id,
                        )
                        # Only start drag for true element columns.
                        if col in _ELEMENT_COLS:
                            self._drag_start_pos = pos
                    else:
                        self._clear_element_selection()
                elif col not in _ELEMENT_COLS:
                    # Non-element columns (Action, Direction, Options)
                    # are always selectable even when the cell is empty.
                    row_data = model.get_row_data(index)
                    if row_data is not None:
                        self._select_element(
                            index,
                            f'__{_COL_TO_SLOT[col]}__',
                            _COL_TO_SLOT[col],
                            row_data.rule_id,
                        )
                    else:
                        self._clear_element_selection()
                else:
                    self._clear_element_selection()
            else:
                self._clear_element_selection()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if (
            self._drag_start_pos is not None
            and self._selected_element is not None
            and event.buttons() & Qt.MouseButton.LeftButton
        ):
            dist = (event.position().toPoint() - self._drag_start_pos).manhattanLength()
            if dist >= QApplication.startDragDistance():
                self._start_element_drag()
                return
        super().mouseMoveEvent(event)

    def _start_element_drag(self):
        """Initiate a drag operation for the selected element."""
        rule_id, slot, target_id = self._selected_element
        model = self.model()
        if model is None:
            return
        row_data = model.get_row_data(self._selected_index)
        if row_data is None:
            return
        elements = getattr(row_data, slot, [])
        name = ''
        obj_type = ''
        for eid, ename, etype in elements:
            if eid == target_id:
                name = ename
                obj_type = etype
                break
        if not obj_type:
            return

        payload = json.dumps(
            {
                'id': str(target_id),
                'name': name,
                'source_rule_id': str(rule_id),
                'source_slot': slot,
                'type': obj_type,
            }
        ).encode()

        mime_data = QMimeData()
        mime_data.setData(FWF_MIME_TYPE, payload)

        drag = QDrag(self)
        drag.setMimeData(mime_data)

        icon_sz = QSettings().value('UI/IconSizeInRules', 25, type=int)
        icon = QIcon(f':/Icons/{obj_type}/icon')
        if not icon.isNull():
            drag.setPixmap(icon.pixmap(icon_sz, icon_sz))

        self._drag_start_pos = None
        drag.exec(Qt.DropAction.CopyAction | Qt.DropAction.MoveAction)

    # ------------------------------------------------------------------
    # Double-click to rename group
    # ------------------------------------------------------------------

    def _on_double_clicked(self, index):
        model = self.model()
        if model is None:
            return
        if model.is_group(index):
            old_name = model.group_name(index)
            new_name, ok = QInputDialog.getText(
                self,
                'Rename Group',
                'Group name:',
                text=old_name,
            )
            if ok and new_name and new_name != old_name:
                model.rename_group(index, new_name)
            return

        col = index.column()
        row_data = model.get_row_data(index)
        if row_data is None:
            return

        if col in _ELEMENT_COLS:
            slot = _COL_TO_SLOT[col]
            elements = getattr(row_data, slot, [])
            if elements:
                target = None
                if self._selected_element is not None:
                    sel_rid, sel_slot, sel_tid = self._selected_element
                    if sel_rid == row_data.rule_id and sel_slot == slot:
                        for eid, ename, etype in elements:
                            if eid == sel_tid:
                                target = (eid, ename, etype)
                                break
                if target is None:
                    target = elements[0]
                if target[1] == 'Any':
                    self._show_any_message(col)
                else:
                    self._open_element_editor(str(target[0]), target[2])
                    self._reveal_in_tree(str(target[0]))
        elif col == _COL_ACTION:
            self._open_action_editor(model, index)
        elif col == _COL_COMMENT:
            self._open_comment_editor(model, index)
        elif col == _COL_DIRECTION:
            self._open_direction_editor(model, index)
        elif col == _COL_OPTIONS:
            self._open_rule_options_dialog(model, index)

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def contextMenuEvent(self, event):
        """Show context menu, using viewport coordinates for correct hit-testing."""
        vp_pos = self.viewport().mapFromGlobal(event.globalPos())
        index = self.indexAt(vp_pos)
        global_pos = event.globalPos()
        model = self.model()
        if model is None:
            return

        menu = QMenu(self)

        if not index.isValid():
            # Clicked on empty area.
            menu.addAction(
                'Insert New Rule on Top',
                lambda: self._insert_and_scroll(model, at_top=True),
            )
            menu.addAction(
                'Insert New Rule at Bottom',
                lambda: self._insert_and_scroll(model, at_bottom=True),
            )
            menu.exec(global_pos)
            return

        # setFirstColumnSpanned on group headers can cause indexAt() to
        # return the group index even for clicks on child rule rows.
        # Detect this and resolve to the correct child index.
        if model.is_group(index):
            child_index = self._child_index_at(model, index, vp_pos)
            if child_index is not None:
                index = child_index
            else:
                self._build_group_header_menu(menu, model, index)
                menu.exec(global_pos)
                return

        col = index.column()

        # Element and comment columns get their own self-contained menus
        # without group/color actions.
        if col in _ELEMENT_COLS:
            # Hit-test for per-element selection on right-click.
            elem = self._element_at_pos(index, vp_pos)
            if elem is not None:
                tid, _n, _t = elem
                rd = model.get_row_data(index)
                if rd is not None:
                    self._select_element(
                        index,
                        tid,
                        _COL_TO_SLOT[col],
                        rd.rule_id,
                    )
            self._build_element_menu(menu, model, index, col)
            menu.exec(global_pos)
            return

        if col == _COL_COMMENT:
            self._build_comment_menu(menu, model, index)
            menu.exec(global_pos)
            return

        # Columns with self-contained menus (no group/color).
        # Select the element on right-click for visual feedback.
        if col in _SELECTABLE_COLS and col not in _ELEMENT_COLS:
            self._select_element_at(index, vp_pos, model)

        if col == _COL_ACTION:
            self._build_action_menu(menu, model, index)
            menu.exec(global_pos)
            return

        if col == _COL_DIRECTION:
            self._build_direction_menu(menu, model, index)
            menu.exec(global_pos)
            return

        if col == _COL_OPTIONS:
            self._build_options_menu(menu, model, index)
            menu.exec(global_pos)
            return

        # Remaining columns get group/color actions.
        row_data = model.get_row_data(index)
        in_group = row_data is not None and row_data.group

        if in_group:
            selected = self._selected_rule_indices()
            if not selected:
                selected = [index]
            # Collect all selected in-group rule IDs; show action if any
            # selected rule is outermost (matches fwbuilder behavior).
            group_rids = []
            any_outermost = False
            for sel in selected:
                rd = model.get_row_data(sel)
                if rd is not None and rd.group:
                    group_rids.append(rd.rule_id)
                    if model.is_outermost(sel):
                        any_outermost = True
            if any_outermost and group_rids:
                menu.addAction(
                    'Remove From Group',
                    lambda rids=group_rids: model.remove_from_group_by_ids(rids),
                )
                menu.addSeparator()
        else:
            self._add_new_group_action(menu, model, index)
            self._add_to_adjacent_group_actions(menu, model, index)

        self._add_color_submenu(menu, model, index)
        menu.addSeparator()

        self._build_row_menu(menu, model, index)

        menu.exec(global_pos)

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

    def _add_to_adjacent_group_actions(self, menu, model, index):
        """Add 'Add to the Group <name>' actions for adjacent groups."""
        selected = self._selected_rule_indices()
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

    def _child_index_at(self, model, group_index, vp_pos):
        """Resolve a click below a group header to the correct child index.

        When ``setFirstColumnSpanned`` is active, ``indexAt()`` may return
        the group index for clicks on child rows.  This method checks the
        visual rects to find the actual child.

        Returns a child :class:`QModelIndex`, or *None* if the click is on
        the group header itself.
        """
        group_rect = self.visualRect(group_index)
        if group_rect.isValid() and group_rect.contains(vp_pos):
            return None  # Click is genuinely on the group header.

        child_count = model.rowCount(group_index)
        for row in range(child_count):
            child_idx = model.index(row, 0, group_index)
            child_rect = self.visualRect(child_idx)
            if (
                child_rect.isValid()
                and child_rect.top() <= vp_pos.y() <= child_rect.bottom()
            ):
                # Determine the correct column from the x coordinate.
                for col in range(model.columnCount()):
                    col_idx = model.index(row, col, group_index)
                    col_rect = self.visualRect(col_idx)
                    if (
                        col_rect.isValid()
                        and col_rect.left() <= vp_pos.x() <= col_rect.right()
                    ):
                        return col_idx
                return child_idx  # Fallback: column-0 child.
        return None

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
        selected = self._selected_rule_indices()
        if not selected:
            selected = [index]
        multi = len(selected) > 1
        rule_label = 'Rules' if multi else 'Rule'

        menu.addAction(
            'Insert Rule Above',
            lambda: self._insert_and_scroll(model, index=index, before=True),
        )
        menu.addAction(
            'Insert Rule Below',
            lambda: self._insert_and_scroll(model, index=index),
        )
        menu.addAction('Remove Rule', lambda: model.delete_rules([index]))
        menu.addSeparator()
        up = menu.addAction(
            'Move Rule Up',
            lambda: self._move_and_select(model.move_rule_up(index)),
        )
        up.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_PageUp))
        down = menu.addAction(
            'Move Rule Down',
            lambda: self._move_and_select(model.move_rule_down(index)),
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
            lambda: self._paste_and_scroll(model, index, before=True),
        )
        paste_above.setShortcut(QKeySequence(Qt.Modifier.CTRL | Qt.Key.Key_V))
        paste_below = menu.addAction(
            f'Paste {paste_label} Below',
            lambda: self._paste_and_scroll(model, index),
        )
        paste_above.setEnabled(clipboard_count > 0)
        paste_below.setEnabled(clipboard_count > 0)
        menu.addSeparator()
        self._add_disable_action(menu, model, index)
        menu.addSeparator()
        self._add_compile_action(menu, model, index)

    def _add_compile_action(self, menu, model, index):
        """Add 'Compile Rule' action, disabled for multi-select or disabled rules."""
        selected = self._selected_rule_indices()
        if not selected:
            selected = [index]
        row_data = model.get_row_data(index)
        enabled = len(selected) == 1 and row_data is not None and not row_data.disabled
        action = menu.addAction(
            'Compile Rule',
            lambda: self._do_compile_rule(model, index),
        )
        action.setShortcut(QKeySequence('X'))
        action.setEnabled(enabled)

    def _do_compile_rule(self, model, index):
        """Trigger single-rule compilation via the main window."""
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        main_win = self.window()
        if hasattr(main_win, 'compile_single_rule'):
            main_win.compile_single_rule(row_data.rule_id, model.rule_set_id)

    # Actions whose Parameters entry should be enabled (have a dialog in fwbuilder).
    _ACTIONS_WITH_PARAMS = frozenset(
        {
            PolicyAction.Accounting,
            PolicyAction.Branch,
            PolicyAction.Custom,
            PolicyAction.Reject,
        }
    )

    # Action entries shown in the menu: (enum, display_label, icon_name).
    _ACTION_MENU_ENTRIES = (
        (PolicyAction.Accept, 'Accept', 'Accept'),
        (PolicyAction.Deny, 'Deny', 'Deny'),
        (PolicyAction.Reject, 'Reject', 'Reject'),
        (PolicyAction.Accounting, 'Accounting', 'Accounting'),
        (PolicyAction.Pipe, 'Queue', 'Pipe'),
        (PolicyAction.Custom, 'Custom', 'Custom'),
        (PolicyAction.Branch, 'Branch', 'Branch'),
        (PolicyAction.Continue, 'Continue', 'Continue'),
    )

    def _build_action_menu(self, menu, model, index):
        """Build action-selection context menu matching fwbuilder."""
        for action, label, icon_name in self._ACTION_MENU_ENTRIES:
            icon = QIcon(f':/Icons/{icon_name}/icon-tree')
            menu.addAction(
                icon,
                label,
                lambda a=action: self._change_action_and_edit(model, index, a),
            )
        menu.addSeparator()

        row_data = model.get_row_data(index)
        current_action = None
        if row_data is not None:
            with contextlib.suppress(TypeError, ValueError):
                current_action = PolicyAction(row_data.action_int)
        params_act = menu.addAction(
            'Parameters',
            lambda: self._open_action_editor(model, index),
        )
        params_act.setEnabled(current_action in self._ACTIONS_WITH_PARAMS)
        menu.addSeparator()

        self._add_compile_action(menu, model, index)

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
        """Build element column context menu matching fwbuilder's layout."""
        slot = _COL_TO_SLOT[col]
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        elements = getattr(row_data, slot, [])

        # Determine the target element (clicked or first).
        target_id = target_name = target_type = None
        if elements:
            target_id, target_name, target_type = elements[0]
            if self._selected_element is not None:
                sel_rid, sel_slot, sel_tid = self._selected_element
                if sel_rid == row_data.rule_id and sel_slot == slot:
                    for eid, ename, etype in elements:
                        if eid == sel_tid:
                            target_id, target_name, target_type = eid, ename, etype
                            break

        has_element = target_id is not None

        # Edit.
        edit_act = menu.addAction(
            'Edit',
            lambda oid=target_id, otype=target_type: self._open_element_editor(
                str(oid), otype
            ),
        )
        edit_act.setEnabled(has_element)
        menu.addSeparator()

        # Copy.
        copy_act = menu.addAction(
            'Copy',
            lambda tid=target_id, n=target_name, t=target_type: self._copy_element(
                tid, n, t
            ),
        )
        copy_act.setEnabled(has_element)

        # Cut.
        cut_act = menu.addAction(
            'Cut',
            lambda tid=target_id, n=target_name, t=target_type: self._cut_element(
                model, index, slot, tid, n, t
            ),
        )
        cut_act.setEnabled(has_element)

        # Paste.
        paste_act = menu.addAction(
            'Paste',
            lambda: self._paste_element(model, index, slot),
        )
        valid_types = _VALID_TYPES_BY_SLOT.get(slot, frozenset())
        can_paste = (
            PolicyView._object_clipboard is not None
            and PolicyView._object_clipboard.get('type', '') in valid_types
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
            lambda oid=target_id, n=target_name, ot=target_type: self._show_where_used(
                str(oid), n, ot
            ),
        )
        where_act.setEnabled(has_element)

        # Reveal in Tree.
        reveal_act = menu.addAction(
            'Reveal in Tree',
            lambda oid=target_id: self._reveal_in_tree(str(oid)),
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
        self._add_compile_action(menu, model, index)

    def _open_element_editor(self, obj_id, obj_type):
        """Open the object editor for the given element."""
        main_win = self.window()
        if hasattr(main_win, '_open_object_editor'):
            main_win._open_object_editor(obj_id, obj_type)

    def _show_any_message(self, col):
        """Show the 'Any' object description in the editor pane."""
        main_win = self.window()
        if hasattr(main_win, 'show_any_editor'):
            main_win.show_any_editor(col)

    def _reveal_in_tree(self, obj_id):
        """Select and reveal the object in the object tree."""
        main_win = self.window()
        if hasattr(main_win, '_object_tree'):
            main_win._object_tree.select_object(obj_id)

    def _show_where_used(self, obj_id, name, obj_type):
        """Show where-used results for the given object."""
        main_win = self.window()
        if hasattr(main_win, 'show_where_used'):
            main_win.show_where_used(obj_id, name, obj_type)

    def _copy_element(self, target_id, name, obj_type):
        """Copy the element to the object clipboard."""
        PolicyView._object_clipboard = {
            'id': str(target_id),
            'name': name,
            'type': obj_type,
        }

    def _cut_element(self, model, index, slot, target_id, name, obj_type):
        """Copy the element to clipboard and remove it from the cell."""
        self._copy_element(target_id, name, obj_type)
        model.remove_element(index, slot, target_id)

    def _paste_element(self, model, index, slot):
        """Paste the object clipboard into the cell."""
        if PolicyView._object_clipboard is None:
            return
        obj_id = PolicyView._object_clipboard['id']
        model.add_element(index, slot, uuid.UUID(obj_id))

    def _build_comment_menu(self, menu, model, index):
        """Build Comment column context menu."""
        menu.addAction('Edit', lambda: self._open_comment_editor(model, index))
        menu.addSeparator()
        self._add_compile_action(menu, model, index)

    def _build_options_menu(self, menu, model, index):
        """Build Options column context menu."""
        menu.addAction(
            QIcon(':/Icons/Options/icon-tree'),
            'Rule Options',
            lambda: self._open_rule_options_dialog(model, index),
        )
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
        self._add_compile_action(menu, model, index)

    def _change_action_and_edit(self, model, index, action):
        """Change the rule action and open the action editor with a fresh index."""
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        rule_id = row_data.rule_id
        model.set_action(index, action)
        # set_action() triggers reload(), invalidating the old index.
        new_index = model.index_for_rule(rule_id)
        if new_index.isValid():
            self._open_action_editor(model, new_index)

    def _open_action_editor(self, model, index):
        """Open the Action parameters panel in the editor pane."""
        main_win = self.window()
        if hasattr(main_win, 'open_action_editor'):
            main_win.open_action_editor(model, index)

    def _open_comment_editor(self, model, index):
        """Open the Comment editor panel in the editor pane."""
        main_win = self.window()
        if hasattr(main_win, 'open_comment_editor'):
            main_win.open_comment_editor(model, index)

    def _open_direction_editor(self, model, index):
        """Open the (blank) Direction pane in the editor pane."""
        main_win = self.window()
        if hasattr(main_win, 'open_direction_editor'):
            main_win.open_direction_editor(model, index)

    def _open_rule_options_dialog(self, model, index):
        """Open the Rule Options panel in the editor pane."""
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        main_win = self.window()
        if hasattr(main_win, 'open_rule_options'):
            main_win.open_rule_options(model, index)

    def _add_disable_action(self, menu, model, index):
        """Add 'Disable Rule' or 'Enable Rule' action to the menu."""
        selected = self._selected_rule_indices()
        if not selected:
            selected = [index]
        multi = len(selected) > 1
        rule_label = 'Rules' if multi else 'Rule'
        any_enabled = any(
            not (rd := model.get_row_data(idx)) or not rd.disabled for idx in selected
        )
        any_disabled = any(
            (rd := model.get_row_data(idx)) is not None and rd.disabled
            for idx in selected
        )
        if any_disabled:
            menu.addAction(
                f'Enable {rule_label}',
                lambda sel=selected: self._set_disabled_on_selection(
                    model, sel, disabled=False
                ),
            )
        if any_enabled:
            menu.addAction(
                f'Disable {rule_label}',
                lambda sel=selected: self._set_disabled_on_selection(
                    model, sel, disabled=True
                ),
            )

    @staticmethod
    def _set_disabled_on_selection(model, indices, *, disabled):
        """Set the disabled state for all rules in *indices*."""
        for idx in indices:
            model.set_disabled(idx, disabled)

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
    # Public clipboard actions (called from main window edit menu)
    # ------------------------------------------------------------------

    def copy_selection(self):
        """Copy selected rules to the clipboard."""
        model = self.model()
        if model is None:
            return
        indices = self._selected_rule_indices()
        if indices:
            model.copy_rules(indices)

    def cut_selection(self):
        """Cut selected rules to the clipboard."""
        model = self.model()
        if model is None:
            return
        indices = self._selected_rule_indices()
        if indices:
            model.cut_rules(indices)

    def copy_object(self):
        """Copy element or rules — context-aware like fwbuilder.

        If a single element is selected in an element column, copy that
        element to the object clipboard.  Otherwise copy whole rules.
        """
        if self._selected_element is not None:
            _rule_id, _slot, target_id = self._selected_element
            idx = self._selected_index
            if idx.isValid() and idx.column() in _ELEMENT_COLS:
                elements = idx.data(ELEMENTS_ROLE) or []
                for eid, ename, etype in elements:
                    if eid == target_id:
                        self._copy_element(target_id, ename, etype)
                        return
        self.copy_selection()

    def cut_object(self):
        """Cut element or rules — context-aware like fwbuilder.

        If a single element is selected in an element column, cut that
        element.  Otherwise cut whole rules.
        """
        if self._selected_element is not None:
            _rule_id, slot, target_id = self._selected_element
            idx = self._selected_index
            model = self.model()
            if idx.isValid() and idx.column() in _ELEMENT_COLS and model is not None:
                elements = idx.data(ELEMENTS_ROLE) or []
                for eid, ename, etype in elements:
                    if eid == target_id:
                        self._cut_element(model, idx, slot, target_id, ename, etype)
                        return
        self.cut_selection()

    def delete_selection(self):
        """Delete element or rules — context-aware like fwbuilder.

        If a single element is selected in an element column, remove
        that element from the cell.  Otherwise delete whole rules.
        """
        if self._selected_element is not None:
            _rule_id, slot, target_id = self._selected_element
            idx = self._selected_index
            model = self.model()
            if idx.isValid() and idx.column() in _ELEMENT_COLS and model is not None:
                model.remove_element(idx, slot, target_id)
                self._clear_element_selection()
                return
        model = self.model()
        if model is None:
            return
        indices = self._selected_rule_indices()
        if indices:
            model.delete_rules(indices)

    def paste_below(self):
        """Paste rules from clipboard below the current rule."""
        model = self.model()
        if model is None:
            return
        idx = self.currentIndex()
        if idx.isValid() and not model.is_group(idx):
            self._paste_and_scroll(model, idx)

    def paste_object(self):
        """Paste clipboard content — object into cell or rules below.

        Mimics fwbuilder's ``RuleSetView::pasteObject()``: if the
        object clipboard holds a regular object and the current cell
        can accept it, paste it there; otherwise fall back to rule
        paste.
        """
        model = self.model()
        if model is None:
            return
        idx = self.currentIndex()
        if not idx.isValid() or model.is_group(idx):
            return

        # If the object clipboard has a compatible object for the
        # current cell's slot, paste the object into that cell.
        col = idx.column()
        if col in _ELEMENT_COLS:
            slot = _COL_TO_SLOT[col]
            valid_types = _VALID_TYPES_BY_SLOT.get(slot, frozenset())
            if (
                PolicyView._object_clipboard is not None
                and PolicyView._object_clipboard.get('type', '') in valid_types
            ):
                self._paste_element(model, index=idx, slot=slot)
                return

        # Fall back to rule paste.
        self._paste_and_scroll(model, idx)

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

    def _insert_and_scroll(self, model, index=None, **kwargs):
        """Insert a rule and scroll to it."""
        rule_id = model.insert_rule(index, **kwargs)
        if rule_id is not None:
            new_idx = model.index_for_rule(rule_id)
            if new_idx.isValid():
                self.scrollTo(new_idx)
                self.setCurrentIndex(new_idx)

    def _paste_and_scroll(self, model, index, *, before=False):
        """Paste rules from clipboard and scroll to the first pasted rule."""
        new_ids = model.paste_rules(index, before=before)
        if new_ids:
            first_idx = model.index_for_rule(new_ids[0])
            if first_idx.isValid():
                self.scrollTo(first_idx)
                self.setCurrentIndex(first_idx)

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
            if key == Qt.Key.Key_C:
                self.copy_selection()
                return
            if key == Qt.Key.Key_V:
                self.paste_below()
                return
            if key == Qt.Key.Key_X:
                self.cut_selection()
                return
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
                    self._insert_and_scroll(model, index=idx)
                else:
                    self._insert_and_scroll(model, at_bottom=True)
                return
            if key == Qt.Key.Key_X:
                idx = self.currentIndex()
                if idx.isValid() and not model.is_group(idx):
                    self._do_compile_rule(model, idx)
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
            if event.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
                event.setDropAction(Qt.DropAction.CopyAction)
            else:
                event.setDropAction(Qt.DropAction.MoveAction)
            event.accept()
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

        source_rule_id = payload.get('source_rule_id')
        source_slot = payload.get('source_slot')

        if source_rule_id and source_slot:
            # Drag from another cell (or same cell).
            row_data = model.get_row_data(index)
            if row_data is None:
                event.ignore()
                return
            # Same cell → no-op.
            if str(row_data.rule_id) == source_rule_id and source_slot == slot:
                event.ignore()
                return
            if event.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
                # Copy (Ctrl+drag).
                model.add_element(index, slot, uuid.UUID(obj_id))
            else:
                # Move.
                model.move_element(
                    uuid.UUID(source_rule_id),
                    source_slot,
                    index,
                    slot,
                    uuid.UUID(obj_id),
                )
        else:
            # Tree drop (existing behavior).
            model.add_element(index, slot, uuid.UUID(obj_id))

        event.acceptProposedAction()
