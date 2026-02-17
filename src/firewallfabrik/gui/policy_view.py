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

from PySide6.QtCore import (
    QEvent,
    QItemSelectionModel,
    QMimeData,
    QModelIndex,
    QRect,
    QSettings,
    QSize,
    Qt,
)
from PySide6.QtGui import QColor, QDrag, QIcon, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QToolButton,
    QToolTip,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.gui.policy_context_menu import (
    VALID_TYPES_BY_SLOT,
    add_color_submenu,
    add_new_group_action,
    add_to_adjacent_group_actions,
    build_action_menu,
    build_comment_menu,
    build_direction_menu,
    build_element_menu,
    build_group_header_menu,
    build_metric_menu,
    build_options_menu,
    build_row_menu,
)
from firewallfabrik.gui.policy_model import (
    ELEMENTS_ROLE,
    FWF_MIME_TYPE,
    NEGATED_ROLE,
)


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
            max_text_w = max(fm.horizontalAdvance(name) for _, name, *_ in elements)
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

        # Always highlight the position column for the current row (like
        # Excel row headers) so the user can orient themselves.
        view = self.parent()
        model = index.model()
        if (
            isinstance(view, PolicyView)
            and model is not None
            and index.column() == model.position_col
            and not (option.state & QStyle.StateFlag.State_Selected)
        ):
            cur = view.currentIndex()
            if (
                cur.isValid()
                and cur.row() == index.row()
                and cur.parent() == index.parent()
            ):
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
        if text is not None and text != '':
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
        for target_id, name, obj_type, *_ in elements:
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


def _model_col_to_slot(model, col):
    """Return the slot name for *col* using model config."""
    return model.col_to_slot.get(col)


def _model_element_cols(model):
    """Return the element column frozenset from the model."""
    return model.element_cols


def _model_selectable_cols(model):
    """Return the selectable column frozenset from the model."""
    return model.selectable_cols


class PolicyView(QTreeView):
    """Tree view with context menus, keyboard shortcuts, and drop support."""

    _object_clipboard = None  # {'id': str, 'name': str, 'type': str} or None

    def __init__(self, parent=None):
        super().__init__(parent)
        self._highlight_rule_id = None
        self._highlight_col = None
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
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

        # Double-click on group header -> rename.
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

    def viewportEvent(self, event):
        """Show per-element tooltips and an instructional tooltip for empty space."""
        if event.type() == QEvent.Type.ToolTip:
            if not QSettings().value('UI/ObjTooltips', True, type=bool):
                return super().viewportEvent(event)
            index = self.indexAt(event.pos())
            if not index.isValid():
                QToolTip.showText(
                    event.globalPos(),
                    '<html>'
                    'Policy, NAT and routing rules are shown here.'
                    '<ul>'
                    '<li><b>Rules use objects</b> &ndash; to use an object '
                    'like an IP address in a rule, first create it in the '
                    'object tree.</li>'
                    '<li><b>Drag and drop</b> objects from the tree to the '
                    'desired field (Source, Destination, etc.) in the rule.</li>'
                    '<li><b>To add a rule</b>, click the &ldquo;+&rdquo; '
                    'button at the top of the window.</li>'
                    '<li><b>To open the context menu</b> with operations such '
                    "as 'Add rule', 'Remove rule', etc., right-click.</li>"
                    '</ul></html>',
                    self,
                )
                return True
            # Per-element tooltip: show only the hovered element's tooltip.
            elements = index.data(ELEMENTS_ROLE)
            if elements and len(elements) > 1:
                tip = self._element_tooltip_at(index, event.pos(), elements)
                if tip:
                    QToolTip.showText(event.globalPos(), tip, self)
                    return True
        return super().viewportEvent(event)

    def _element_tooltip_at(self, index, pos, elements):
        """Return the tooltip for the element at *pos*, or None."""
        rect = self.visualRect(index)
        icon_sz = QSettings().value('UI/IconSizeInRules', 25, type=int)
        fm = self.fontMetrics()
        line_h = max(icon_sz, fm.height())
        v_pad = _CellBorderDelegate._V_PAD
        y_offset = pos.y() - rect.top() - v_pad
        if y_offset < 0:
            return None
        elem_idx = y_offset // line_h
        if 0 <= elem_idx < len(elements):
            *_, tip = elements[elem_idx]
            return tip or None
        return None

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
            for idx in self._selected_rule_indices():
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
        slot_to_col = model.slot_to_col

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
                        QItemSelectionModel.SelectionFlag.Select,
                    )
            self._saved_row_rule_ids = []

        # Restore per-element selection.
        saved_elem = getattr(self, '_saved_element', None)
        if saved_elem is not None:
            rule_id, slot, _target_id = saved_elem
            idx = model.index_for_rule(rule_id)
            if idx.isValid():
                col = slot_to_col.get(slot)
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
        col_to_slot = model.col_to_slot
        element_cols = _model_element_cols(model)
        slot = col_to_slot.get(col)
        if not slot:
            return
        elem = self._element_at_pos(index, vp_pos)
        if elem is not None:
            tid, _n, _t, *_ = elem
            rd = model.get_row_data(index)
            if rd is not None:
                self._select_element(index, tid, slot, rd.rule_id)
        elif col not in element_cols:
            rd = model.get_row_data(index)
            if rd is not None:
                self._select_element(index, f'__{slot}__', slot, rd.rule_id)

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
    # Current-index tracking (position column highlight)
    # ------------------------------------------------------------------

    def currentChanged(self, current, previous):
        super().currentChanged(current, previous)
        model = self.model()
        if model is None:
            return
        pos_col = model.position_col
        # Repaint the position column cell for the old and new row so the
        # "row header" highlight follows the cursor (like Excel).
        for idx in (previous, current):
            if idx.isValid():
                pos_idx = model.index(idx.row(), pos_col, idx.parent())
                self.update(pos_idx)

    # ------------------------------------------------------------------
    # Mouse events for per-element selection and drag
    # ------------------------------------------------------------------

    def mousePressEvent(self, event):
        self.clear_highlight()
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            index = self.indexAt(pos)
            model = self.model()
            selectable = _model_selectable_cols(model)
            element_cols = _model_element_cols(model)
            col_to_slot = model.col_to_slot if model is not None else {}
            if (
                index.isValid()
                and model is not None
                and not model.is_group(index)
                and index.column() in selectable
            ):
                col = index.column()
                elem = self._element_at_pos(index, pos)
                if elem is not None:
                    target_id, _name, _obj_type, *_ = elem
                    slot = col_to_slot.get(col)
                    row_data = model.get_row_data(index)
                    if row_data is not None and slot:
                        self._select_element(
                            index,
                            target_id,
                            slot,
                            row_data.rule_id,
                        )
                        # Only start drag for true element columns.
                        if col in element_cols:
                            self._drag_start_pos = pos
                    else:
                        self._clear_element_selection()
                elif col not in element_cols:
                    # Non-element columns (Action, Direction, Options)
                    # are always selectable even when the cell is empty.
                    slot = col_to_slot.get(col)
                    row_data = model.get_row_data(index)
                    if row_data is not None and slot:
                        self._select_element(
                            index,
                            f'__{slot}__',
                            slot,
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
        for eid, ename, etype, *_ in elements:
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

        element_cols = _model_element_cols(model)
        col_to_slot = model.col_to_slot
        action_col = model.action_col
        comment_col = model.comment_col
        direction_col = model.direction_col
        metric_col = model.metric_col
        options_col = model.options_col

        if col in element_cols:
            slot = col_to_slot.get(col)
            if not slot:
                return
            elements = getattr(row_data, slot, [])
            if elements:
                target = None
                if self._selected_element is not None:
                    sel_rid, sel_slot, sel_tid = self._selected_element
                    if sel_rid == row_data.rule_id and sel_slot == slot:
                        for eid, ename, etype, *_ in elements:
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
        elif col == action_col:
            self._open_action_editor(model, index)
        elif col == comment_col:
            self._open_comment_editor(model, index)
        elif col == direction_col:
            self._open_direction_editor(model, index)
        elif col == metric_col:
            self._open_metric_editor(model, index)
        elif col == options_col:
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
                build_group_header_menu(menu, self, model, index)
                menu.exec(global_pos)
                return

        col = index.column()
        element_cols = _model_element_cols(model)
        col_to_slot = model.col_to_slot
        selectable = _model_selectable_cols(model)
        action_col = model.action_col
        comment_col = model.comment_col
        direction_col = model.direction_col
        options_col = model.options_col

        # Element and comment columns get their own self-contained menus
        # without group/color actions.
        if col in element_cols:
            # Hit-test for per-element selection on right-click.
            elem = self._element_at_pos(index, vp_pos)
            if elem is not None:
                tid, _n, _t, *_ = elem
                rd = model.get_row_data(index)
                slot = col_to_slot.get(col)
                if rd is not None and slot:
                    self._select_element(index, tid, slot, rd.rule_id)
            build_element_menu(menu, self, model, index, col)
            menu.exec(global_pos)
            return

        if col == comment_col:
            build_comment_menu(menu, self, model, index)
            menu.exec(global_pos)
            return

        # Columns with self-contained menus (no group/color).
        # Select the element on right-click for visual feedback.
        if col in selectable and col not in element_cols:
            self._select_element_at(index, vp_pos, model)

        if col == action_col:
            build_action_menu(menu, self, model, index)
            menu.exec(global_pos)
            return

        if col == direction_col:
            build_direction_menu(menu, self, model, index)
            menu.exec(global_pos)
            return

        metric_col = model.metric_col
        if col == metric_col:
            build_metric_menu(menu, self, model, index)
            menu.exec(global_pos)
            return

        if col == options_col:
            build_options_menu(menu, self, model, index)
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
            add_new_group_action(menu, self, model, index)
            add_to_adjacent_group_actions(menu, self, model, index)

        add_color_submenu(menu, self, model, index)
        menu.addSeparator()

        build_row_menu(menu, self, model, index)

        menu.exec(global_pos)

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

    def _do_compile_rule(self, model, index):
        """Trigger single-rule compilation via the main window."""
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        main_win = self.window()
        if hasattr(main_win, 'compile_single_rule'):
            main_win.compile_single_rule(row_data.rule_id, model.rule_set_id)

    def _open_element_editor(self, obj_id, obj_type):
        """Open the object editor for the given element."""
        main_win = self.window()
        if hasattr(main_win, '_open_object_editor'):
            main_win._open_object_editor(obj_id, obj_type)

    def _show_any_message(self, col):
        """Show the 'Any' object description in the editor pane."""
        main_win = self.window()
        if hasattr(main_win, 'show_any_editor'):
            model = self.model()
            slot = model.col_to_slot.get(col, '') if model else ''
            main_win.show_any_editor(slot)

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

    def _open_metric_editor(self, model, index):
        """Open the Metric editor panel in the editor pane."""
        main_win = self.window()
        if hasattr(main_win, 'open_metric_editor'):
            main_win.open_metric_editor(model, index)

    def _open_rule_options_dialog(self, model, index):
        """Open the Rule Options panel in the editor pane."""
        row_data = model.get_row_data(index)
        if row_data is None:
            return
        main_win = self.window()
        if hasattr(main_win, 'open_rule_options'):
            main_win.open_rule_options(model, index)

    @staticmethod
    def _set_disabled_on_selection(model, indices, *, disabled):
        """Set the disabled state for all rules in *indices*."""
        for idx in indices:
            model.set_disabled(idx, disabled)

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
        """Copy element or rules -- context-aware like fwbuilder.

        If a single element is selected in an element column, copy that
        element to the object clipboard.  Otherwise copy whole rules.
        """
        if self._selected_element is not None:
            _rule_id, _slot, target_id = self._selected_element
            idx = self._selected_index
            model = self.model()
            element_cols = _model_element_cols(model)
            if idx.isValid() and idx.column() in element_cols:
                elements = idx.data(ELEMENTS_ROLE) or []
                for eid, ename, etype, *_ in elements:
                    if eid == target_id:
                        self._copy_element(target_id, ename, etype)
                        return
        self.copy_selection()

    def cut_object(self):
        """Cut element or rules -- context-aware like fwbuilder.

        If a single element is selected in an element column, cut that
        element.  Otherwise cut whole rules.
        """
        if self._selected_element is not None:
            _rule_id, slot, target_id = self._selected_element
            idx = self._selected_index
            model = self.model()
            element_cols = _model_element_cols(model)
            if idx.isValid() and idx.column() in element_cols and model is not None:
                elements = idx.data(ELEMENTS_ROLE) or []
                for eid, ename, etype, *_ in elements:
                    if eid == target_id:
                        self._cut_element(model, idx, slot, target_id, ename, etype)
                        return
        self.cut_selection()

    def delete_selection(self):
        """Delete element or rules -- context-aware like fwbuilder.

        If a single element is selected in an element column, remove
        that element from the cell.  If the current cell is in an
        element column but no element is individually selected, do
        nothing (don't accidentally delete the whole rule).  Only
        delete whole rules when the current cell is outside element
        columns (e.g. Position or Comment).
        """
        model = self.model()
        element_cols = _model_element_cols(model)
        if self._selected_element is not None:
            _rule_id, slot, target_id = self._selected_element
            idx = self._selected_index
            if idx.isValid() and idx.column() in element_cols and model is not None:
                model.remove_element(idx, slot, target_id)
                self._clear_element_selection()
                return
        # Guard: if the current cell is in an element column, don't
        # fall through to deleting the whole rule -- the user intended
        # to remove an element, not the row.
        cur = self.currentIndex()
        if cur.isValid() and cur.column() in element_cols:
            return
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
        """Paste clipboard content -- object into cell or rules below.

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
        element_cols = _model_element_cols(model)
        col_to_slot = model.col_to_slot
        if col in element_cols:
            slot = col_to_slot.get(col)
            if slot:
                valid_types = VALID_TYPES_BY_SLOT.get(slot, frozenset())
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
                self.copy_object()
                return
            if key == Qt.Key.Key_V:
                self.paste_object()
                return
            if key == Qt.Key.Key_X:
                self.cut_object()
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
        element_cols = _model_element_cols(model)
        if (
            index.isValid()
            and index.column() in element_cols
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
        element_cols = _model_element_cols(model)
        col_to_slot = model.col_to_slot if model is not None else {}
        if (
            not index.isValid()
            or index.column() not in element_cols
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

        # Normalise payload: old format (single dict) → list.
        if isinstance(payload, dict):
            items = [payload]
        elif isinstance(payload, list):
            items = payload
        else:
            event.ignore()
            return

        if not items:
            event.ignore()
            return

        slot = col_to_slot.get(index.column())
        if not slot:
            event.ignore()
            return
        valid_types = VALID_TYPES_BY_SLOT.get(slot, frozenset())

        # Cell-to-cell drag (always single item).
        first = items[0]
        source_rule_id = first.get('source_rule_id')
        source_slot = first.get('source_slot')

        if source_rule_id and source_slot:
            obj_id = first.get('id')
            obj_type = first.get('type', '')
            if not obj_id or obj_type not in valid_types:
                event.ignore()
                return
            row_data = model.get_row_data(index)
            if row_data is None:
                event.ignore()
                return
            if str(row_data.rule_id) == source_rule_id and source_slot == slot:
                event.ignore()
                return
            if event.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
                model.add_element(index, slot, uuid.UUID(obj_id))
            else:
                model.move_element(
                    uuid.UUID(source_rule_id),
                    source_slot,
                    index,
                    slot,
                    uuid.UUID(obj_id),
                )
        else:
            # Tree drop — add all valid items.
            for entry in items:
                obj_id = entry.get('id')
                obj_type = entry.get('type', '')
                if obj_id and obj_type in valid_types:
                    model.add_element(index, slot, uuid.UUID(obj_id))

        event.acceptProposedAction()


class RuleSetPanel(QWidget):
    """Container with an 'Insert Rule' button and a :class:`PolicyView`."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(2, 2, 2, 2)
        add_btn = QToolButton()
        add_btn.setIcon(QIcon(':/Icons/Add'))
        add_btn.setIconSize(QSize(25, 25))
        add_btn.setToolTip('Insert rule')
        add_btn.clicked.connect(self._insert_rule)
        toolbar.addWidget(add_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.policy_view = PolicyView()
        layout.addWidget(self.policy_view)

    def _insert_rule(self):
        model = self.policy_view.model()
        if model is None:
            return
        idx = self.policy_view.currentIndex()
        if idx.isValid() and not model.is_group(idx):
            self.policy_view._insert_and_scroll(model, index=idx, before=True)
        else:
            self.policy_view._insert_and_scroll(model, at_bottom=True)
