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

"""Database-backed table model for policy rules with full editing support."""

import dataclasses
import uuid

import sqlalchemy
from PySide6.QtCore import QAbstractTableModel, QSettings, Qt
from PySide6.QtGui import QColor, QIcon

from firewallfabrik.core.objects import (
    Address,
    Direction,
    Group,
    Host,
    Interface,
    Interval,
    PolicyAction,
    PolicyRule,
    Service,
    rule_elements,
)

FWF_MIME_TYPE = 'application/x-fwf-object'

HEADERS = [
    '#',
    'Source',
    'Destination',
    'Service',
    'Interface',
    'Direction',
    'Action',
    'Comment',
]

_COL_ACTION = 6
_COL_COMMENT = 7
_COL_DIRECTION = 5
_COL_DST = 2
_COL_ITF = 4
_COL_POSITION = 0
_COL_SRC = 1
_COL_SRV = 3

_COL_TO_SLOT = {
    _COL_DST: 'dst',
    _COL_ITF: 'itf',
    _COL_SRC: 'src',
    _COL_SRV: 'srv',
}

_ELEMENT_COLS = frozenset(_COL_TO_SLOT.keys())

_ACTION_COLORS = {
    'Accept': QColor(200, 255, 200),
    'Deny': QColor(255, 200, 200),
    'Reject': QColor(255, 230, 200),
}

_DIRECTION_ICONS = {
    'Both': ':/Icons/Both/icon-tree',
    'Inbound': ':/Icons/Inbound/icon-tree',
    'Outbound': ':/Icons/Outbound/icon-tree',
}

# Classes used to resolve target names from the database.
_NAME_CLASSES = (Address, Group, Host, Interface, Interval, Service)


@dataclasses.dataclass
class _RowData:
    """Structured data for one policy rule row."""

    action: str
    action_int: int
    comment: str
    direction: str
    direction_int: int
    dst: list  # list[tuple[uuid.UUID, str]]
    itf: list
    position: int
    rule_id: uuid.UUID
    src: list
    srv: list


class PolicyTableModel(QAbstractTableModel):
    """Database-backed table model for policy rules with mutation support."""

    def __init__(self, db_manager, rule_set_id, parent=None):
        super().__init__(parent)
        self._db_manager = db_manager
        self._rule_set_id = rule_set_id
        self._rows: list[_RowData] = []
        self.reload()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def reload(self):
        """Re-query the database and rebuild all rows."""
        self.beginResetModel()
        self._rows.clear()

        with self._db_manager.session() as session:
            rules = session.scalars(
                sqlalchemy.select(PolicyRule)
                .where(PolicyRule.rule_set_id == self._rule_set_id)
                .order_by(PolicyRule.position),
            ).all()

            if not rules:
                self.endResetModel()
                return

            rule_ids = [r.id for r in rules]
            name_map = self._build_name_map(session)

            # Gather all rule_elements for these rules in one query.
            slot_map: dict[uuid.UUID, dict[str, list[tuple[uuid.UUID, str]]]] = {}
            re_rows = session.execute(
                sqlalchemy.select(
                    rule_elements.c.rule_id,
                    rule_elements.c.slot,
                    rule_elements.c.target_id,
                ).where(rule_elements.c.rule_id.in_(rule_ids)),
            ).all()
            for rule_id, slot, target_id in re_rows:
                pair = (target_id, name_map.get(target_id, str(target_id)))
                slot_map.setdefault(rule_id, {}).setdefault(slot, []).append(pair)

            for rule in rules:
                slots = slot_map.get(rule.id, {})
                try:
                    direction = Direction(rule.policy_direction)
                    dir_name = direction.name
                except (TypeError, ValueError):
                    direction = Direction.Undefined
                    dir_name = ''
                try:
                    action = PolicyAction(rule.policy_action)
                    act_name = action.name
                except (TypeError, ValueError):
                    action = PolicyAction.Unknown
                    act_name = ''

                self._rows.append(
                    _RowData(
                        action=act_name,
                        action_int=action.value,
                        comment=rule.comment or '',
                        direction=dir_name,
                        direction_int=direction.value,
                        dst=slots.get('dst', []),
                        itf=slots.get('itf', []),
                        position=rule.position,
                        rule_id=rule.id,
                        src=slots.get('src', []),
                        srv=slots.get('srv', []),
                    )
                )

        self.endResetModel()

    @staticmethod
    def _build_name_map(session):
        """Build a {uuid: name} lookup from all name-bearing tables."""
        name_map = {}
        for cls in _NAME_CLASSES:
            for obj_id, name in session.execute(
                sqlalchemy.select(cls.id, cls.name),
            ):
                name_map[obj_id] = name
        return name_map

    # ------------------------------------------------------------------
    # Qt model interface
    # ------------------------------------------------------------------

    def rowCount(self, parent=None):
        return len(self._rows)

    def columnCount(self, parent=None):
        return len(HEADERS)

    def flags(self, index):
        base = super().flags(index)
        if not index.isValid():
            return base
        col = index.column()
        if col == _COL_COMMENT:
            return base | Qt.ItemFlag.ItemIsEditable
        if col in _ELEMENT_COLS:
            return base | Qt.ItemFlag.ItemIsDropEnabled
        return base

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row_data = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display_value(row_data, col)

        if role == Qt.ItemDataRole.ToolTipRole:
            if QSettings().value('UI/ObjTooltips', True, type=bool):
                return self._display_value(row_data, col)
            return None

        if role == Qt.ItemDataRole.BackgroundRole:
            return _ACTION_COLORS.get(row_data.action)

        if role == Qt.ItemDataRole.DecorationRole:
            if col == _COL_ACTION:
                icon_path = f':/Icons/{row_data.action}/icon-tree'
                icon = QIcon(icon_path)
                if not icon.isNull():
                    return icon
            elif col == _COL_DIRECTION:
                icon_path = _DIRECTION_ICONS.get(row_data.direction)
                if icon_path:
                    return QIcon(icon_path)

        return None

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or role != Qt.ItemDataRole.EditRole:
            return False
        if index.column() != _COL_COMMENT:
            return False

        row_data = self._rows[index.row()]
        new_comment = str(value).strip()
        if new_comment == row_data.comment:
            return False

        with self._db_manager.session(
            f'Edit rule {row_data.position} comment',
        ) as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                rule.comment = new_comment

        row_data.comment = new_comment
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.DisplayRole])
        return True

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
        ):
            return HEADERS[section]
        return None

    def mimeTypes(self):
        return [FWF_MIME_TYPE]

    def canDropMimeData(self, data, action, row, column, parent):
        if not data.hasFormat(FWF_MIME_TYPE):
            return False
        col = parent.column() if parent.isValid() else column
        return col in _ELEMENT_COLS

    def dropMimeData(self, data, action, row, column, parent):
        # Handled by the view's dropEvent instead.
        return False

    def supportedDropActions(self):
        return Qt.DropAction.CopyAction

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _display_value(row_data, col):
        if col == _COL_POSITION:
            return row_data.position
        if col == _COL_SRC:
            return _format_elements(row_data.src)
        if col == _COL_DST:
            return _format_elements(row_data.dst)
        if col == _COL_SRV:
            return _format_elements(row_data.srv)
        if col == _COL_ITF:
            return _format_elements(row_data.itf)
        if col == _COL_DIRECTION:
            return row_data.direction
        if col == _COL_ACTION:
            return row_data.action
        if col == _COL_COMMENT:
            return row_data.comment
        return ''

    # ------------------------------------------------------------------
    # Mutation methods
    # ------------------------------------------------------------------

    def insert_rule(self, position=None, *, at_top=False, at_bottom=False):
        """Insert a new rule at the given position (or top/bottom)."""
        if at_top:
            position = 0
        elif at_bottom or position is None:
            position = len(self._rows)

        with self._db_manager.session(f'New rule {position}') as session:
            # Shift existing rules at or after the insertion point.
            session.execute(
                sqlalchemy.update(PolicyRule)
                .where(
                    PolicyRule.rule_set_id == self._rule_set_id,
                    PolicyRule.position >= position,
                )
                .values(position=PolicyRule.position + 1),
            )
            new_rule = PolicyRule(
                id=uuid.uuid4(),
                rule_set_id=self._rule_set_id,
                position=position,
                policy_action=PolicyAction.Deny.value,
                policy_direction=Direction.Both.value,
            )
            session.add(new_rule)

        self.reload()

    def delete_rules(self, row_indices):
        """Delete rules at the given row indices."""
        if not row_indices:
            return
        rule_ids = [self._rows[r].rule_id for r in sorted(row_indices)]

        with self._db_manager.session('Delete rule(s)') as session:
            # Remove rule_elements first (FK constraint).
            session.execute(
                sqlalchemy.delete(rule_elements).where(
                    rule_elements.c.rule_id.in_(rule_ids),
                ),
            )
            session.execute(
                sqlalchemy.delete(PolicyRule).where(PolicyRule.id.in_(rule_ids)),
            )
            # Renumber remaining rules.
            remaining = session.scalars(
                sqlalchemy.select(PolicyRule)
                .where(PolicyRule.rule_set_id == self._rule_set_id)
                .order_by(PolicyRule.position),
            ).all()
            for i, rule in enumerate(remaining):
                rule.position = i

        self.reload()

    def move_rule_up(self, row):
        """Swap the rule at *row* with the one above it."""
        if row <= 0 or row >= len(self._rows):
            return
        self._swap_positions(row, row - 1)

    def move_rule_down(self, row):
        """Swap the rule at *row* with the one below it."""
        if row < 0 or row >= len(self._rows) - 1:
            return
        self._swap_positions(row, row + 1)

    def _swap_positions(self, row_a, row_b):
        a = self._rows[row_a]
        b = self._rows[row_b]
        with self._db_manager.session('Move rule') as session:
            rule_a = session.get(PolicyRule, a.rule_id)
            rule_b = session.get(PolicyRule, b.rule_id)
            if rule_a is not None and rule_b is not None:
                rule_a.position, rule_b.position = (
                    rule_b.position,
                    rule_a.position,
                )
        self.reload()

    def set_action(self, row, action):
        """Set the policy action for the rule at *row*.

        *action* is a :class:`PolicyAction` member.
        """
        row_data = self._rows[row]
        with self._db_manager.session(
            f'Edit rule {row_data.position} action',
        ) as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                rule.policy_action = action.value
        self.reload()

    def set_direction(self, row, direction):
        """Set the policy direction for the rule at *row*.

        *direction* is a :class:`Direction` member.
        """
        row_data = self._rows[row]
        with self._db_manager.session(
            f'Edit rule {row_data.position} direction',
        ) as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                rule.policy_direction = direction.value
        self.reload()

    def add_element(self, row, slot, target_id):
        """Add *target_id* to element *slot* of the rule at *row*."""
        row_data = self._rows[row]
        with self._db_manager.session(
            f'Edit rule {row_data.position} {slot}',
        ) as session:
            # Check for duplicate.
            existing = session.execute(
                sqlalchemy.select(rule_elements.c.target_id).where(
                    rule_elements.c.rule_id == row_data.rule_id,
                    rule_elements.c.slot == slot,
                    rule_elements.c.target_id == target_id,
                ),
            ).first()
            if existing is not None:
                return
            # Determine next position in this slot.
            max_pos = session.scalar(
                sqlalchemy.select(
                    sqlalchemy.func.coalesce(
                        sqlalchemy.func.max(rule_elements.c.position), -1
                    ),
                ).where(
                    rule_elements.c.rule_id == row_data.rule_id,
                    rule_elements.c.slot == slot,
                ),
            )
            session.execute(
                rule_elements.insert().values(
                    rule_id=row_data.rule_id,
                    slot=slot,
                    target_id=target_id,
                    position=(max_pos or 0) + 1,
                ),
            )
        self.reload()

    def remove_element(self, row, slot, target_id):
        """Remove *target_id* from element *slot* of the rule at *row*."""
        row_data = self._rows[row]
        with self._db_manager.session(
            f'Edit rule {row_data.position} {slot}',
        ) as session:
            session.execute(
                sqlalchemy.delete(rule_elements).where(
                    rule_elements.c.rule_id == row_data.rule_id,
                    rule_elements.c.slot == slot,
                    rule_elements.c.target_id == target_id,
                ),
            )
        self.reload()

    def get_row_data(self, row):
        """Return the :class:`_RowData` for *row*."""
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None


def _format_elements(pairs):
    """Format a list of (uuid, name) pairs for display."""
    if not pairs:
        return 'Any'
    return ', '.join(name for _, name in pairs)
