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

"""Database-backed tree model for policy rules with group support."""

import dataclasses
import enum
import uuid

import sqlalchemy
from PySide6.QtCore import QAbstractItemModel, QModelIndex, QSettings, Qt
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
from firewallfabrik.gui.label_settings import (
    LABEL_KEYS,
    get_label_color,
    get_label_text,
)

ELEMENTS_ROLE = Qt.ItemDataRole.UserRole + 1
NEGATED_ROLE = Qt.ItemDataRole.UserRole + 2
FWF_MIME_TYPE = 'application/x-fwf-object'
_INVALID_INDEX = QModelIndex()

HEADERS = [
    '#',
    'Source',
    'Destination',
    'Service',
    'Interface',
    'Direction',
    'Action',
    'Time',
    'Options',
    'Comment',
]

_COL_ACTION = 6
_COL_COMMENT = 9
_COL_DIRECTION = 5
_COL_DST = 2
_COL_ITF = 4
_COL_OPTIONS = 8
_COL_POSITION = 0
_COL_SRC = 1
_COL_SRV = 3
_COL_TIME = 7

_COL_TO_SLOT = {
    _COL_DST: 'dst',
    _COL_ITF: 'itf',
    _COL_SRC: 'src',
    _COL_SRV: 'srv',
    _COL_TIME: 'when',
}

_ELEMENT_COLS = frozenset(_COL_TO_SLOT.keys())

_DIRECTION_NAMES = frozenset({'Both', 'Inbound', 'Outbound'})

_GROUP_BG = QColor('lightgray')

# Classes used to resolve target names from the database.
_NAME_CLASSES = (Address, Group, Host, Interface, Interval, Service)


class _NodeType(enum.IntEnum):
    Group = 0
    Root = 1
    Rule = 2


@dataclasses.dataclass
class _RowData:
    """Structured data for one policy rule row."""

    action: str
    action_int: int
    color_hex: str
    comment: str
    direction: str
    direction_int: int
    dst: list  # list[tuple[uuid.UUID, str, str]]  (id, name, type)
    group: str
    itf: list
    label: str
    negations: dict  # slot → bool, e.g. {'src': True, 'dst': False}
    options_display: list  # list[tuple[None, str, str]]  (None, label, icon-type)
    position: int
    rule_id: uuid.UUID
    src: list
    srv: list
    when: list  # list[tuple[uuid.UUID, str, str]]  (id, name, type)


class _TreeNode:
    """Lightweight tree node used by the model."""

    __slots__ = ('children', 'name', 'node_type', 'parent', 'row_data')

    def __init__(self, node_type, *, name='', parent=None, row_data=None):
        self.children: list[_TreeNode] = []
        self.name = name
        self.node_type = node_type
        self.parent = parent
        self.row_data = row_data

    def row_index(self):
        """Return this node's index among its parent's children."""
        if self.parent is not None:
            return self.parent.children.index(self)
        return 0


class PolicyTreeModel(QAbstractItemModel):
    """Database-backed tree model for policy rules with group support."""

    def __init__(self, db_manager, rule_set_id, *, object_name='', parent=None):
        super().__init__(parent)
        self._db_manager = db_manager
        self._object_name = object_name
        self._rule_set_id = rule_set_id
        self._root = _TreeNode(_NodeType.Root)
        self.reload()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def reload(self):
        """Re-query the database and rebuild the tree."""
        self.beginResetModel()
        self._root = _TreeNode(_NodeType.Root)

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
                name, obj_type = name_map.get(target_id, (str(target_id), ''))
                triple = (target_id, name, obj_type)
                slot_map.setdefault(rule_id, {}).setdefault(slot, []).append(triple)

            # Build tree: group nodes created on first occurrence.
            group_nodes: dict[str, _TreeNode] = {}

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

                opts = rule.options or {}
                group_name = opts.get('group', '')
                color_hex = opts.get('color', '')
                if not color_hex and rule.label and rule.label in LABEL_KEYS:
                    color_hex = get_label_color(rule.label)

                row_data = _RowData(
                    action=act_name,
                    action_int=action.value,
                    color_hex=color_hex,
                    comment=rule.comment or '',
                    direction=dir_name,
                    direction_int=direction.value,
                    dst=slots.get('dst', []),
                    group=group_name,
                    itf=slots.get('itf', []),
                    label=rule.label or '',
                    negations=rule.negations or {},
                    options_display=_build_options_display(opts),
                    position=rule.position,
                    rule_id=rule.id,
                    src=slots.get('src', []),
                    srv=slots.get('srv', []),
                    when=slots.get('when', []),
                )

                rule_node = _TreeNode(
                    _NodeType.Rule,
                    row_data=row_data,
                )

                if group_name:
                    if group_name not in group_nodes:
                        gnode = _TreeNode(
                            _NodeType.Group,
                            name=group_name,
                            parent=self._root,
                        )
                        self._root.children.append(gnode)
                        group_nodes[group_name] = gnode
                    parent_node = group_nodes[group_name]
                else:
                    parent_node = self._root

                rule_node.parent = parent_node
                parent_node.children.append(rule_node)

        self.endResetModel()

    def _desc(self, text):
        """Prefix *text* with the object name for undo descriptions."""
        if self._object_name:
            return f'{self._object_name}: {text}'
        return text

    @staticmethod
    def _build_name_map(session):
        """Build a {uuid: (name, type)} lookup from all name-bearing tables."""
        name_map = {}
        for cls in _NAME_CLASSES:
            if hasattr(cls, 'type'):
                for obj_id, name, obj_type in session.execute(
                    sqlalchemy.select(cls.id, cls.name, cls.type),
                ):
                    name_map[obj_id] = (name, obj_type)
            else:
                # Interface, Interval — fixed type name.
                type_name = cls.__name__
                for obj_id, name in session.execute(
                    sqlalchemy.select(cls.id, cls.name),
                ):
                    name_map[obj_id] = (name, type_name)
        return name_map

    # ------------------------------------------------------------------
    # Qt model interface (QAbstractItemModel overrides)
    # ------------------------------------------------------------------

    def index(self, row, column, parent=_INVALID_INDEX):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        parent_node = self._node_from_index(parent)
        if row < len(parent_node.children):
            child = parent_node.children[row]
            return self.createIndex(row, column, child)
        return QModelIndex()

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        node = index.internalPointer()
        parent_node = node.parent
        if parent_node is None or parent_node is self._root:
            return QModelIndex()
        return self.createIndex(parent_node.row_index(), 0, parent_node)

    def rowCount(self, parent=_INVALID_INDEX):
        node = self._node_from_index(parent)
        return len(node.children)

    def columnCount(self, parent=_INVALID_INDEX):
        return len(HEADERS)

    def hasChildren(self, parent=_INVALID_INDEX):
        node = self._node_from_index(parent)
        return node.node_type != _NodeType.Rule

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        node = index.internalPointer()
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if node.node_type == _NodeType.Group:
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
        node = index.internalPointer()
        if node.node_type == _NodeType.Group:
            return self._group_data(node, index.column(), role)
        return self._rule_data(node.row_data, index.column(), role)

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or role != Qt.ItemDataRole.EditRole:
            return False
        node = index.internalPointer()
        if node.node_type != _NodeType.Rule or index.column() != _COL_COMMENT:
            return False

        row_data = node.row_data
        new_comment = str(value).strip()
        if new_comment == row_data.comment:
            return False

        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} comment'),
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
    # Node helpers
    # ------------------------------------------------------------------

    def _node_from_index(self, index):
        """Return the _TreeNode for *index*, or the root node."""
        if index.isValid():
            return index.internalPointer()
        return self._root

    def is_group(self, index):
        """Return True if *index* points to a group header row."""
        if not index.isValid():
            return False
        node = index.internalPointer()
        return node.node_type == _NodeType.Group

    def group_name(self, index):
        """Return the group name for a group index, or '' otherwise."""
        if not index.isValid():
            return ''
        node = index.internalPointer()
        if node.node_type == _NodeType.Group:
            return node.name
        return ''

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _group_data(self, node, col, role):
        """Return data for a group header row."""
        if role == Qt.ItemDataRole.DisplayRole and col == _COL_POSITION:
            if node.children:
                first = node.children[0].row_data.position
                last = node.children[-1].row_data.position
                return f'{node.name} ({first} - {last})'
            return node.name
        if role == Qt.ItemDataRole.BackgroundRole:
            return _GROUP_BG
        if role == Qt.ItemDataRole.ToolTipRole and col == _COL_POSITION:
            return f'Rule group: {node.name}'
        return None

    def _rule_data(self, row_data, col, role):
        """Return data for a rule row."""
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display_value(row_data, col)
        if role == Qt.ItemDataRole.ToolTipRole:
            if QSettings().value('UI/ObjTooltips', True, type=bool):
                return self._display_value(row_data, col)
            return None
        if role == Qt.ItemDataRole.BackgroundRole:
            if row_data.color_hex:
                return QColor(row_data.color_hex)
            return None
        if role == Qt.ItemDataRole.ForegroundRole:
            if row_data.color_hex:
                return _contrast_color(QColor(row_data.color_hex))
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col == _COL_POSITION:
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        if role == Qt.ItemDataRole.DecorationRole:
            suffix = _icon_suffix()
            if col == _COL_ACTION and row_data.action:
                icon = QIcon(f':/Icons/{row_data.action}/{suffix}')
                if not icon.isNull():
                    return icon
            elif col == _COL_DIRECTION and row_data.direction in _DIRECTION_NAMES:
                return QIcon(f':/Icons/{row_data.direction}/{suffix}')
        if role == ELEMENTS_ROLE:
            if col in _ELEMENT_COLS:
                slot = _COL_TO_SLOT[col]
                return getattr(row_data, slot)
            if col == _COL_OPTIONS:
                return row_data.options_display or None
        if role == NEGATED_ROLE:
            if col in _ELEMENT_COLS:
                slot = _COL_TO_SLOT[col]
                return bool(row_data.negations.get(slot))
            return False
        return None

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
        if col == _COL_TIME:
            return _format_elements(row_data.when)
        if col == _COL_OPTIONS:
            return (
                _format_elements(row_data.options_display)
                if row_data.options_display
                else ''
            )
        if col == _COL_COMMENT:
            return row_data.comment
        return ''

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get_row_data(self, index):
        """Return the :class:`_RowData` for *index*, or None."""
        if not index.isValid():
            return None
        node = index.internalPointer()
        if node.node_type == _NodeType.Rule:
            return node.row_data
        return None

    def index_for_rule(self, rule_id):
        """Return a :class:`QModelIndex` for the rule with *rule_id*, or invalid."""
        for i, child in enumerate(self._root.children):
            if child.node_type == _NodeType.Rule and child.row_data.rule_id == rule_id:
                return self.createIndex(i, 0, child)
            if child.node_type == _NodeType.Group:
                for j, grandchild in enumerate(child.children):
                    if grandchild.row_data.rule_id == rule_id:
                        return self.createIndex(j, 0, grandchild)
        return QModelIndex()

    def flat_rule_count(self):
        """Return the total number of rule nodes in the tree."""
        count = 0
        for child in self._root.children:
            if child.node_type == _NodeType.Group:
                count += len(child.children)
            else:
                count += 1
        return count

    # ------------------------------------------------------------------
    # Mutation methods
    # ------------------------------------------------------------------

    def insert_rule(self, index=None, *, at_top=False, at_bottom=False):
        """Insert a new rule.

        If *index* points inside a group, the new rule inherits that group.
        """
        # Determine insertion position and group.
        group_name = ''
        if at_top:
            position = 0
        elif at_bottom or index is None:
            position = self.flat_rule_count()
        else:
            node = self._node_from_index(index)
            if node.node_type == _NodeType.Group:
                # Insert at end of group.
                if node.children:
                    position = node.children[-1].row_data.position + 1
                else:
                    position = 0
                group_name = node.name
            elif node.node_type == _NodeType.Rule:
                position = node.row_data.position + 1
                group_name = node.row_data.group
            else:
                position = self.flat_rule_count()

        with self._db_manager.session(self._desc(f'New rule {position}')) as session:
            # Shift existing rules at or after the insertion point.
            session.execute(
                sqlalchemy.update(PolicyRule)
                .where(
                    PolicyRule.rule_set_id == self._rule_set_id,
                    PolicyRule.position >= position,
                )
                .values(position=PolicyRule.position + 1),
            )
            opts = {'group': group_name} if group_name else None
            new_rule = PolicyRule(
                id=uuid.uuid4(),
                rule_set_id=self._rule_set_id,
                position=position,
                policy_action=PolicyAction.Deny.value,
                policy_direction=Direction.Both.value,
                options=opts,
            )
            session.add(new_rule)

        self.reload()

    def delete_rules(self, indices):
        """Delete rules at the given QModelIndex list."""
        if not indices:
            return
        rule_ids = []
        for idx in indices:
            node = self._node_from_index(idx)
            if node.node_type == _NodeType.Rule:
                rule_ids.append(node.row_data.rule_id)
            elif node.node_type == _NodeType.Group:
                for child in node.children:
                    rule_ids.append(child.row_data.rule_id)
        if not rule_ids:
            return

        with self._db_manager.session(self._desc('Delete rule(s)')) as session:
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

    def move_rule_up(self, index):
        """Move the rule at *index* up one position.

        Group boundary behavior:
        - First in group + up → leaves group (placed before group)
        - Top-level above group + up → joins group as last member

        Returns the :pyattr:`rule_id` of the moved rule, or *None*.
        """
        if not index.isValid():
            return None
        node = index.internalPointer()
        if node.node_type != _NodeType.Rule:
            return None

        pos = node.row_data.position
        rule_id = node.row_data.rule_id
        parent_node = node.parent
        child_idx = parent_node.children.index(node)

        if parent_node is self._root:
            if child_idx == 0:
                return None
            prev = parent_node.children[child_idx - 1]
            if prev.node_type == _NodeType.Group and prev.children:
                self._do_move(
                    rule_id,
                    new_group=prev.name,
                    description=f'Move rule {pos} into group',
                )
            else:
                prev_data = prev.row_data if prev.node_type == _NodeType.Rule else None
                if prev_data:
                    self._do_move(
                        rule_id,
                        swap_with=prev_data.rule_id,
                        description=f'Move rule {pos} > rule {prev_data.position}',
                    )
        else:
            if child_idx == 0:
                first_pos = parent_node.children[0].row_data.position
                self._do_move(
                    rule_id,
                    new_group='',
                    target_pos=first_pos,
                    description=f'Move rule {pos} out of group',
                )
            else:
                prev = parent_node.children[child_idx - 1]
                self._do_move(
                    rule_id,
                    swap_with=prev.row_data.rule_id,
                    description=f'Move rule {pos} > rule {prev.row_data.position}',
                )

        self.reload()
        return rule_id

    def move_rule_down(self, index):
        """Move the rule at *index* down one position.

        Group boundary behavior:
        - Last in group + down → leaves group (placed after group)
        - Top-level below group + down → joins group as first member

        Returns the :pyattr:`rule_id` of the moved rule, or *None*.
        """
        if not index.isValid():
            return None
        node = index.internalPointer()
        if node.node_type != _NodeType.Rule:
            return None

        pos = node.row_data.position
        rule_id = node.row_data.rule_id
        parent_node = node.parent
        child_idx = parent_node.children.index(node)

        if parent_node is self._root:
            if child_idx >= len(parent_node.children) - 1:
                return None
            nxt = parent_node.children[child_idx + 1]
            if nxt.node_type == _NodeType.Group and nxt.children:
                self._do_move(
                    rule_id,
                    new_group=nxt.name,
                    description=f'Move rule {pos} into group',
                )
            else:
                nxt_data = nxt.row_data if nxt.node_type == _NodeType.Rule else None
                if nxt_data:
                    self._do_move(
                        rule_id,
                        swap_with=nxt_data.rule_id,
                        description=f'Move rule {pos} > rule {nxt_data.position}',
                    )
        else:
            if child_idx >= len(parent_node.children) - 1:
                last_pos = parent_node.children[-1].row_data.position
                self._do_move(
                    rule_id,
                    new_group='',
                    target_pos=last_pos,
                    description=f'Move rule {pos} out of group',
                )
            else:
                nxt = parent_node.children[child_idx + 1]
                self._do_move(
                    rule_id,
                    swap_with=nxt.row_data.rule_id,
                    description=f'Move rule {pos} > rule {nxt.row_data.position}',
                )

        self.reload()
        return rule_id

    def set_action(self, index, action):
        """Set the policy action for the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} action'),
        ) as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                rule.policy_action = action.value
        self.reload()

    def set_direction(self, index, direction):
        """Set the policy direction for the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} direction'),
        ) as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                rule.policy_direction = direction.value
        self.reload()

    def set_label(self, index, label_key):
        """Set the color label for the rule at *index*.

        *label_key* should be one of ``'color1'`` .. ``'color7'``, or
        ``''`` to remove the label.
        """
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        if label_key:
            desc = (
                f'Change rule {row_data.position} color to {get_label_text(label_key)}'
            )
        else:
            desc = f'Remove rule {row_data.position} color'
        with self._db_manager.session(self._desc(desc)) as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                rule.label = label_key
                opts = dict(rule.options or {})
                if label_key:
                    opts['color'] = get_label_color(label_key)
                else:
                    opts.pop('color', None)
                rule.options = opts
        self.reload()

    def add_element(self, index, slot, target_id):
        """Add *target_id* to element *slot* of the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} {slot}'),
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

    def remove_element(self, index, slot, target_id):
        """Remove *target_id* from element *slot* of the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} {slot}'),
        ) as session:
            session.execute(
                sqlalchemy.delete(rule_elements).where(
                    rule_elements.c.rule_id == row_data.rule_id,
                    rule_elements.c.slot == slot,
                    rule_elements.c.target_id == target_id,
                ),
            )
        self.reload()

    # ------------------------------------------------------------------
    # Group management methods
    # ------------------------------------------------------------------

    def create_group(self, name, indices):
        """Group the rules at *indices* under a new group named *name*."""
        if not name or not indices:
            return
        unique_name = self._find_unique_group_name(name)
        rule_ids = []
        for idx in indices:
            rd = self.get_row_data(idx)
            if rd is not None:
                rule_ids.append(rd.rule_id)
        if not rule_ids:
            return

        with self._db_manager.session(
            self._desc(f'New group {unique_name}')
        ) as session:
            for rid in rule_ids:
                self._set_rule_group(session, rid, unique_name)
        self.reload()

    def rename_group(self, group_index, new_name):
        """Rename the group at *group_index* to *new_name*."""
        if not group_index.isValid() or not new_name:
            return
        node = group_index.internalPointer()
        if node.node_type != _NodeType.Group:
            return
        old_name = node.name
        if new_name == old_name:
            return

        with self._db_manager.session(self._desc('Rename group')) as session:
            for child in node.children:
                self._set_rule_group(session, child.row_data.rule_id, new_name)
        self.reload()

    def remove_from_group(self, indices):
        """Remove the rules at *indices* from their groups."""
        if not indices:
            return
        rule_ids = []
        for idx in indices:
            rd = self.get_row_data(idx)
            if rd is not None and rd.group:
                rule_ids.append(rd.rule_id)
        if not rule_ids:
            return

        with self._db_manager.session(self._desc('Remove from group')) as session:
            for rid in rule_ids:
                self._set_rule_group(session, rid, '')
        self.reload()

    def _find_unique_group_name(self, base):
        """Return *base* if unused, otherwise append -1, -2, etc."""
        existing = set()
        for child in self._root.children:
            if child.node_type == _NodeType.Group:
                existing.add(child.name)
        if base not in existing:
            return base
        counter = 1
        while f'{base}-{counter}' in existing:
            counter += 1
        return f'{base}-{counter}'

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _set_rule_group(session, rule_id, group_name):
        """Persist the group name into a rule's options JSON."""
        rule = session.get(PolicyRule, rule_id)
        if rule is None:
            return
        opts = dict(rule.options or {})
        if group_name:
            opts['group'] = group_name
        else:
            opts.pop('group', None)
        rule.options = opts

    def _do_move(
        self,
        rule_id,
        *,
        description,
        new_group=None,
        swap_with=None,
        target_pos=None,
    ):
        """Perform a move in a single session (group change + reposition).

        Exactly one of *swap_with* or *target_pos* may be given (or
        neither, when only a group change is needed).  After the
        operation, all positions in the rule set are renumbered
        sequentially.
        """
        with self._db_manager.session(self._desc(description)) as session:
            rule = session.get(PolicyRule, rule_id)
            if rule is None:
                return
            if new_group is not None:
                self._set_rule_group(session, rule_id, new_group)
            if swap_with is not None:
                other = session.get(PolicyRule, swap_with)
                if other is not None:
                    rule.position, other.position = other.position, rule.position
            elif target_pos is not None:
                rule.position = target_pos
            # Renumber to keep positions sequential (0, 1, 2, …).
            session.flush()
            remaining = session.scalars(
                sqlalchemy.select(PolicyRule)
                .where(PolicyRule.rule_set_id == self._rule_set_id)
                .order_by(PolicyRule.position, PolicyRule.id),
            ).all()
            for i, r in enumerate(remaining):
                r.position = i


_BLACK = QColor('black')
_WHITE = QColor('white')


def _build_options_display(opts):
    """Build a list of (None, label, icon_type) triples from rule options.

    Matches fwbuilder's ``PolicyModel::getRuleOptions()`` display logic.
    """
    if not opts:
        return []
    result = []
    if _opt_str(opts, 'counter_name') or _opt_str(opts, 'rule_name_accounting'):
        result.append((None, 'accounting', 'Accounting'))
    if _opt_bool(opts, 'classification'):
        label = _opt_str(opts, 'classify_str') or 'classify'
        result.append((None, label, 'Classify'))
    if _opt_bool(opts, 'log'):
        result.append((None, 'log', 'Log'))
    if _has_nondefault_options(opts):
        result.append((None, 'options', 'Options'))
    if _opt_bool(opts, 'routing'):
        result.append((None, 'route', 'Route'))
    if _opt_bool(opts, 'tagging'):
        result.append((None, 'tag', 'TagService'))
    return result


def _opt_bool(opts, key):
    """Return a boolean for *key*, coercing ``'True'``/``'False'`` strings."""
    val = opts.get(key)
    if isinstance(val, str):
        return val.lower() == 'true'
    return bool(val)


def _opt_str(opts, key):
    """Return a non-empty string for *key*, or ``''``."""
    val = opts.get(key, '')
    return str(val) if val else ''


def _opt_int(opts, key):
    """Return an int for *key*, or 0."""
    val = opts.get(key, 0)
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def _has_nondefault_options(opts):
    """Check whether any non-default iptables rule options are set.

    Mirrors fwbuilder's ``isDefaultPolicyRuleOptions()`` for iptables.
    """
    if _opt_str(opts, 'log_prefix'):
        return True
    if _opt_str(opts, 'log_level'):
        return True
    if _opt_int(opts, 'limit_value') > 0:
        return True
    if _opt_int(opts, 'connlimit_value') > 0:
        return True
    return _opt_int(opts, 'hashlimit_value') > 0


def _icon_suffix():
    """Return the QRC icon alias suffix for the configured rule icon size."""
    size = QSettings().value('UI/IconSizeInRules', 25, type=int)
    return 'icon-tree' if size == 16 else 'icon'


def _contrast_color(bg):
    """Return black or white, whichever has more contrast against *bg*.

    Uses the WCAG perceived-luminance formula.
    """
    luminance = 0.299 * bg.red() + 0.587 * bg.green() + 0.114 * bg.blue()
    return _BLACK if luminance > 128 else _WHITE


def _format_elements(triples):
    """Format a list of (uuid, name, type) triples for display."""
    if not triples:
        return 'Any'
    return '\n'.join(name for _, name, _ in triples)
