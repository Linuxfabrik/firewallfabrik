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

"""Database-backed tree model for policy/NAT/routing rules with group support."""

from __future__ import annotations

import dataclasses
import enum
import uuid
from collections import namedtuple
from typing import ClassVar

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
    NATAction,
    NATRule,
    PolicyAction,
    PolicyRule,
    RoutingRule,
    Rule,
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

# ---------------------------------------------------------------------------
# Column configuration per rule set type
# ---------------------------------------------------------------------------

_ColDesc = namedtuple('_ColDesc', ['header', 'slot', 'col_type'])
# col_type: 'position' | 'element' | 'action' | 'direction' | 'metric' | 'options' | 'comment'

_POLICY_COLS = (
    _ColDesc('#', None, 'position'),
    _ColDesc('Source', 'src', 'element'),
    _ColDesc('Destination', 'dst', 'element'),
    _ColDesc('Service', 'srv', 'element'),
    _ColDesc('Interface', 'itf', 'element'),
    _ColDesc('Direction', 'direction', 'direction'),
    _ColDesc('Action', 'action', 'action'),
    _ColDesc('Time', 'when', 'element'),
    _ColDesc('Options', 'options', 'options'),
    _ColDesc('Comment', None, 'comment'),
)

_NAT_COLS = (
    _ColDesc('#', None, 'position'),
    _ColDesc('Original Src', 'osrc', 'element'),
    _ColDesc('Original Dst', 'odst', 'element'),
    _ColDesc('Original Srv', 'osrv', 'element'),
    _ColDesc('Translated Src', 'tsrc', 'element'),
    _ColDesc('Translated Dst', 'tdst', 'element'),
    _ColDesc('Translated Srv', 'tsrv', 'element'),
    _ColDesc('Itf Inbound', 'itf_inb', 'element'),
    _ColDesc('Itf Outbound', 'itf_outb', 'element'),
    _ColDesc('Action', 'action', 'action'),
    _ColDesc('Options', 'options', 'options'),
    _ColDesc('Comment', None, 'comment'),
)

_ROUTING_COLS = (
    _ColDesc('#', None, 'position'),
    _ColDesc('Destination', 'rdst', 'element'),
    _ColDesc('Gateway', 'rgtw', 'element'),
    _ColDesc('Interface', 'ritf', 'element'),
    _ColDesc('Metric', None, 'metric'),
    _ColDesc('Options', 'options', 'options'),
    _ColDesc('Comment', None, 'comment'),
)

_COLS_BY_TYPE = {
    'NAT': _NAT_COLS,
    'Policy': _POLICY_COLS,
    'Routing': _ROUTING_COLS,
}

_RULE_CLASS = {
    'NAT': NATRule,
    'Policy': PolicyRule,
    'Routing': RoutingRule,
}


def _build_col_config(cols):
    """Derive helper dicts from a column config tuple."""
    headers = [c.header for c in cols]
    col_to_slot = {}
    slot_to_col = {}
    element_cols = set()
    action_col = None
    comment_col = None
    direction_col = None
    metric_col = None
    options_col = None
    position_col = None
    for i, desc in enumerate(cols):
        if desc.slot:
            col_to_slot[i] = desc.slot
            slot_to_col[desc.slot] = i
        if desc.col_type == 'element':
            element_cols.add(i)
        elif desc.col_type == 'action':
            action_col = i
            col_to_slot[i] = 'action'
            slot_to_col['action'] = i
        elif desc.col_type == 'comment':
            comment_col = i
        elif desc.col_type == 'direction':
            direction_col = i
            col_to_slot[i] = 'direction'
            slot_to_col['direction'] = i
        elif desc.col_type == 'metric':
            metric_col = i
        elif desc.col_type == 'options':
            options_col = i
            col_to_slot[i] = 'options'
            slot_to_col['options'] = i
        elif desc.col_type == 'position':
            position_col = i
    selectable_cols = set(element_cols)
    if action_col is not None:
        selectable_cols.add(action_col)
    if direction_col is not None:
        selectable_cols.add(direction_col)
    if options_col is not None:
        selectable_cols.add(options_col)
    return {
        'action_col': action_col,
        'col_to_slot': col_to_slot,
        'comment_col': comment_col,
        'direction_col': direction_col,
        'element_cols': frozenset(element_cols),
        'headers': headers,
        'metric_col': metric_col,
        'options_col': options_col,
        'position_col': position_col,
        'selectable_cols': frozenset(selectable_cols),
        'slot_to_col': slot_to_col,
    }


# ---------------------------------------------------------------------------
# Backward-compatible module-level constants (correct for Policy only).
# View code will progressively switch to model-level config.
# ---------------------------------------------------------------------------

HEADERS = [c.header for c in _POLICY_COLS]

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
    _COL_ACTION: 'action',
    _COL_DIRECTION: 'direction',
    _COL_DST: 'dst',
    _COL_ITF: 'itf',
    _COL_OPTIONS: 'options',
    _COL_SRC: 'src',
    _COL_SRV: 'srv',
    _COL_TIME: 'when',
}

_SLOT_TO_COL = {v: k for k, v in _COL_TO_SLOT.items()}

_ELEMENT_COLS = frozenset({_COL_DST, _COL_ITF, _COL_SRC, _COL_SRV, _COL_TIME})

# All columns that support single-click element selection / highlighting.
_SELECTABLE_COLS = _ELEMENT_COLS | {_COL_ACTION, _COL_DIRECTION, _COL_OPTIONS}

# ---------------------------------------------------------------------------

_DIRECTION_NAMES = frozenset({'Both', 'Inbound', 'Outbound'})

_GROUP_BG = QColor('lightgray')

# Enum names that differ from the display label shown in the UI.
_ACTION_DISPLAY = {'Pipe': 'Queue'}


def _action_label(enum_name):
    """Return the user-visible label for an action enum name."""
    return _ACTION_DISPLAY.get(enum_name, enum_name)


# Classes used to resolve target names from the database.
_NAME_CLASSES = (Address, Group, Host, Interface, Interval, Service)


class _NodeType(enum.IntEnum):
    Group = 0
    Root = 1
    Rule = 2


@dataclasses.dataclass
class _RowData:
    """Structured data for one rule row (Policy, NAT, or Routing)."""

    action: str
    action_int: int
    color_hex: str
    comment: str
    direction: str
    direction_int: int
    disabled: bool
    dst: list  # list[tuple[uuid.UUID, str, str]]  (id, name, type)
    group: str
    itf: list
    label: str
    negations: dict  # slot -> bool, e.g. {'src': True, 'dst': False}
    options: dict  # raw rule options dict for tooltip generation
    options_display: list  # list[tuple[str, str, str]]  (sentinel_id, label, icon-type)
    position: int
    rule_id: uuid.UUID
    src: list
    srv: list
    when: list  # list[tuple[uuid.UUID, str, str]]  (id, name, type)
    # NAT-specific
    itf_inb: list = dataclasses.field(default_factory=list)
    itf_outb: list = dataclasses.field(default_factory=list)
    metric: int = 0
    nat_action: str = ''
    nat_action_int: int = 0
    odst: list = dataclasses.field(default_factory=list)
    osrc: list = dataclasses.field(default_factory=list)
    osrv: list = dataclasses.field(default_factory=list)
    rdst: list = dataclasses.field(default_factory=list)
    rgtw: list = dataclasses.field(default_factory=list)
    ritf: list = dataclasses.field(default_factory=list)
    tdst: list = dataclasses.field(default_factory=list)
    tsrc: list = dataclasses.field(default_factory=list)
    tsrv: list = dataclasses.field(default_factory=list)


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
    """Database-backed tree model for policy/NAT/routing rules with group support."""

    _clipboard: ClassVar[list[uuid.UUID]] = []

    def __init__(
        self,
        db_manager,
        rule_set_id,
        *,
        object_name='',
        parent=None,
        rule_set_type='Policy',
    ):
        super().__init__(parent)
        self._db_manager = db_manager
        self._object_name = object_name
        self._rule_set_id = rule_set_id
        self._rule_set_type = rule_set_type
        self._rule_cls = _RULE_CLASS.get(rule_set_type, PolicyRule)

        # Column configuration derived from type.
        self._cols = _COLS_BY_TYPE.get(rule_set_type, _POLICY_COLS)
        cfg = _build_col_config(self._cols)
        self._action_col = cfg['action_col']
        self._col_to_slot = cfg['col_to_slot']
        self._comment_col = cfg['comment_col']
        self._direction_col = cfg['direction_col']
        self._element_cols = cfg['element_cols']
        self._headers = cfg['headers']
        self._metric_col = cfg['metric_col']
        self._options_col = cfg['options_col']
        self._position_col = cfg['position_col']
        self._selectable_cols = cfg['selectable_cols']
        self._slot_to_col = cfg['slot_to_col']

        self._root = _TreeNode(_NodeType.Root)
        self.reload()

    # ------------------------------------------------------------------
    # Public column config accessors (used by the view)
    # ------------------------------------------------------------------

    @property
    def action_col(self):
        return self._action_col

    @property
    def col_to_slot(self):
        return self._col_to_slot

    @property
    def comment_col(self):
        return self._comment_col

    @property
    def direction_col(self):
        return self._direction_col

    @property
    def element_cols(self):
        return self._element_cols

    @property
    def metric_col(self):
        return self._metric_col

    @property
    def options_col(self):
        return self._options_col

    @property
    def position_col(self):
        return self._position_col

    @property
    def rule_set_type(self):
        return self._rule_set_type

    @property
    def selectable_cols(self):
        return self._selectable_cols

    @property
    def slot_to_col(self):
        return self._slot_to_col

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def reload(self):
        """Re-query the database and rebuild the tree."""
        self.beginResetModel()
        self._root = _TreeNode(_NodeType.Root)

        with self._db_manager.session() as session:
            rules = session.scalars(
                sqlalchemy.select(self._rule_cls)
                .where(self._rule_cls.rule_set_id == self._rule_set_id)
                .order_by(self._rule_cls.position),
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
                row_data = self._build_row_data(rule, slots)

                rule_node = _TreeNode(
                    _NodeType.Rule,
                    row_data=row_data,
                )

                group_name = row_data.group
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

    def _build_row_data(self, rule, slots):
        """Build a _RowData from a Rule ORM object and its slot elements."""
        # Parse Policy action/direction.
        dir_name = ''
        direction_int = 0
        act_name = ''
        action_int = 0
        nat_action_name = ''
        nat_action_int = 0

        if self._rule_set_type == 'Policy':
            try:
                direction = Direction(rule.policy_direction)
                dir_name = direction.name
                direction_int = direction.value
            except (TypeError, ValueError):
                pass
            try:
                action = PolicyAction(rule.policy_action)
                act_name = action.name
                action_int = action.value
            except (TypeError, ValueError):
                pass
        elif self._rule_set_type == 'NAT':
            try:
                nat_act = NATAction(rule.nat_action)
                nat_action_name = nat_act.name
                nat_action_int = nat_act.value
                # Also set the generic action fields so Action column works.
                act_name = nat_act.name
                action_int = nat_act.value
            except (TypeError, ValueError):
                pass

        opts = rule.options or {}
        group_name = opts.get('group', '')
        color_hex = opts.get('color', '')
        if not color_hex and rule.label and rule.label in LABEL_KEYS:
            color_hex = get_label_color(rule.label)

        return _RowData(
            action=act_name,
            action_int=action_int,
            color_hex=color_hex,
            comment=rule.comment or '',
            direction=dir_name,
            direction_int=direction_int,
            disabled=_opt_bool(opts, 'disabled'),
            dst=slots.get('dst', []),
            group=group_name,
            itf=slots.get('itf', []),
            itf_inb=slots.get('itf_inb', []),
            itf_outb=slots.get('itf_outb', []),
            label=rule.label or '',
            metric=_opt_int(opts, 'metric'),
            nat_action=nat_action_name,
            nat_action_int=nat_action_int,
            negations=rule.negations or {},
            odst=slots.get('odst', []),
            options=opts,
            options_display=_build_options_display(opts),
            osrc=slots.get('osrc', []),
            osrv=slots.get('osrv', []),
            position=rule.position,
            rdst=slots.get('rdst', []),
            rgtw=slots.get('rgtw', []),
            ritf=slots.get('ritf', []),
            rule_id=rule.id,
            src=slots.get('src', []),
            srv=slots.get('srv', []),
            tdst=slots.get('tdst', []),
            tsrc=slots.get('tsrc', []),
            tsrv=slots.get('tsrv', []),
            when=slots.get('when', []),
        )

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
        return len(self._headers)

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
        if col in self._element_cols:
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
        if node.node_type != _NodeType.Rule or index.column() != self._comment_col:
            return False

        row_data = node.row_data
        new_comment = str(value).strip()
        if new_comment == row_data.comment:
            return False

        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} comment'),
        ) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
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
            return self._headers[section]
        return None

    def mimeTypes(self):
        return [FWF_MIME_TYPE]

    def canDropMimeData(self, data, action, row, column, parent):
        if not data.hasFormat(FWF_MIME_TYPE):
            return False
        col = parent.column() if parent.isValid() else column
        return col in self._element_cols

    def dropMimeData(self, data, action, row, column, parent):
        # Handled by the view's dropEvent instead.
        return False

    def supportedDropActions(self):
        return Qt.DropAction.CopyAction | Qt.DropAction.MoveAction

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

    def is_outermost(self, index):
        """Return True if *index* is the first or last rule in its group.

        Matches fwbuilder's ``RuleNode::isOutermost()`` — only outermost
        rules can be removed from a group.
        """
        if not index.isValid():
            return False
        node = index.internalPointer()
        if node.node_type != _NodeType.Rule:
            return False
        parent = node.parent
        if parent is None or parent is self._root:
            return False  # Not in a group.
        return node is parent.children[0] or node is parent.children[-1]

    def adjacent_group_names(self, index):
        """Return ``(above, below)`` group names adjacent to a top-level rule.

        Each value is the group name or ``''`` if no group is adjacent
        in that direction.  Returns ``('', '')`` for grouped rules or
        non-rule indices.
        """
        if not index.isValid():
            return ('', '')
        node = index.internalPointer()
        if node.node_type != _NodeType.Rule or node.parent is not self._root:
            return ('', '')
        children = self._root.children
        idx = children.index(node)
        above = ''
        if idx > 0 and children[idx - 1].node_type == _NodeType.Group:
            above = children[idx - 1].name
        below = ''
        if idx < len(children) - 1 and children[idx + 1].node_type == _NodeType.Group:
            below = children[idx + 1].name
        return (above, below)

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _group_data(self, node, col, role):
        """Return data for a group header row."""
        if role == Qt.ItemDataRole.DisplayRole and col == self._position_col:
            if node.children:
                first = node.children[0].row_data.position
                last = node.children[-1].row_data.position
                return f'{node.name} ({first} - {last})'
            return node.name
        if role == Qt.ItemDataRole.BackgroundRole:
            return _GROUP_BG
        if role == Qt.ItemDataRole.ToolTipRole and col == self._position_col:
            return f'Rule group: {node.name}'
        return None

    def _rule_data(self, row_data, col, role):
        """Return data for a rule row."""
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display_value(row_data, col)
        if role == Qt.ItemDataRole.ToolTipRole:
            if not QSettings().value('UI/ObjTooltips', True, type=bool):
                return None
            if col == self._options_col:
                return _options_tooltip(row_data)
            return self._display_value(row_data, col)
        if role == Qt.ItemDataRole.BackgroundRole:
            if row_data.color_hex:
                return QColor(row_data.color_hex)
            return None
        if role == Qt.ItemDataRole.ForegroundRole:
            if row_data.color_hex:
                return _contrast_color(QColor(row_data.color_hex))
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col == self._position_col:
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        if role == Qt.ItemDataRole.DecorationRole:
            return self._decoration_value(row_data, col)
        if role == ELEMENTS_ROLE:
            return self._elements_value(row_data, col)
        if role == NEGATED_ROLE:
            if col in self._element_cols:
                slot = self._col_to_slot.get(col)
                if slot:
                    return bool(row_data.negations.get(slot))
            return False
        return None

    def _display_value(self, row_data, col):
        """Return the display string for *col* of *row_data*."""
        if col >= len(self._cols):
            return ''
        desc = self._cols[col]
        if desc.col_type == 'position':
            return row_data.position
        if desc.col_type == 'element':
            return _format_elements(getattr(row_data, desc.slot, []))
        if desc.col_type == 'action':
            if self._rule_set_type == 'NAT':
                return row_data.nat_action or ''
            return _action_label(row_data.action)
        if desc.col_type == 'direction':
            return row_data.direction
        if desc.col_type == 'metric':
            return str(row_data.metric) if row_data.metric else ''
        if desc.col_type == 'options':
            return (
                _format_elements(row_data.options_display)
                if row_data.options_display
                else ''
            )
        if desc.col_type == 'comment':
            return row_data.comment
        return ''

    def _decoration_value(self, row_data, col):
        """Return the icon for *col* of *row_data*, or None."""
        suffix = _icon_suffix()
        if col == self._position_col and row_data.disabled:
            return QIcon(f':/Icons/Neg/{suffix}')
        if col == self._action_col:
            if self._rule_set_type == 'NAT' and row_data.nat_action:
                icon = QIcon(f':/Icons/{row_data.nat_action}/{suffix}')
                if not icon.isNull():
                    return icon
            elif row_data.action:
                icon = QIcon(f':/Icons/{row_data.action}/{suffix}')
                if not icon.isNull():
                    return icon
        if col == self._direction_col and row_data.direction in _DIRECTION_NAMES:
            return QIcon(f':/Icons/{row_data.direction}/{suffix}')
        return None

    def _elements_value(self, row_data, col):
        """Return the ELEMENTS_ROLE data for *col* of *row_data*."""
        if col in self._element_cols:
            slot = self._col_to_slot.get(col)
            if slot:
                return getattr(row_data, slot)
        if col == self._action_col:
            if self._rule_set_type == 'NAT' and row_data.nat_action:
                return [
                    ('__action__', row_data.nat_action, row_data.nat_action),
                ]
            if row_data.action:
                return [
                    (
                        '__action__',
                        _action_label(row_data.action),
                        row_data.action,
                    ),
                ]
        if col == self._direction_col and row_data.direction:
            return [
                ('__direction__', row_data.direction, row_data.direction),
            ]
        if col == self._options_col:
            return row_data.options_display or None
        return None

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def rule_set_id(self):
        """Return the UUID of the rule set this model represents."""
        return self._rule_set_id

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

    def insert_rule(self, index=None, *, at_top=False, at_bottom=False, before=False):
        """Insert a new rule.

        When *before* is True the new rule is placed **at** the position
        of the rule pointed to by *index* (pushing it down).  When False
        (the default) the new rule is placed **after** *index*.

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
                if before:
                    position = node.row_data.position
                else:
                    position = node.row_data.position + 1
                group_name = node.row_data.group
            else:
                position = self.flat_rule_count()

        with self._db_manager.session(self._desc(f'New rule {position}')) as session:
            # Shift existing rules at or after the insertion point.
            session.execute(
                sqlalchemy.update(self._rule_cls)
                .where(
                    self._rule_cls.rule_set_id == self._rule_set_id,
                    self._rule_cls.position >= position,
                )
                .values(position=self._rule_cls.position + 1),
            )
            # Defaults per type.
            opts = {}
            kwargs = {}
            if self._rule_set_type == 'Policy':
                opts['stateless'] = True
                kwargs['policy_action'] = PolicyAction.Deny.value
                kwargs['policy_direction'] = Direction.Both.value
            elif self._rule_set_type == 'NAT':
                kwargs['nat_action'] = NATAction.Translate.value
            if group_name:
                opts['group'] = group_name
            new_id = uuid.uuid4()
            new_rule = self._rule_cls(
                id=new_id,
                rule_set_id=self._rule_set_id,
                position=position,
                options=opts,
                **kwargs,
            )
            session.add(new_rule)

        self.reload()
        return new_id

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
                sqlalchemy.delete(self._rule_cls).where(
                    self._rule_cls.id.in_(rule_ids)
                ),
            )
            # Renumber remaining rules.
            remaining = session.scalars(
                sqlalchemy.select(self._rule_cls)
                .where(self._rule_cls.rule_set_id == self._rule_set_id)
                .order_by(self._rule_cls.position),
            ).all()
            for i, rule in enumerate(remaining):
                rule.position = i

        self.reload()

    def copy_rules(self, indices):
        """Copy rule IDs from selected *indices* to the clipboard."""
        rule_ids = []
        for idx in indices:
            node = self._node_from_index(idx)
            if node.node_type == _NodeType.Rule:
                rule_ids.append(node.row_data.rule_id)
            elif node.node_type == _NodeType.Group:
                for child in node.children:
                    rule_ids.append(child.row_data.rule_id)
        PolicyTreeModel._clipboard = rule_ids

    def cut_rules(self, indices):
        """Copy rule IDs to clipboard, then delete the rules."""
        self.copy_rules(indices)
        self.delete_rules(indices)

    def paste_rules(self, index, *, before=False):
        """Paste rules from clipboard at *index*.

        When *before* is True, pasted rules are inserted above the target;
        otherwise they are inserted below.  Returns a list of new rule IDs.

        Uses :meth:`DatabaseManager.create_session` with an explicit
        :meth:`~DatabaseManager.save_state` call because the internal
        ``session.flush()`` (needed for FK constraints on rule_elements)
        clears ``session.new``, which would prevent the automatic dirty
        detection in the ``session()`` context manager.
        """
        if not PolicyTreeModel._clipboard:
            return []

        node = self._node_from_index(index)
        if node.node_type == _NodeType.Group:
            position = node.children[-1].row_data.position + 1 if node.children else 0
            group_name = node.name
        elif node.node_type == _NodeType.Rule:
            position = node.row_data.position if before else node.row_data.position + 1
            group_name = node.row_data.group
        else:
            position = self.flat_rule_count()
            group_name = ''

        new_ids = []
        session = self._db_manager.create_session()
        try:
            for i, src_id in enumerate(PolicyTreeModel._clipboard):
                # Use base Rule for lookup — clipboard may hold any type.
                src_rule = session.get(Rule, src_id)
                if src_rule is None:
                    continue

                # Shift existing rules to make room.
                session.execute(
                    sqlalchemy.update(self._rule_cls)
                    .where(
                        self._rule_cls.rule_set_id == self._rule_set_id,
                        self._rule_cls.position >= position + i,
                    )
                    .values(position=self._rule_cls.position + 1),
                )

                new_id = uuid.uuid4()
                opts = dict(src_rule.options or {})
                if group_name:
                    opts['group'] = group_name
                else:
                    opts.pop('group', None)

                kwargs = {
                    'comment': src_rule.comment or '',
                    'id': new_id,
                    'label': src_rule.label or '',
                    'negations': dict(src_rule.negations or {}),
                    'options': opts,
                    'position': position + i,
                    'rule_set_id': self._rule_set_id,
                }
                # Copy type-specific fields.
                if self._rule_set_type == 'Policy':
                    kwargs['policy_action'] = src_rule.policy_action
                    kwargs['policy_direction'] = src_rule.policy_direction
                elif self._rule_set_type == 'NAT':
                    kwargs['nat_action'] = src_rule.nat_action
                    kwargs['nat_rule_type'] = src_rule.nat_rule_type
                elif self._rule_set_type == 'Routing':
                    kwargs['routing_rule_type'] = src_rule.routing_rule_type

                new_rule = self._rule_cls(**kwargs)
                session.add(new_rule)
                session.flush()

                # Copy rule_elements.
                src_elements = session.execute(
                    sqlalchemy.select(
                        rule_elements.c.slot,
                        rule_elements.c.target_id,
                        rule_elements.c.position,
                    ).where(rule_elements.c.rule_id == src_id),
                ).all()
                for slot, target_id, elem_pos in src_elements:
                    session.execute(
                        rule_elements.insert().values(
                            rule_id=new_id,
                            slot=slot,
                            target_id=target_id,
                            position=elem_pos,
                        ),
                    )

                new_ids.append(new_id)

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        if new_ids:
            self._db_manager.save_state(self._desc(f'Paste rule at {position}'))

        self.reload()
        return new_ids

    def move_rule_up(self, index):
        """Move the rule at *index* up one position.

        Group boundary behavior:
        - First in group + up -> leaves group (placed before group)
        - Top-level above group + up -> joins group as last member

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
        - Last in group + down -> leaves group (placed after group)
        - Top-level below group + down -> joins group as first member

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
        """Set the action for the rule at *index*.

        For Policy rules, *action* is a :class:`PolicyAction`.
        For NAT rules, *action* is a :class:`NATAction`.

        Also updates the ``stateless`` flag for Policy rules: Accept
        defaults to stateful, all other actions default to stateless
        (matching fwbuilder's ``getStatelessFlagForAction``).
        """
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} action'),
        ) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
            if rule is not None:
                if self._rule_set_type == 'NAT':
                    rule.nat_action = action.value
                else:
                    rule.policy_action = action.value
                    opts = dict(rule.options or {})
                    if action == PolicyAction.Accept:
                        opts.pop('stateless', None)
                    else:
                        opts['stateless'] = True
                    rule.options = opts
        self.reload()

    def set_comment(self, index, comment):
        """Set the comment for the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        new_comment = str(comment).strip()
        if new_comment == (row_data.comment or ''):
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} comment'),
        ) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
            if rule is not None:
                rule.comment = new_comment
        self.reload()

    def set_disabled(self, index, disabled):
        """Enable or disable the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        desc = (
            f'Disable rule {row_data.position}'
            if disabled
            else f'Enable rule {row_data.position}'
        )
        with self._db_manager.session(self._desc(desc)) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
            if rule is not None:
                opts = dict(rule.options or {})
                if disabled:
                    opts['disabled'] = True
                else:
                    opts.pop('disabled', None)
                rule.options = opts
        self.reload()

    def set_direction(self, index, direction):
        """Set the policy direction for the rule at *index*.

        Only meaningful for Policy rules; no-op for NAT/Routing.
        """
        if self._rule_set_type != 'Policy':
            return
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} direction'),
        ) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
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
            rule = session.get(self._rule_cls, row_data.rule_id)
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

    def move_element(
        self, source_rule_id, source_slot, target_index, target_slot, target_id
    ):
        """Move *target_id* from *source_rule_id*/*source_slot* to the rule at *target_index*."""
        target_row_data = self.get_row_data(target_index)
        if target_row_data is None:
            return
        with self._db_manager.session(
            self._desc(
                f'Move element to rule {target_row_data.position} {target_slot}'
            ),
        ) as session:
            # Check for duplicate in target.
            existing = session.execute(
                sqlalchemy.select(rule_elements.c.target_id).where(
                    rule_elements.c.rule_id == target_row_data.rule_id,
                    rule_elements.c.slot == target_slot,
                    rule_elements.c.target_id == target_id,
                ),
            ).first()
            if existing is not None:
                return
            # Delete from source.
            session.execute(
                sqlalchemy.delete(rule_elements).where(
                    rule_elements.c.rule_id == source_rule_id,
                    rule_elements.c.slot == source_slot,
                    rule_elements.c.target_id == target_id,
                ),
            )
            # Insert into target.
            max_pos = session.scalar(
                sqlalchemy.select(
                    sqlalchemy.func.coalesce(
                        sqlalchemy.func.max(rule_elements.c.position), -1
                    ),
                ).where(
                    rule_elements.c.rule_id == target_row_data.rule_id,
                    rule_elements.c.slot == target_slot,
                ),
            )
            session.execute(
                rule_elements.insert().values(
                    rule_id=target_row_data.rule_id,
                    slot=target_slot,
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
        elem_name = ''
        for eid, ename, _etype in getattr(row_data, slot, []):
            if eid == target_id:
                elem_name = ename
                break
        desc = f'Delete rule {row_data.position} {slot} {elem_name}'.rstrip()
        with self._db_manager.session(self._desc(desc)) as session:
            session.execute(
                sqlalchemy.delete(rule_elements).where(
                    rule_elements.c.rule_id == row_data.rule_id,
                    rule_elements.c.slot == slot,
                    rule_elements.c.target_id == target_id,
                ),
            )
        self.reload()

    def set_logging(self, index, enabled):
        """Toggle the logging flag for the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        desc = (
            f'Enable logging rule {row_data.position}'
            if enabled
            else f'Disable logging rule {row_data.position}'
        )
        with self._db_manager.session(self._desc(desc)) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
            if rule is not None:
                opts = dict(rule.options or {})
                if enabled:
                    opts['log'] = True
                else:
                    opts.pop('log', None)
                rule.options = opts
        self.reload()

    def set_options(self, index, options):
        """Replace rule options for the rule at *index*.

        *options* is a dict that replaces the non-structural keys in the
        rule's ``options`` JSON (``group``, ``disabled``, and ``color``
        are preserved from the existing options).
        """
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        with self._db_manager.session(
            self._desc(f'Edit rule {row_data.position} options'),
        ) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
            if rule is not None:
                old = dict(rule.options or {})
                merged = dict(options)
                # Preserve structural keys managed elsewhere.
                for key in ('color', 'disabled', 'group'):
                    if key in old:
                        merged[key] = old[key]
                rule.options = merged
        self.reload()

    def toggle_negation(self, index, slot):
        """Flip the negation flag for *slot* of the rule at *index*."""
        row_data = self.get_row_data(index)
        if row_data is None:
            return
        current = bool(row_data.negations.get(slot))
        new_val = not current
        with self._db_manager.session(
            self._desc(f'Negate rule {row_data.position} {slot}'),
        ) as session:
            rule = session.get(self._rule_cls, row_data.rule_id)
            if rule is not None:
                negs = dict(rule.negations or {})
                negs[slot] = new_val
                rule.negations = negs
        row_data.negations[slot] = new_val
        col = self._slot_to_col.get(slot)
        if col is not None:
            cell_index = self.index(index.row(), col, index.parent())
            self.dataChanged.emit(
                cell_index, cell_index, [Qt.ItemDataRole.DisplayRole, NEGATED_ROLE]
            )

    # ------------------------------------------------------------------
    # Group management methods
    # ------------------------------------------------------------------

    def add_to_group(self, indices, group_name):
        """Move the top-level rules at *indices* into the existing *group_name*."""
        if not group_name or not indices:
            return
        rule_ids = []
        positions = []
        for idx in indices:
            rd = self.get_row_data(idx)
            if rd is not None and not rd.group:
                rule_ids.append(rd.rule_id)
                positions.append(str(rd.position))
        if not rule_ids:
            return
        pos_str = ', '.join(positions)
        with self._db_manager.session(
            self._desc(f'Add rule {pos_str} to group {group_name}'),
        ) as session:
            for rid in rule_ids:
                self._set_rule_group(session, rid, group_name)
        self.reload()

    def create_group(self, name, indices):
        """Group the rules at *indices* under a new group named *name*."""
        if not name or not indices:
            return
        unique_name = self._find_unique_group_name(name)
        rule_ids = []
        positions = []
        for idx in indices:
            rd = self.get_row_data(idx)
            if rd is not None:
                rule_ids.append(rd.rule_id)
                positions.append(str(rd.position))
        if not rule_ids:
            return
        pos_str = ', '.join(positions)
        with self._db_manager.session(
            self._desc(f'New group {unique_name} with rule {pos_str}'),
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
        self.remove_from_group_by_ids(rule_ids)

    def remove_from_group_by_ids(self, rule_ids):
        """Remove the rules identified by *rule_ids* from their groups."""
        if not rule_ids:
            return
        positions = []
        for rid in rule_ids:
            idx = self.index_for_rule(rid)
            rd = self.get_row_data(idx)
            if rd is not None:
                positions.append(str(rd.position))
        pos_str = ', '.join(positions) if positions else '?'
        with self._db_manager.session(
            self._desc(f'Remove rule {pos_str} from group'),
        ) as session:
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

    def _set_rule_group(self, session, rule_id, group_name):
        """Persist the group name into a rule's options JSON."""
        rule = session.get(self._rule_cls, rule_id)
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
            rule = session.get(self._rule_cls, rule_id)
            if rule is None:
                return
            if new_group is not None:
                self._set_rule_group(session, rule_id, new_group)
            if swap_with is not None:
                other = session.get(self._rule_cls, swap_with)
                if other is not None:
                    rule.position, other.position = other.position, rule.position
            elif target_pos is not None:
                rule.position = target_pos
            # Renumber to keep positions sequential (0, 1, 2, ...).
            session.flush()
            remaining = session.scalars(
                sqlalchemy.select(self._rule_cls)
                .where(self._rule_cls.rule_set_id == self._rule_set_id)
                .order_by(self._rule_cls.position, self._rule_cls.id),
            ).all()
            for i, r in enumerate(remaining):
                r.position = i


_BLACK = QColor('black')
_WHITE = QColor('white')


def _build_options_display(opts):
    """Build a list of (id, label, icon_type) triples from rule options.

    Matches fwbuilder's ``PolicyModel::getRuleOptions()`` display logic.
    The *id* is a unique string sentinel used for per-element selection.
    """
    if not opts:
        return []
    result = []
    if _opt_str(opts, 'counter_name') or _opt_str(opts, 'rule_name_accounting'):
        result.append(('__opt_accounting__', 'accounting', 'Accounting'))
    if _opt_bool(opts, 'classification'):
        label = _opt_str(opts, 'classify_str') or 'classify'
        result.append(('__opt_classify__', label, 'Classify'))
    if _opt_bool(opts, 'log'):
        result.append(('__opt_log__', 'log', 'Log'))
    if _has_nondefault_options(opts):
        result.append(('__opt_options__', 'options', 'Options'))
    if _opt_bool(opts, 'routing'):
        result.append(('__opt_route__', 'route', 'Route'))
    if _opt_bool(opts, 'tagging'):
        result.append(('__opt_tag__', 'tag', 'TagService'))
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


def _options_tooltip(row_data):
    """Build an HTML tooltip for the Options column.

    Mirrors fwbuilder's ``FWObjectPropertiesFactory::getPolicyRuleOptions()``.
    The stateful/stateless default depends on the action: Accept defaults to
    stateful, all other actions default to stateless.
    """
    opts = row_data.options or {}
    rows = []

    # Stateful / Stateless.
    if _opt_bool(opts, 'stateless'):
        rows.append(('Stateless', ''))
    else:
        rows.append(('Stateful', ''))

    # iptables-specific options (the only platform we support).
    if _opt_bool(opts, 'tagging'):
        tag_id = _opt_str(opts, 'tagobject_id')
        rows.append(('Tag:', tag_id or 'yes'))

    classify = _opt_str(opts, 'classify_str')
    if classify:
        rows.append(('Class:', classify))

    log_prefix = _opt_str(opts, 'log_prefix')
    if log_prefix:
        rows.append(('Log prefix:', log_prefix))

    log_level = _opt_str(opts, 'log_level')
    if log_level:
        rows.append(('Log level:', log_level))

    nlgroup = _opt_int(opts, 'ulog_nlgroup')
    if nlgroup > 1:
        rows.append(('Netlink group:', str(nlgroup)))

    limit_val = _opt_int(opts, 'limit_value')
    if limit_val > 0:
        arg = '! ' if _opt_bool(opts, 'limit_value_not') else ''
        arg += str(limit_val)
        suffix = _opt_str(opts, 'limit_suffix')
        if suffix:
            arg += suffix
        rows.append(('Limit value:', arg))

    limit_burst = _opt_int(opts, 'limit_burst')
    if limit_burst > 0:
        rows.append(('Limit burst:', str(limit_burst)))

    connlimit = _opt_int(opts, 'connlimit_value')
    if connlimit > 0:
        arg = '! ' if _opt_bool(opts, 'connlimit_above_not') else ''
        arg += str(connlimit)
        rows.append(('Connlimit value:', arg))

    hashlimit_val = _opt_int(opts, 'hashlimit_value')
    if hashlimit_val > 0:
        hl_name = _opt_str(opts, 'hashlimit_name')
        if hl_name:
            rows.append(('Hashlimit name:', hl_name))
        arg = str(hashlimit_val)
        hl_suffix = _opt_str(opts, 'hashlimit_suffix')
        if hl_suffix:
            arg += hl_suffix
        rows.append(('Hashlimit value:', arg))
        hl_burst = _opt_int(opts, 'hashlimit_burst')
        if hl_burst > 0:
            rows.append(('Hashlimit burst:', str(hl_burst)))

    if _opt_str(opts, 'firewall_is_part_of_any_and_networks'):
        rows.append(('Part of Any', ''))

    # Logging (always shown, last row).
    logging_on = _opt_bool(opts, 'log')
    rows.append(('Logging:', 'on' if logging_on else 'off'))

    # Format as HTML table.
    html = '<table>'
    for label, value in rows:
        html += f"<tr><th align='left'>{label}</th><td>{value}</td></tr>"
    html += '</table>'
    return html


def _has_nondefault_options(opts):
    """Check whether any non-default iptables rule options are set.

    Mirrors fwbuilder's ``isDefaultPolicyRuleOptions()`` for iptables.
    """
    if _opt_int(opts, 'connlimit_value') > 0:
        return True
    if _opt_bool(opts, 'connlimit_above_not'):
        return True
    if _opt_int(opts, 'connlimit_masklen') > 0:
        return True
    if _opt_str(opts, 'firewall_is_part_of_any_and_networks'):
        return True
    if _opt_int(opts, 'hashlimit_burst') > 0:
        return True
    if _opt_int(opts, 'hashlimit_expire') > 0:
        return True
    if _opt_int(opts, 'hashlimit_gcinterval') > 0:
        return True
    if _opt_int(opts, 'hashlimit_max') > 0:
        return True
    if _opt_str(opts, 'hashlimit_name'):
        return True
    if _opt_int(opts, 'hashlimit_size') > 0:
        return True
    if _opt_int(opts, 'hashlimit_value') > 0:
        return True
    if _opt_int(opts, 'limit_burst') > 0:
        return True
    if _opt_str(opts, 'limit_suffix'):
        return True
    if _opt_int(opts, 'limit_value') > 0:
        return True
    if _opt_bool(opts, 'limit_value_not'):
        return True
    if _opt_str(opts, 'log_level'):
        return True
    if _opt_str(opts, 'log_prefix'):
        return True
    return _opt_int(opts, 'ulog_nlgroup') > 1


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
