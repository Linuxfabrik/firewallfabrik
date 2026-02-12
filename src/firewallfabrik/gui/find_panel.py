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

"""Find panel widget for searching objects in the tree and replacing in rules."""

import dataclasses
import re
import uuid
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QSettings, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QTreeWidgetItemIterator,
    QWidget,
)

from firewallfabrik.core.objects import Rule, rule_elements
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'
_MAX_SEARCH_ITEMS = 10

# Object types matched by each attribute index.
_ADDRESS_TYPES = frozenset(
    {
        'IPv4',
        'IPv6',
        'Network',
        'NetworkIPv6',
        'AddressRange',
        'PhysAddress',
    }
)
_TCP_UDP_TYPES = frozenset({'TCPService', 'UDPService'})
_IP_SERVICE_TYPES = frozenset({'IPService'})
_ICMP_TYPES = frozenset({'ICMPService', 'ICMP6Service'})

# Type compatibility sets for replace validation.
_ADDRESS_COMPATIBLE = frozenset(
    {
        'IPv4',
        'IPv6',
        'Network',
        'NetworkIPv6',
        'AddressRange',
        'PhysAddress',
        'Host',
        'Firewall',
        'Cluster',
        'Interface',
        'AddressTable',
        'DNSName',
        'AttachedNetworks',
        'ObjectGroup',
    }
)
_SERVICE_COMPATIBLE = frozenset(
    {
        'TCPService',
        'UDPService',
        'ICMPService',
        'ICMP6Service',
        'IPService',
        'CustomService',
        'TagService',
        'UserService',
        'ServiceGroup',
    }
)


@dataclasses.dataclass
class _FindResult:
    """A single search result — either a tree item or a rule element reference."""

    tree_item: QTreeWidgetItem | None = None
    rule_set_id: uuid.UUID | None = None
    rule_id: uuid.UUID | None = None
    slot: str | None = None
    target_id: uuid.UUID | None = None


class FindPanel(QWidget):
    """Find-panel for searching objects in the object tree and rules."""

    object_found = Signal(str, str)  # (obj_id, obj_type)
    navigate_to_rule = Signal(str, str, str)  # (rule_set_id, rule_id, slot)

    def __init__(self, parent=None):
        super().__init__(parent)
        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'findobjectwidget_q.ui'))

        self._tree = None
        self._db_manager = None
        self._reload_callback = None
        self._get_open_rule_set_ids = None
        self._results: list[_FindResult] = []
        self._result_index = 0
        self._last_search_text = ''
        self._last_attr_index = 0
        self._last_use_regexp = False
        self._last_find_obj_id = None

        # Restore saved scope.
        scope = QSettings().value('Search/Scope', 0, type=int)
        self.srScope.setCurrentIndex(scope)

        # Configure drop area helper texts.
        self.findDropArea.set_helper_text('Drop an object you want to find here')
        self.replaceDropArea.set_helper_text('Drop an object to replace with here')

    def set_tree(self, tree: QTreeWidget):
        """Set the tree widget to search."""
        self._tree = tree
        self._reset_results()

    def set_db_manager(self, db_manager):
        """Set the database manager for rule searches and replacements."""
        self._db_manager = db_manager

    def set_reload_callback(self, callback):
        """Set a callback to reload open rule set views after replacement."""
        self._reload_callback = callback

    def set_open_rule_set_ids_callback(self, callback):
        """Set a callback that returns the set of rule set IDs open in the MDI area."""
        self._get_open_rule_set_ids = callback

    def focus_input(self):
        """Focus the search input field."""
        self.findAttr.setFocus()
        self.findAttr.lineEdit().selectAll()

    @Slot()
    def find(self):
        """Start or continue a search."""
        find_obj_id = self.findDropArea.get_object_id()

        if find_obj_id is None:
            # Text-based search.
            text = self.findAttr.currentText()
            if not text:
                return
            # Add to history if it differs from the first item.
            if self.findAttr.count() == 0 or text != self.findAttr.itemText(0):
                if self.findAttr.count() >= _MAX_SEARCH_ITEMS:
                    self.findAttr.removeItem(_MAX_SEARCH_ITEMS - 1)
                self.findAttr.insertItem(0, text)

        self._find_next()

    @Slot(str)
    def findAttrChanged(self, _text=''):
        """Reset results when search parameters change."""
        self._reset_results()

    @Slot()
    def reset(self):
        """Clear search results (called on scope change or tree reload)."""
        self._reset_results()

    @Slot()
    def scopeChanged(self):
        """Persist scope selection to QSettings."""
        QSettings().setValue('Search/Scope', self.srScope.currentIndex())

    @Slot()
    def objectInserted(self):
        """Called when an object is dropped into the find drop area."""
        name = self.findDropArea.get_object_name() or ''
        self.findAttr.lineEdit().setText(name)
        self._reset_results()

    @Slot()
    def objectDeleted(self):
        """Called when the find drop area is cleared."""
        self.findAttr.lineEdit().clear()
        self._reset_results()

    @Slot()
    def replaceEnable(self):
        """Enable replace buttons when replace drop area has an object."""
        self.replaceButton.setEnabled(True)
        self.replaceAllButton.setEnabled(True)
        self.repNextButton.setEnabled(True)

    @Slot()
    def replaceDisable(self):
        """Disable replace buttons when replace drop area is cleared."""
        self.replaceButton.setEnabled(False)
        self.replaceAllButton.setEnabled(False)
        self.repNextButton.setEnabled(False)

    @Slot()
    def replace(self):
        """Replace the current match (if it is a rule element reference)."""
        if not self._validate_replace_object():
            return
        if not self._results or self._result_index == 0:
            return
        current = self._results[self._result_index - 1]
        if current.rule_id is not None:
            self._replace_current(current)

    @Slot()
    def replaceAll(self):
        """Replace all rule element matches in one undo step."""
        if not self._validate_replace_object():
            return

        find_obj_id = self.findDropArea.get_object_id()
        if find_obj_id is None:
            return

        new_id = self.replaceDropArea.get_object_id()
        if new_id is None:
            return

        # Collect all matching rule_elements.
        if self._db_manager is None:
            return

        count = 0
        with self._db_manager.session('Replace all') as session:
            rows = session.execute(
                sqlalchemy.select(
                    rule_elements.c.rule_id,
                    rule_elements.c.slot,
                    rule_elements.c.target_id,
                ).where(rule_elements.c.target_id == find_obj_id),
            ).all()

            for rule_id, slot, _target_id in rows:
                # Check for duplicate (new_id already in same rule+slot).
                dup = session.execute(
                    sqlalchemy.select(rule_elements.c.target_id).where(
                        rule_elements.c.rule_id == rule_id,
                        rule_elements.c.slot == slot,
                        rule_elements.c.target_id == new_id,
                    ),
                ).first()
                if dup is not None:
                    # Duplicate: just delete the old reference.
                    session.execute(
                        sqlalchemy.delete(rule_elements).where(
                            rule_elements.c.rule_id == rule_id,
                            rule_elements.c.slot == slot,
                            rule_elements.c.target_id == find_obj_id,
                        ),
                    )
                else:
                    session.execute(
                        sqlalchemy.update(rule_elements)
                        .where(
                            rule_elements.c.rule_id == rule_id,
                            rule_elements.c.slot == slot,
                            rule_elements.c.target_id == find_obj_id,
                        )
                        .values(target_id=new_id),
                    )
                count += 1

        if self._reload_callback is not None:
            self._reload_callback()
        self._reset_results()

        QMessageBox.information(
            self,
            'FirewallFabrik',
            self.tr(f'Replaced {count} reference(s).'),
        )

    @Slot()
    def replaceNext(self):
        """Replace current match, then find next."""
        self.replace()
        self._find_next()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Enter, Qt.Key.Key_Return):
            event.accept()
            self.find()
            return
        super().keyPressEvent(event)

    def _reset_results(self):
        self._results = []
        self._result_index = 0
        self._last_find_obj_id = None

    def _search_params_changed(self):
        """Return True if the current search params differ from last search."""
        find_obj_id = self.findDropArea.get_object_id()
        if find_obj_id is not None:
            return find_obj_id != self._last_find_obj_id

        text = self.findAttr.currentText()
        attr_idx = self.attribute.currentIndex()
        use_re = self.useRegexp.isChecked()
        return (
            text != self._last_search_text
            or attr_idx != self._last_attr_index
            or use_re != self._last_use_regexp
            or self._last_find_obj_id is not None
        )

    def _find_next(self):
        if self._tree is None:
            return

        # Rebuild results if params changed or results exhausted.
        if not self._results or self._search_params_changed():
            find_obj_id = self.findDropArea.get_object_id()
            self._last_find_obj_id = find_obj_id
            self._last_search_text = self.findAttr.currentText()
            self._last_attr_index = self.attribute.currentIndex()
            self._last_use_regexp = self.useRegexp.isChecked()
            self._results = self._find_all()
            self._result_index = 0

        if not self._results:
            QMessageBox.information(
                self,
                'FirewallFabrik',
                self.tr('No matching objects found.'),
            )
            return

        if self._result_index >= len(self._results):
            reply = QMessageBox.question(
                self,
                'FirewallFabrik',
                self.tr(
                    'Search hit the end of the results.\nContinue from the beginning?'
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._result_index = 0
            else:
                return

        result = self._results[self._result_index]
        self._result_index += 1
        self._show_result(result)

    def _find_all(self) -> list[_FindResult]:
        """Collect all matching items across tree and/or rules."""
        find_obj_id = self.findDropArea.get_object_id()
        scope = self.srScope.currentIndex()

        results: list[_FindResult] = []

        if find_obj_id is not None:
            # Object-based search.
            if scope in (0, 1):
                results.extend(self._find_in_tree(find_obj_id=find_obj_id))
            if scope in (1, 2):
                results.extend(self._find_in_rules(find_obj_id))
            elif scope == 3:
                if self._get_open_rule_set_ids is not None:
                    open_ids = self._get_open_rule_set_ids()
                else:
                    open_ids = set()
                if not open_ids:
                    return []
                results.extend(self._find_in_rules(find_obj_id, rule_set_ids=open_ids))
        else:
            # Text-based search (tree only).
            text = self.findAttr.currentText()
            if not text:
                return []
            if scope in (0, 1):
                results.extend(self._find_in_tree())

        return results

    def _find_in_tree(self, *, find_obj_id=None) -> list[_FindResult]:
        """Walk the tree and collect matching items."""
        if find_obj_id is not None:
            # Match by UUID.
            target = str(find_obj_id)
            results = []
            it = QTreeWidgetItemIterator(self._tree)
            while it.value():
                item = it.value()
                obj_id = item.data(0, Qt.ItemDataRole.UserRole)
                if obj_id == target:
                    results.append(_FindResult(tree_item=item))
                it += 1
            return results

        # Text-based search (existing logic).
        text = self.findAttr.currentText()
        if not text:
            return []

        attr_index = self.attribute.currentIndex()
        use_regexp = self.useRegexp.isChecked()

        pattern = None
        if use_regexp:
            try:
                pattern = re.compile(text, re.IGNORECASE)
            except re.error as exc:
                QMessageBox.warning(
                    self,
                    'FirewallFabrik',
                    self.tr(f'Invalid regular expression: {exc}'),
                )
                return []

        results = []
        it = QTreeWidgetItemIterator(self._tree)
        while it.value():
            item = it.value()
            if self._match_item(item, text, attr_index, use_regexp, pattern):
                results.append(_FindResult(tree_item=item))
            it += 1
        return results

    def _find_in_rules(self, find_obj_id, *, rule_set_ids=None) -> list[_FindResult]:
        """Search rule_elements for references to *find_obj_id*.

        When *rule_set_ids* is given, only rules belonging to those rule sets
        are considered (used for "Policy of the opened firewall" scope).
        """
        if self._db_manager is None:
            return []

        results = []
        with self._db_manager.session() as session:
            query = (
                sqlalchemy.select(
                    rule_elements.c.rule_id,
                    rule_elements.c.slot,
                    rule_elements.c.target_id,
                    Rule.rule_set_id,
                )
                .join(Rule, Rule.id == rule_elements.c.rule_id)
                .where(rule_elements.c.target_id == find_obj_id)
            )
            if rule_set_ids is not None:
                query = query.where(Rule.rule_set_id.in_(rule_set_ids))
            rows = session.execute(query).all()

            for rule_id, slot, target_id, rule_set_id in rows:
                results.append(
                    _FindResult(
                        rule_set_id=rule_set_id,
                        rule_id=rule_id,
                        slot=slot,
                        target_id=target_id,
                    )
                )
        return results

    def _match_item(self, item, text, attr_index, use_regexp, pattern):
        """Return True if *item* matches the current search criteria."""
        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        if obj_id is None:
            return False

        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''

        if attr_index == 0:
            target = item.text(0)
            return self._match_text(target, text, use_regexp, pattern)

        if attr_index == 1:
            if obj_type not in _ADDRESS_TYPES:
                return False
            target = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
            return self._match_text(target, text, use_regexp, pattern)

        if attr_index == 2:
            if obj_type not in _TCP_UDP_TYPES:
                return False
            target = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
            return self._match_text(target, text, use_regexp, pattern)

        if attr_index == 3:
            if obj_type not in _IP_SERVICE_TYPES:
                return False
            target = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
            return self._match_text(target, text, use_regexp, pattern)

        if attr_index == 4:
            if obj_type not in _ICMP_TYPES:
                return False
            target = item.data(0, Qt.ItemDataRole.UserRole + 3) or ''
            return self._match_text(target, text, use_regexp, pattern)

        return False

    @staticmethod
    def _match_text(target, text, use_regexp, pattern):
        """Case-insensitive substring (or regex) match."""
        if use_regexp:
            return pattern.search(target) is not None
        return text.lower() in target.lower()

    def _validate_replace_object(self):
        """Check that find and replace objects are valid and compatible."""
        if self.findDropArea.is_empty():
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('Drop an object into the find area first.'),
            )
            return False

        if self.replaceDropArea.is_empty():
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('Drop an object into the replace area first.'),
            )
            return False

        find_id = self.findDropArea.get_object_id()
        replace_id = self.replaceDropArea.get_object_id()
        if find_id == replace_id:
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('Find and replace objects must be different.'),
            )
            return False

        find_type = self.findDropArea.get_object_type() or ''
        replace_type = self.replaceDropArea.get_object_type() or ''

        find_is_addr = find_type in _ADDRESS_COMPATIBLE
        find_is_srv = find_type in _SERVICE_COMPATIBLE
        replace_is_addr = replace_type in _ADDRESS_COMPATIBLE
        replace_is_srv = replace_type in _SERVICE_COMPATIBLE

        if not ((find_is_addr and replace_is_addr) or (find_is_srv and replace_is_srv)):
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr(
                    f'Incompatible object types: {find_type} and {replace_type}.\n'
                    'Both must be address-like or both must be service-like.'
                ),
            )
            return False

        return True

    def _replace_current(self, result: _FindResult):
        """Replace a single rule element reference."""
        if self._db_manager is None:
            return

        new_id = self.replaceDropArea.get_object_id()
        if new_id is None or result.rule_id is None or result.slot is None:
            return

        find_obj_id = self.findDropArea.get_object_id()

        with self._db_manager.session('Replace object') as session:
            # Check for duplicate.
            dup = session.execute(
                sqlalchemy.select(rule_elements.c.target_id).where(
                    rule_elements.c.rule_id == result.rule_id,
                    rule_elements.c.slot == result.slot,
                    rule_elements.c.target_id == new_id,
                ),
            ).first()
            if dup is not None:
                # Duplicate: just delete the old reference.
                session.execute(
                    sqlalchemy.delete(rule_elements).where(
                        rule_elements.c.rule_id == result.rule_id,
                        rule_elements.c.slot == result.slot,
                        rule_elements.c.target_id == find_obj_id,
                    ),
                )
            else:
                session.execute(
                    sqlalchemy.update(rule_elements)
                    .where(
                        rule_elements.c.rule_id == result.rule_id,
                        rule_elements.c.slot == result.slot,
                        rule_elements.c.target_id == find_obj_id,
                    )
                    .values(target_id=new_id),
                )

        if self._reload_callback is not None:
            self._reload_callback()

    def _show_result(self, result: _FindResult):
        """Display a search result to the user."""
        if result.tree_item is not None:
            self._show_item(result.tree_item)
        elif result.rule_set_id is not None and result.rule_id is not None:
            self.navigate_to_rule.emit(
                str(result.rule_set_id),
                str(result.rule_id),
                result.slot or '',
            )

    def _show_item(self, item: QTreeWidgetItem):
        """Select and scroll to *item* in the tree, emit object_found."""
        parent = item.parent()
        while parent is not None:
            parent.setExpanded(True)
            parent = parent.parent()

        self._tree.setCurrentItem(item)
        self._tree.scrollToItem(item)

        obj_id = item.data(0, Qt.ItemDataRole.UserRole)
        obj_type = item.data(0, Qt.ItemDataRole.UserRole + 1)
        if obj_id and obj_type:
            self.object_found.emit(obj_id, obj_type)
