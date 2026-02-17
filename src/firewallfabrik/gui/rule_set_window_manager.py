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

"""MDI sub-window management for rule set views extracted from FWWindow.

Handles opening, reusing, state persistence, title updates, and querying
of MDI sub-windows that display Policy / NAT / Routing rule sets.
"""

import json
import logging
import uuid
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QModelIndex, QObject, QSettings, Qt, Signal, Slot
from PySide6.QtGui import QActionGroup, QIcon, QKeySequence
from PySide6.QtWidgets import QMdiSubWindow

from firewallfabrik.core.objects import Address, Interface, RuleSet
from firewallfabrik.gui.policy_model import PolicyTreeModel
from firewallfabrik.gui.policy_view import PolicyView, RuleSetPanel

logger = logging.getLogger(__name__)


class RuleSetWindowManager(QObject):
    """Manages MDI sub-windows for rule set views."""

    firewall_modified = Signal(object)  # UUID forwarded from PolicyTreeModel

    _STATE_FILE_NAME = 'last_object_state.json'

    def __init__(self, db_manager, mdi_area, object_tree, window_menu, parent=None):
        """Initialise the rule set window manager.

        Args:
            db_manager: DatabaseManager instance.
            mdi_area: QMdiArea widget (``self.m_space`` on FWWindow).
            object_tree: ObjectTree instance.
            window_menu: QMenu for the Window menu.
            parent: QObject parent (typically FWWindow).
        """
        super().__init__(parent)
        self._db_manager = db_manager
        self._mdi_area = mdi_area
        self._object_tree = object_tree
        self._window_menu = window_menu
        self._display_file = None

    # --- Lifecycle ---

    def set_db_manager(self, db_manager):
        """Replace the database manager (called on file new/open/close)."""
        self._db_manager = db_manager

    def set_display_file(self, display_file):
        """Set the display file path for state persistence."""
        self._display_file = display_file

    # --- MDI window management ---

    @Slot(str, str, str, str)
    def open_rule_set(self, rule_set_id, fw_name, rs_name, rs_type='Policy'):
        """Open a rule set in a new MDI sub-window (triggered by tree double-click)."""
        rs_uuid = uuid.UUID(rule_set_id)

        # Reuse an existing sub-window for this rule set if one is open.
        for sub in self._mdi_area.subWindowList():
            if getattr(sub, '_fwf_rule_set_id', None) == rs_uuid:
                self._mdi_area.setActiveSubWindow(sub)
                return

        model = PolicyTreeModel(
            self._db_manager,
            rs_uuid,
            rule_set_type=rs_type,
            object_name=fw_name,
        )
        model.firewall_modified.connect(self.firewall_modified)
        title = f'{fw_name} / {rs_name}'
        panel = RuleSetPanel()
        panel.set_title(title)
        panel.policy_view.setModel(model)

        sub = QMdiSubWindow()
        sub.setWidget(panel)
        sub.setWindowTitle(title)
        sub.setWindowIcon(QIcon())
        sub.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        sub._fwf_rule_set_id = rs_uuid
        sub._fwf_device_id = None  # set below if available
        self._mdi_area.addSubWindow(sub)
        sub.showMaximized()

        # Store the owning device ID for ensure_parent_rule_set_open().
        try:
            with self._db_manager.session() as sess:
                rs = sess.get(RuleSet, rs_uuid)
                if rs is not None:
                    sub._fwf_device_id = rs.device_id
        except Exception:
            pass

    @Slot(str, str, str)
    def navigate_to_rule_match(self, rule_set_id, rule_id, slot):
        """Navigate to a rule element match in a policy view."""
        rs_uuid = uuid.UUID(rule_set_id)
        r_uuid = uuid.UUID(rule_id)

        # Look for an existing sub-window with this rule set.
        for sub in self._mdi_area.subWindowList():
            view = self.policy_view_from_widget(sub.widget())
            if (
                view is not None
                and isinstance(view.model(), PolicyTreeModel)
                and view.model().rule_set_id == rs_uuid
            ):
                self._mdi_area.setActiveSubWindow(sub)
                self._scroll_to_rule(view, view.model(), r_uuid, slot)
                return

        # Open a new sub-window for this rule set.
        with self._db_manager.session() as session:
            rs = session.get(RuleSet, rs_uuid)
            if rs is None:
                return
            fw_name = rs.device.name if rs.device else ''
            rs_name = rs.name
            rs_type = rs.type

        model = PolicyTreeModel(
            self._db_manager,
            rs_uuid,
            rule_set_type=rs_type,
        )
        model.firewall_modified.connect(self.firewall_modified)
        title = f'{fw_name} / {rs_name}'
        panel = RuleSetPanel()
        panel.set_title(title)
        panel.policy_view.setModel(model)

        sub = QMdiSubWindow()
        sub.setWidget(panel)
        sub.setWindowTitle(title)
        sub.setWindowIcon(QIcon())
        sub.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._mdi_area.addSubWindow(sub)
        sub.showMaximized()

        self._scroll_to_rule(panel.policy_view, model, r_uuid, slot)

    def ensure_parent_rule_set_open(self, obj, obj_type):
        """Open the parent firewall's policy if no rule set is shown.

        When the user double-clicks an object that belongs to a Firewall
        or Cluster (e.g. an interface address), fwbuilder automatically
        opens the device's policy rules in the main area.  This method
        replicates that by walking up the ORM relationships to find the
        owning device and opening its first Policy rule set.
        """
        device = None
        if isinstance(obj, Address) and obj.interface_id is not None:
            iface = obj.interface
            if iface is not None:
                device = iface.device
        elif isinstance(obj, Interface):
            device = obj.device

        if device is None or device.type not in ('Cluster', 'Firewall'):
            return

        # Check if any MDI sub-window already shows this device's rules.
        device_id = device.id
        for sub in self._mdi_area.subWindowList():
            if getattr(sub, '_fwf_device_id', None) == device_id:
                return

        # Find the first Policy rule set for this device.
        policy_rs = None
        for rs in device.rule_sets:
            if rs.type == 'Policy':
                policy_rs = rs
                break
        if policy_rs is None:
            return

        self.open_rule_set(
            str(policy_rs.id), device.name, policy_rs.name, policy_rs.type
        )

    def open_first_firewall_policy(self):
        """Open the Policy rule set of the first writable Firewall.

        Walks the already-populated object tree to find the first
        non-read-only Firewall item and opens its Policy child as an
        MDI sub-window.
        """
        tree = self._object_tree._tree
        root = tree.invisibleRootItem()
        for lib_idx in range(root.childCount()):
            lib_item = root.child(lib_idx)
            # Skip read-only libraries (Standard, etc.).
            if lib_item.data(0, Qt.ItemDataRole.UserRole + 5):
                continue
            self._find_and_open_policy(lib_item)
            if self._mdi_area.subWindowList():
                return

    def _find_and_open_policy(self, parent_item):
        """Recursively search *parent_item* for the first Firewall with a Policy child."""
        for i in range(parent_item.childCount()):
            child = parent_item.child(i)
            child_type = child.data(0, Qt.ItemDataRole.UserRole + 1) or ''
            if child_type in ('Firewall', 'Cluster'):
                fw_name = child.text(0)
                for j in range(child.childCount()):
                    rs_item = child.child(j)
                    rs_type = rs_item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
                    if rs_type == 'Policy':
                        rs_id = rs_item.data(0, Qt.ItemDataRole.UserRole)
                        rs_name = rs_item.text(0)
                        self.open_rule_set(rs_id, fw_name, rs_name, rs_type)
                        # Select the Policy item in the tree so the user
                        # sees which firewall's rules are displayed.
                        parent = rs_item.parent()
                        while parent:
                            parent.setExpanded(True)
                            parent = parent.parent()
                        self._object_tree._tree.scrollToItem(rs_item)
                        self._object_tree._tree.setCurrentItem(rs_item)
                        return
            else:
                # Recurse into group folders (e.g. user-created subfolders).
                self._find_and_open_policy(child)
                if self._mdi_area.subWindowList():
                    return

    def open_rule_set_by_title(self, title):
        """Find the rule set matching *title* (``fw_name / rs_name``) and open it.

        The title format matches ``open_rule_set``'s
        ``f'{fw_name} / {rs_name}'``.
        """
        parts = title.split(' / ', 1)
        if len(parts) != 2:
            return
        fw_name, rs_name = parts

        from PySide6.QtWidgets import QTreeWidgetItemIterator

        tree = self._object_tree._tree
        it = QTreeWidgetItemIterator(tree)
        while it.value():
            item = it.value()
            it += 1
            item_type = item.data(0, Qt.ItemDataRole.UserRole + 1) or ''
            if item_type not in ('NAT', 'Policy', 'Routing'):
                continue
            if item.text(0) != rs_name:
                continue
            fw_item = item.parent()
            if fw_item is None or fw_item.text(0) != fw_name:
                continue
            rs_id = item.data(0, Qt.ItemDataRole.UserRole)
            self.open_rule_set(rs_id, fw_name, rs_name, item_type)
            # Select the rule set in the tree.
            parent = item.parent()
            while parent:
                parent.setExpanded(True)
                parent = parent.parent()
            tree.scrollToItem(item)
            tree.setCurrentItem(item)
            return

    # --- State persistence ---

    def _state_file_path(self):
        """Return the path to the JSON state file in the config directory."""
        ini_path = QSettings().fileName()
        return Path(ini_path).parent / self._STATE_FILE_NAME

    def save_state(self):
        """Save the last active MDI ruleset (by name, not UUID).

        UUIDs are regenerated on every .fwb import, so we save the
        sub-window title (``fw_name / rs_name``) which is stable.
        """
        if not self._display_file:
            return
        file_key = str(self._display_file)

        state = {}

        # Active MDI ruleset — save by window title (stable across imports).
        active_sub = self._mdi_area.activeSubWindow()
        if active_sub is not None:
            state['window_title'] = active_sub.windowTitle()

        state_path = self._state_file_path()
        all_states = self._read_state_file(state_path)
        all_states[file_key] = state
        try:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(all_states, indent=2))
        except OSError:
            logger.debug('Could not write %s', state_path)

    def restore_state(self, file_key):
        """Restore the last active MDI ruleset by matching the window title."""
        all_states = self._read_state_file(self._state_file_path())
        state = all_states.get(file_key, {})

        saved_title = state.get('window_title', '')
        if saved_title:
            self.open_rule_set_by_title(saved_title)

    @staticmethod
    def _read_state_file(path):
        """Read ``{file_key: {state}}`` from *path*, returning {} on error."""
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError, ValueError):
            return {}

    # --- Query helpers ---

    @staticmethod
    def policy_view_from_widget(widget):
        """Extract a :class:`PolicyView` from a sub-window widget."""
        if isinstance(widget, RuleSetPanel):
            return widget.policy_view
        if isinstance(widget, PolicyView):
            return widget
        return None

    def active_policy_view(self):
        """Return the active :class:`PolicyView`, or *None*."""
        sub = self._mdi_area.activeSubWindow()
        if sub is not None:
            return self.policy_view_from_widget(sub.widget())
        return None

    def reload_views(self):
        """Reload all open PolicyTreeModel views (after replace or undo/redo)."""
        for sub in self._mdi_area.subWindowList():
            view = self.policy_view_from_widget(sub.widget())
            if view is not None and isinstance(view.model(), PolicyTreeModel):
                view.model().reload()

    def get_open_rule_set_ids(self) -> set[uuid.UUID]:
        """Return the set of rule set IDs currently open in MDI sub-windows."""
        ids = set()
        for sub in self._mdi_area.subWindowList():
            view = self.policy_view_from_widget(sub.widget())
            if view is not None and isinstance(view.model(), PolicyTreeModel):
                ids.add(view.model().rule_set_id)
        return ids

    def get_active_firewall_rule_set_ids(self) -> set[uuid.UUID]:
        """Return all rule set IDs belonging to the active firewall.

        Unlike :meth:`get_open_rule_set_ids`, this returns **all** rule
        sets (Policy, NAT, Routing) of the firewall whose rule set is
        currently active — matching fwbuilder's scope 3 behaviour which
        uses ``getCurrentRuleSet()->getParent()``.
        """
        sub = self._mdi_area.activeSubWindow()
        if sub is None:
            return set()
        device_id = getattr(sub, '_fwf_device_id', None)
        if device_id is None:
            return set()
        ids = set()
        try:
            with self._db_manager.session() as session:
                rows = session.execute(
                    sqlalchemy.select(RuleSet.id).where(
                        RuleSet.device_id == device_id,
                    ),
                ).all()
                for (rs_id,) in rows:
                    ids.add(rs_id)
        except Exception:
            logger.exception('Failed to query rule sets for active firewall')
        return ids

    # --- Title updates ---

    def update_titles(self, fw_obj):
        """Update MDI sub-window titles after a firewall rename."""
        fw_id = fw_obj.id
        fw_name = fw_obj.name
        for sub in self._mdi_area.subWindowList():
            if getattr(sub, '_fwf_device_id', None) != fw_id:
                continue
            rs_uuid = getattr(sub, '_fwf_rule_set_id', None)
            if rs_uuid is None:
                continue
            try:
                with self._db_manager.session() as sess:
                    rs = sess.get(RuleSet, rs_uuid)
                    rs_name = rs.name if rs else '?'
            except Exception:
                rs_name = '?'
            title = f'{fw_name} / {rs_name}'
            sub.setWindowTitle(title)
            panel = sub.widget()
            if isinstance(panel, RuleSetPanel):
                panel.set_title(title)

    # --- Window menu ---

    def prepare_windows_menu(self):
        """Dynamically rebuild the Window menu before it opens.

        Mirrors fwbuilder's ``FWWindow::prepareWindowsMenu()``
        (FWWindow.cpp:974).
        """
        menu = self._window_menu
        menu.clear()

        sub_windows = self._mdi_area.subWindowList()
        has_subs = len(sub_windows) > 0
        active_sub = self._mdi_area.activeSubWindow()

        act_close = menu.addAction('Close')
        act_close.setShortcut(QKeySequence('Ctrl+F4'))
        act_close.setEnabled(has_subs)
        act_close.triggered.connect(self._mdi_area.closeActiveSubWindow)

        act_close_all = menu.addAction('Close All')
        act_close_all.setEnabled(has_subs)
        act_close_all.triggered.connect(self._mdi_area.closeAllSubWindows)

        act_tile = menu.addAction('Tile')
        act_tile.setEnabled(has_subs)
        act_tile.triggered.connect(self._mdi_area.tileSubWindows)

        act_cascade = menu.addAction('Cascade')
        act_cascade.setEnabled(has_subs)
        act_cascade.triggered.connect(self._mdi_area.cascadeSubWindows)

        act_next = menu.addAction('Next')
        act_next.setEnabled(has_subs)
        act_next.triggered.connect(self._mdi_area.activateNextSubWindow)

        act_prev = menu.addAction('Previous')
        act_prev.setEnabled(has_subs)
        act_prev.triggered.connect(self._mdi_area.activatePreviousSubWindow)

        menu.addSeparator()

        act_minimize = menu.addAction('Minimize')
        act_minimize.setEnabled(active_sub is not None)
        act_minimize.triggered.connect(self.minimize_active)

        act_maximize = menu.addAction('Maximize')
        act_maximize.setEnabled(active_sub is not None)
        act_maximize.triggered.connect(self.maximize_active)

        menu.addSeparator()

        if has_subs:
            group = QActionGroup(menu)
            group.setExclusive(True)
            for sub in sub_windows:
                action = menu.addAction(sub.windowTitle())
                action.setCheckable(True)
                action.setChecked(sub is active_sub)
                group.addAction(action)
                action.triggered.connect(
                    lambda _checked, s=sub: self._mdi_area.setActiveSubWindow(s),
                )

    def minimize_active(self):
        """Minimize the active MDI sub-window."""
        sub = self._mdi_area.activeSubWindow()
        if sub is not None:
            sub.showMinimized()

    def maximize_active(self):
        """Maximize the active MDI sub-window."""
        sub = self._mdi_area.activeSubWindow()
        if sub is not None:
            sub.showMaximized()

    def close_all(self):
        """Close all MDI sub-windows."""
        self._mdi_area.closeAllSubWindows()

    # --- Internal helpers ---

    @staticmethod
    def _scroll_to_rule(view, model, rule_id, slot):
        """Scroll *view* to the rule node matching *rule_id*."""
        col = model.slot_to_col.get(slot, 0) if slot else 0

        def _walk(parent_index, row_count):
            for row in range(row_count):
                idx = model.index(row, col, parent_index)
                rd = model.get_row_data(idx)
                if rd is not None and rd.rule_id == rule_id:
                    if col:
                        view.set_highlight(rule_id, col)
                    view.setCurrentIndex(idx)
                    view.scrollTo(idx)
                    return True
                # Check children (group nodes).
                child_count = model.rowCount(idx)
                if child_count > 0 and _walk(idx, child_count):
                    return True
            return False

        _walk(QModelIndex(), model.rowCount(QModelIndex()))
