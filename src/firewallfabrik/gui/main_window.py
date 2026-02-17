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

import importlib.resources
import logging
import subprocess
import traceback
import uuid
from pathlib import Path

import sqlalchemy
import sqlalchemy.exc
from PySide6.QtCore import (
    QByteArray,
    QResource,
    QSettings,
    Qt,
    QTimer,
    QUrl,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QCursor,
    QDesktopServices,
    QGuiApplication,
    QIcon,
    QKeySequence,
)
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QVBoxLayout,
)

from firewallfabrik import __version__
from firewallfabrik.core import DatabaseManager, duplicate_object_name
from firewallfabrik.core._util import escape_obj_name
from firewallfabrik.core.objects import (
    Address,
    Firewall,
    FWObjectDatabase,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    Rule,
    RuleSet,
    Service,
    group_membership,
    rule_elements,
)
from firewallfabrik.gui.about_dialog import AboutDialog
from firewallfabrik.gui.clipboard_router import ClipboardRouter
from firewallfabrik.gui.debug_dialog import DebugDialog
from firewallfabrik.gui.editor_manager import EditorManager, EditorManagerUI
from firewallfabrik.gui.find_panel import FindPanel
from firewallfabrik.gui.find_where_used_panel import FindWhereUsedPanel
from firewallfabrik.gui.object_tree import (
    ICON_MAP,
    ObjectTree,
    create_library_folder_structure,
)
from firewallfabrik.gui.preferences_dialog import PreferencesDialog
from firewallfabrik.gui.rule_set_window_manager import RuleSetWindowManager
from firewallfabrik.gui.ui_loader import FWFUiLoader

logger = logging.getLogger(__name__)

_DEFAULT_WIDTH = 1024
_DEFAULT_HEIGHT = 768

# Menu entries for the "New Object" popup (toolbar / Object menu / Ctrl+N).
# Order matches fwbuilder's buildNewObjectMenu() exactly:
#   1. Library
#   2. getObjectTypes()  — devices first, then addresses, then groups
#   3. getServiceTypes() — individual services, then ServiceGroup last
#   4. Interval
_NEW_OBJECT_MENU_ENTRIES = (
    ('Library', 'New Library'),
    None,  # separator
    # -- getObjectTypes() --
    ('Firewall', 'New Firewall'),
    ('Cluster', 'New Cluster'),
    ('Host', 'New Host'),
    ('Network', 'New Network'),
    ('NetworkIPv6', 'New Network IPv6'),
    ('IPv4', 'New Address'),
    ('IPv6', 'New Address IPv6'),
    ('DNSName', 'New DNS Name'),
    ('AddressTable', 'New Address Table'),
    ('AddressRange', 'New Address Range'),
    ('ObjectGroup', 'New Object Group'),
    ('DynamicGroup', 'New Dynamic Group'),
    None,  # separator
    # -- getServiceTypes() --
    ('CustomService', 'New Custom Service'),
    ('IPService', 'New IP Service'),
    ('ICMPService', 'New ICMP Service'),
    ('ICMP6Service', 'New ICMP6 Service'),
    ('TCPService', 'New TCP Service'),
    ('UDPService', 'New UDP Service'),
    ('TagService', 'New TagService'),
    ('UserService', 'New User Service'),
    ('ServiceGroup', 'New Service Group'),
    None,  # separator
    ('Interval', 'New Time Interval'),
)


FILE_FILTERS = 'FirewallFabrik Files *.fwf (*.fwf);;Firewall Builder Files *.fwb (*.fwb);;All Files (*)'
_MAX_RECENT_FILES = 20


def _build_library_path_map(session, library):
    """Build a ``{tree_path: UUID}`` map for every object in *library*.

    The paths use the same format as the YAML reader's ``ref_index`` so
    that old UUIDs can be matched to new ones by path after a re-import.
    """
    lib_path = f'Library:{escape_obj_name(library.name)}'
    path_map = {}

    # 1. Groups (hierarchical via parent_group_id).
    all_groups = (
        session.scalars(
            sqlalchemy.select(Group).where(Group.library_id == library.id),
        )
        .unique()
        .all()
    )
    group_by_id = {g.id: g for g in all_groups}
    group_paths = {}

    def _group_path(g):
        if g.id in group_paths:
            return group_paths[g.id]
        if g.parent_group_id is None or g.parent_group_id not in group_by_id:
            p = f'{lib_path}/{g.type}:{escape_obj_name(g.name)}'
        else:
            parent_p = _group_path(group_by_id[g.parent_group_id])
            p = f'{parent_p}/{g.type}:{escape_obj_name(g.name)}'
        group_paths[g.id] = p
        path_map[p] = g.id
        return p

    for g in all_groups:
        _group_path(g)

    # 2. Services.
    for svc in session.scalars(
        sqlalchemy.select(Service).where(Service.library_id == library.id),
    ).all():
        parent = group_paths.get(svc.group_id, lib_path)
        path_map[f'{parent}/{svc.type}:{escape_obj_name(svc.name)}'] = svc.id

    # 3. Addresses (library-owned; interface-owned handled under devices).
    for addr in session.scalars(
        sqlalchemy.select(Address).where(Address.library_id == library.id),
    ).all():
        parent = group_paths.get(addr.group_id, lib_path)
        path_map[f'{parent}/{addr.type}:{escape_obj_name(addr.name)}'] = addr.id

    # 4. Intervals.
    for itv in session.scalars(
        sqlalchemy.select(Interval).where(Interval.library_id == library.id),
    ).all():
        parent = group_paths.get(itv.group_id, lib_path)
        path_map[f'{parent}/Interval:{escape_obj_name(itv.name)}'] = itv.id

    # 5. Devices + interfaces + interface addresses.
    for dev in (
        session.scalars(
            sqlalchemy.select(Host).where(Host.library_id == library.id),
        )
        .unique()
        .all()
    ):
        parent = group_paths.get(dev.group_id, lib_path)
        dev_path = f'{parent}/{dev.type}:{escape_obj_name(dev.name)}'
        path_map[dev_path] = dev.id

        def _walk_ifaces(ifaces, parent_iface_path):
            for iface in ifaces:
                iface_path = (
                    f'{parent_iface_path}/Interface:{escape_obj_name(iface.name)}'
                )
                path_map[iface_path] = iface.id
                for addr in iface.addresses:
                    path_map[
                        f'{iface_path}/{addr.type}:{escape_obj_name(addr.name)}'
                    ] = addr.id
                _walk_ifaces(iface.sub_interfaces, iface_path)

        _walk_ifaces(dev.interfaces, dev_path)

    return path_map


class FWWindow(QMainWindow):
    """Main application window, equivalent to FWWindow in the C++ codebase."""

    def __init__(self):
        super().__init__()

        ui_path = Path(__file__).resolve().parent / 'ui'
        self._register_resources(ui_path)

        ui_path = ui_path / 'FWBMainWindow_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._closing = False
        self._current_file = None
        self._db_manager = DatabaseManager()

        self.setWindowTitle(f'FirewallFabrik {__version__}')
        self.setWindowIcon(QIcon(':/Icons/FirewallFabrik/scalable'))
        self.newObjectAction.setEnabled(False)

        # Attach a menu to the "New Object" action so the toolbar button
        # shows a dropdown arrow (matching fwbuilder).  The menu is
        # populated dynamically via aboutToShow.
        self._new_object_menu = QMenu(self)
        self._new_object_menu.aboutToShow.connect(self._populate_new_object_menu)
        self.newObjectAction.setMenu(self._new_object_menu)

        # Object tree + splitter layout
        self._object_tree = ObjectTree()
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self.gridLayout_4.removeWidget(self.m_space)
        self._splitter.addWidget(self._object_tree)
        self._splitter.addWidget(self.m_space)
        self._splitter.setSizes([250, 800])
        self.gridLayout_4.addWidget(self._splitter, 0, 0)

        # Create RuleSetWindowManager — handles MDI sub-window lifecycle.
        self._rs_mgr = RuleSetWindowManager(
            self._db_manager,
            self.m_space,
            self._object_tree,
            self.menuWindow,
            parent=self,
        )
        self._rs_mgr.firewall_modified.connect(self._on_firewall_modified)
        self._object_tree.rule_set_activated.connect(self._rs_mgr.open_rule_set)
        self._object_tree.object_activated.connect(self._open_object_editor)
        # Use a queued connection so tree_changed.emit() returns
        # immediately without calling _on_tree_changed synchronously.
        # This lets the emitting handler finish and release all local
        # QTreeWidgetItem references before populate() → clear()
        # destroys the items (avoiding a Shiboken setParent segfault).
        self._object_tree.tree_changed.connect(
            self._on_tree_changed, Qt.ConnectionType.QueuedConnection
        )
        self._object_tree.find_requested.connect(self._on_find_from_tree)
        self._object_tree.where_used_requested.connect(self._on_where_used_from_tree)
        self._object_tree.compile_requested.connect(self.compile)
        self._object_tree.install_requested.connect(self.install)
        self._object_tree.set_db_manager(self._db_manager)

        # Clipboard routing (copy/cut/paste/delete based on focus).
        self._clipboard = ClipboardRouter(
            self._object_tree,
            self._rs_mgr.active_policy_view,
        )

        editor_map = {
            'AddressRange': self.w_AddressRangeDialog,
            'AddressTable': self.w_AddressTableDialog,
            'Cluster': self.w_FirewallDialog,
            'CustomService': self.w_CustomServiceDialog,
            'DNSName': self.w_DNSNameDialog,
            'DynamicGroup': self.w_DynamicGroupDialog,
            'Firewall': self.w_FirewallDialog,
            'Host': self.w_HostDialog,
            'ICMP6Service': self.w_ICMP6ServiceDialog,
            'ICMPService': self.w_ICMPServiceDialog,
            'IPService': self.w_IPServiceDialog,
            'IPv4': self.w_IPv4Dialog,
            'IPv6': self.w_IPv6Dialog,
            'Interface': self.w_InterfaceDialog,
            'Interval': self.w_TimeDialog,
            'IntervalGroup': self.w_IntervalGroupDialog,
            'Library': self.w_LibraryDialog,
            'NAT': self.w_NATDialog,
            'Network': self.w_NetworkDialog,
            'NetworkIPv6': self.w_NetworkDialogIPv6,
            'ObjectGroup': self.w_ObjectGroupDialog,
            'PhysAddress': self.w_PhysicalAddressDialog,
            'Policy': self.w_PolicyDialog,
            'Routing': self.w_RoutingDialog,
            'ServiceGroup': self.w_ServiceGroupDialog,
            'TCPService': self.w_TCPServiceDialog,
            'TagService': self.w_TagServiceDialog,
            'UDPService': self.w_UDPServiceDialog,
            'UserService': self.w_UserDialog,
        }

        # Blank-dialog label for "Any" object messages.
        blank_label = QLabel(self.w_BlankDialog)
        blank_label.setWordWrap(True)
        blank_label.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
        )
        blank_label.setContentsMargins(10, 10, 10, 10)
        QVBoxLayout(self.w_BlankDialog).addWidget(blank_label)

        # Create EditorManager — handles editor open/save/close lifecycle.
        ui_refs = EditorManagerUI(
            actions_dialog=self.w_ActionsDialog,
            blank_dialog=self.w_BlankDialog,
            comment_panel=self.w_CommentEditorPanel,
            dock=self.editorDockWidget,
            editor_action=self.actionEditor_panel,
            get_display_file=lambda: (
                getattr(self, '_display_file', None) or self._current_file
            ),
            icon=self.objectTypeIcon,
            metric_editor=self.w_MetricEditorPanel,
            nat_rule_options=self.w_NATRuleOptionsDialog,
            routing_rule_options=self.w_RoutingRuleOptionsDialog,
            rule_options=self.w_RuleOptionsDialog,
            stack=self.objectEditorStack,
            tab_widget=self.editorPanelTabWidget,
        )
        self._editor_mgr = EditorManager(
            self._db_manager,
            editor_map,
            ui_refs,
            blank_label,
            parent=self,
        )
        self._editor_mgr.connect_dialogs()
        self._editor_mgr.object_saved.connect(self._on_editor_object_saved)
        self._editor_mgr.mdi_titles_changed.connect(self._rs_mgr.update_titles)
        self._editor_mgr.editor_opened.connect(
            lambda obj, t: self._rs_mgr.ensure_parent_rule_set_open(obj, t),
        )

        # Connect "Create new object and add to group" from group dialogs.
        from firewallfabrik.gui.dynamic_group_dialog import DynamicGroupDialog
        from firewallfabrik.gui.group_dialog import GroupObjectDialog

        for widget in set(editor_map.values()):
            if isinstance(widget, DynamicGroupDialog):
                widget.navigate_to_object.connect(self._open_object_editor)
            if isinstance(widget, GroupObjectDialog):
                widget.member_create_requested.connect(self._on_create_group_member)

        # Find panel — embedded in the "Find" tab of the editor dock.
        self._find_panel = FindPanel()
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_reload_callback(self._rs_mgr.reload_views)
        self._find_panel.set_open_rule_set_ids_callback(
            self._rs_mgr.get_active_firewall_rule_set_ids
        )
        self.find_panel.layout().addWidget(self._find_panel)
        self._find_panel.object_found.connect(self._open_object_editor)
        self._find_panel.navigate_to_rule.connect(self._rs_mgr.navigate_to_rule_match)
        self.findAction.triggered.connect(self._show_find_panel)

        # Where Used panel — embedded in the "Where Used" tab.
        self._where_used_panel = FindWhereUsedPanel()
        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.set_db_manager(self._db_manager)
        self.where_used_panel.layout().addWidget(self._where_used_panel)
        self._where_used_panel.object_found.connect(self._open_object_editor)
        self._where_used_panel.navigate_to_rule.connect(
            self._rs_mgr.navigate_to_rule_match
        )

        # Undo / redo actions in the Edit menu.
        self._undo_action = QAction('&Undo', self)
        self._undo_action.setShortcut(QKeySequence('Ctrl+Z'))
        self._undo_action.setEnabled(False)
        self._undo_action.triggered.connect(self._do_undo)
        self._redo_action = QAction('&Redo', self)
        self._redo_action.setShortcut(QKeySequence('Ctrl+Y'))
        self._redo_action.setEnabled(False)
        self._redo_action.triggered.connect(self._do_redo)
        first_action = self.editMenu.actions()[0] if self.editMenu.actions() else None
        self.editMenu.insertAction(first_action, self._undo_action)
        self.editMenu.insertAction(first_action, self._redo_action)
        # Register on the main window so shortcuts work regardless of focus.
        self.addAction(self._undo_action)
        self.addAction(self._redo_action)

        # Clipboard and delete actions — route based on focus.
        # NOTE: editCopyAction, editCutAction, editPasteAction, and
        # editDeleteAction are already connected to their slots via the
        # .ui file's <connections> section.  Do NOT add .connect() calls
        # here — that would fire each slot twice per keypress.
        self.editDeleteAction.setShortcut(QKeySequence.StandardKey.Delete)

        # History list and callback.
        self.undoView.currentRowChanged.connect(self._on_undo_list_clicked)
        self._db_manager.on_history_changed = self._on_history_changed

        self._prepare_recent_menu()
        self.menuWindow.aboutToShow.connect(self._rs_mgr.prepare_windows_menu)
        self._restore_view_state()
        self._start_maximized = False
        self._restore_geometry()

        # Connect *after* restoring state so that restoreState() toggling
        # dock visibility during init doesn't overwrite saved settings.
        self.editorDockWidget.visibilityChanged.connect(
            self._on_editor_visibility_changed
        )
        self.undoDockWidget.visibilityChanged.connect(self._on_undo_visibility_changed)

        # Hide panels until a file is loaded — block signals so the
        # visibility-changed slots don't overwrite saved QSettings.
        self.editorDockWidget.blockSignals(True)
        self.undoDockWidget.blockSignals(True)
        self._apply_no_file_state()
        self.editorDockWidget.blockSignals(False)
        self.undoDockWidget.blockSignals(False)

    def showEvent(self, event):
        super().showEvent(event)
        if self._start_maximized:
            self._start_maximized = False
            # Defer maximize so Wayland has finished mapping the window.
            QTimer.singleShot(0, self.showMaximized)

    def closeEvent(self, event):
        if not self._save_if_modified():
            event.ignore()
            return
        # Save tree state for the current file before closing.
        display = getattr(self, '_display_file', None)
        if display:
            self._object_tree.save_tree_state(str(display))
            self._rs_mgr.save_state()
        self._closing = True
        settings = QSettings()
        # Capture dock visibility *before* saveState() / destruction can
        # change it.  These explicit keys are what _restore_view_state()
        # reads after restoreState().  Only save when a file was loaded;
        # otherwise the hidden-by-default state would overwrite the
        # user's saved preferences.
        if self._current_file is not None:
            settings.setValue('View/EditorPanel', self.editorDockWidget.isVisible())
            settings.setValue('View/UndoStack', self.undoDockWidget.isVisible())
        # Save normal (non-maximized) geometry so restore works both ways.
        if not self.isMaximized():
            settings.setValue('Window/geometry', self.saveGeometry())
        settings.setValue('Window/maximized', self.isMaximized())
        settings.setValue('Window/state', self.saveState())
        settings.setValue('Window/splitter', self._splitter.saveState())
        super().closeEvent(event)

    def _restore_geometry(self):
        """Restore saved window geometry, falling back to centered default."""
        settings = QSettings()
        geometry = settings.value('Window/geometry', type=QByteArray)
        if geometry and self.restoreGeometry(geometry):
            # Verify the restored rect overlaps at least one screen.
            rect = self.geometry()
            for screen in QGuiApplication.screens():
                if screen.availableGeometry().intersects(rect):
                    self._start_maximized = settings.value(
                        'Window/maximized',
                        False,
                        type=bool,
                    )
                    return
        self.resize(_DEFAULT_WIDTH, _DEFAULT_HEIGHT)
        screen = QGuiApplication.primaryScreen()
        if screen:
            center = screen.availableGeometry().center()
            frame = self.frameGeometry()
            frame.moveCenter(center)
            self.move(frame.topLeft())
        self._start_maximized = settings.value('Window/maximized', False, type=bool)

    @staticmethod
    def _register_resources(ui_path):
        """Compile MainRes.qrc to a binary .rcc (if needed) and register it."""
        qrc = ui_path / 'MainRes.qrc'
        rcc = ui_path / 'MainRes.rcc'
        if not rcc.exists() or rcc.stat().st_mtime < qrc.stat().st_mtime:
            try:
                result = subprocess.run(
                    ['pyside6-rcc', '--binary', str(qrc), '-o', str(rcc)],
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError:
                QMessageBox.critical(
                    None,
                    'FirewallFabrik',
                    QMainWindow.tr(
                        'pyside6-rcc was not found.\n\n'
                        'Install the PySide6 tools package and try again.'
                    ),
                )
                raise SystemExit(1) from None
            if result.returncode != 0:
                QMessageBox.critical(
                    None,
                    'FirewallFabrik',
                    QMainWindow.tr('Failed to compile Qt resources.\n\n')
                    + result.stderr.strip(),
                )
                raise SystemExit(1) from None
        QResource.registerResource(str(rcc))

    def _restore_view_state(self):
        """Restore panel visibility and layout from QSettings."""
        settings = QSettings()

        # Restore dock widget / toolbar layout (sizes & positions).
        state = settings.value('Window/state', type=QByteArray)
        if state:
            self.restoreState(state)

        # Restore splitter proportions (object tree vs. MDI area).
        splitter_state = settings.value('Window/splitter', type=QByteArray)
        if splitter_state:
            self._splitter.restoreState(splitter_state)

        tree_visible = settings.value('View/ObjectTree', True, type=bool)
        self._object_tree.setVisible(tree_visible)
        self.actionObject_Tree.setChecked(tree_visible)

        editor_visible = settings.value('View/EditorPanel', True, type=bool)
        self.editorDockWidget.setVisible(editor_visible)
        self.actionEditor_panel.setChecked(editor_visible)

        undo_visible = settings.value('View/UndoStack', False, type=bool)
        self.undoDockWidget.setVisible(undo_visible)
        self.actionUndo_view.setChecked(undo_visible)

    def _apply_no_file_state(self):
        """Hide panels and disable file-dependent actions when no database file is loaded."""
        self._object_tree.setVisible(False)
        self.editorDockWidget.setVisible(False)
        self.undoDockWidget.setVisible(False)
        self.compileAction.setEnabled(False)
        self.fileReloadAction.setEnabled(False)
        self.fileSaveAction.setEnabled(False)
        self.fileSaveAsAction.setEnabled(False)
        self.installAction.setEnabled(False)
        self.toolbarFileSave.setEnabled(False)

    def _apply_file_loaded_state(self):
        """Restore panel visibility from QSettings after loading a file."""
        settings = QSettings()
        tree_visible = settings.value('View/ObjectTree', True, type=bool)
        self._object_tree.setVisible(tree_visible)
        self.actionObject_Tree.setChecked(tree_visible)
        editor_visible = settings.value('View/EditorPanel', True, type=bool)
        self.editorDockWidget.setVisible(editor_visible)
        self.actionEditor_panel.setChecked(editor_visible)
        self.compileAction.setEnabled(True)
        self.fileReloadAction.setEnabled(self._current_file is not None)
        self.fileSaveAction.setEnabled(True)
        self.fileSaveAsAction.setEnabled(True)
        self.installAction.setEnabled(True)
        self.toolbarFileSave.setEnabled(True)
        undo_visible = settings.value('View/UndoStack', False, type=bool)
        self.undoDockWidget.setVisible(undo_visible)
        self.actionUndo_view.setChecked(undo_visible)

    def _save_if_modified(self):
        """Prompt the user to save unsaved changes.

        Returns ``True`` if the caller may proceed (saved or discarded),
        ``False`` if the user chose Cancel.
        """
        self._flush_editor_changes()
        if not self._db_manager.is_dirty:
            return True
        display = getattr(self, '_display_file', None) or self._current_file
        name = str(display) if display else 'Untitled'
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle('FirewallFabrik')
        box.setText(
            self.tr(
                f'Some objects have been modified but not saved.\n'
                f'Do you want to save {name} changes now?'
            )
        )
        save_btn = box.addButton(self.tr('&Save'), QMessageBox.ButtonRole.AcceptRole)
        box.addButton(self.tr('&Discard'), QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(self.tr('&Cancel'), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(save_btn)
        box.exec()
        clicked = box.clickedButton()
        if clicked is save_btn:
            self.fileSave()
            return True
        return box.buttonRole(clicked) == QMessageBox.ButtonRole.DestructiveRole

    def _update_title(self):
        display = getattr(self, '_display_file', None) or self._current_file
        dirty = '*' if self._db_manager.is_dirty else ''
        if display:
            self.setWindowTitle(
                f'{dirty}{display.name} - FirewallFabrik {__version__}',
            )
        else:
            self.setWindowTitle(f'FirewallFabrik {__version__}')

    @Slot()
    def fileNew(self):
        """Create a new object file (mirrors fwbuilder ProjectPanel::fileNew())."""
        if not self._save_if_modified():
            return

        # Show save dialog to choose filename.
        fd = QFileDialog(self)
        fd.setFileMode(QFileDialog.FileMode.AnyFile)
        fd.setDefaultSuffix('fwf')
        fd.setNameFilter(FILE_FILTERS)
        fd.setWindowTitle(self.tr('Create New File'))
        fd.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        if not fd.exec():
            return

        file_path = Path(fd.selectedFiles()[0]).resolve()
        if file_path.suffix == '':
            file_path = file_path.with_suffix('.fwf')

        # Save tree state for the current file before closing.
        display = getattr(self, '_display_file', None)
        if display:
            self._object_tree.save_tree_state(str(display))
            self._rs_mgr.save_state()

        # Close current state (mirrors fileClose but without the save prompt).
        self._close_editor()
        self._rs_mgr.close_all()
        self._object_tree._tree.clear()
        self._object_tree._filter.clear()
        self.undoView.clear()

        # Create new database: load the Standard library, then add an
        # empty "User" library (mirrors fwbuilder's loadStandardObjects).
        self._db_manager = DatabaseManager()
        self._db_manager.on_history_changed = self._on_history_changed
        self._editor_mgr.set_db_manager(self._db_manager)
        self._rs_mgr.set_db_manager(self._db_manager)
        std_path = (
            Path(str(importlib.resources.files('firewallfabrik') / 'resources'))
            / 'libraries'
            / 'standard.fwf'
        )
        try:
            self._db_manager._load_yaml(std_path)
        except Exception:
            logger.exception('Failed to load standard library from %s', std_path)
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr('Failed to load the standard object library.'),
            )
            return
        with self._db_manager.session(description='New file') as session:
            db_obj = session.scalars(
                sqlalchemy.select(FWObjectDatabase),
            ).first()
            user_lib = Library(id=uuid.uuid4(), name='User', database=db_obj)
            session.add(user_lib)
            session.flush()  # ensure user_lib.id is available
            create_library_folder_structure(session, user_lib.id)

        # Save to the chosen path.
        try:
            self._db_manager.save(file_path)
        except Exception:
            logger.exception('Failed to save %s', file_path)
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr(f"Failed to save '{file_path}'"),
            )
            return

        # Set up UI.
        self._current_file = file_path
        self._display_file = file_path
        self._rs_mgr.set_display_file(file_path)
        self._update_title()
        self._add_to_recent(str(file_path))

        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=str(file_path))

        self._object_tree.set_db_manager(self._db_manager)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_reload_callback(self._rs_mgr.reload_views)
        self._find_panel.set_open_rule_set_ids_callback(
            self._rs_mgr.get_active_firewall_rule_set_ids,
        )
        self._find_panel.reset()
        self._where_used_panel.set_db_manager(self._db_manager)
        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.reset()

        self.newObjectAction.setEnabled(True)
        self._apply_file_loaded_state()
        self._object_tree.focus_filter()

    @Slot()
    def fileOpen(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            self.tr('Open File'),
            '',
            FILE_FILTERS,
        )
        if not file_name:
            return
        self._load_file(Path(file_name).resolve())

    @Slot()
    def fileSave(self):
        if not self._current_file:
            self.fileSaveAs()
            return
        self._flush_editor_changes()
        try:
            self._db_manager.save(self._current_file)
        except Exception:
            logger.exception('Failed to save %s', self._current_file)
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr(f"Failed to save '{self._current_file}'"),
            )
            return
        if self._display_file != self._current_file:
            self._display_file = self._current_file
            self._rs_mgr.set_display_file(self._current_file)
            self._add_to_recent(str(self._current_file))
        self._update_title()

    @Slot()
    def fileSaveAs(self):
        fd = QFileDialog(self)
        fd.setFileMode(QFileDialog.FileMode.AnyFile)
        fd.setDefaultSuffix('fwf')
        fd.setNameFilter(FILE_FILTERS)
        fd.setWindowTitle(self.tr('Save File As'))
        fd.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        if self._current_file:
            fd.setDirectory(str(self._current_file.parent))
            fd.selectFile(self._current_file.name)
        elif self._display_file:
            fd.setDirectory(str(self._display_file.parent))
            fd.selectFile(self._display_file.with_suffix('.fwf').name)
        if not fd.exec():
            return

        file_path = Path(fd.selectedFiles()[0]).resolve()
        if file_path.suffix == '':
            file_path = file_path.with_suffix('.fwf')

        self._flush_editor_changes()
        try:
            self._db_manager.save(file_path)
        except Exception:
            logger.exception('Failed to save %s', file_path)
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr(f"Failed to save '{file_path}'"),
            )
            return

        self._current_file = file_path
        self._display_file = file_path
        self._rs_mgr.set_display_file(file_path)
        self._update_title()
        self._add_to_recent(str(file_path))
        self.fileReloadAction.setEnabled(True)

    @Slot()
    def fileClose(self):
        if not self._save_if_modified():
            return
        display = getattr(self, '_display_file', None)
        if display:
            self._object_tree.save_tree_state(str(display))
            self._rs_mgr.save_state()
        self._close_editor()
        self._rs_mgr.close_all()
        self._object_tree._tree.clear()
        self._object_tree._filter.clear()
        self.undoView.clear()
        self._db_manager = DatabaseManager()
        self._db_manager.on_history_changed = self._on_history_changed
        self._editor_mgr.set_db_manager(self._db_manager)
        self._rs_mgr.set_db_manager(self._db_manager)
        self._current_file = None
        self._display_file = None
        self._rs_mgr.set_display_file(None)
        self._update_title()
        self.newObjectAction.setEnabled(False)
        self._update_undo_actions()
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.reset()
        self._where_used_panel.set_db_manager(self._db_manager)
        self._where_used_panel.reset()
        self._object_tree.set_db_manager(self._db_manager)
        self.editorDockWidget.blockSignals(True)
        self.undoDockWidget.blockSignals(True)
        self._apply_no_file_state()
        self.editorDockWidget.blockSignals(False)
        self.undoDockWidget.blockSignals(False)

    @Slot()
    def fileReload(self):
        """Re-read the current file from disk, discarding unsaved changes."""
        if self._current_file is None or not self._current_file.is_file():
            return
        if self._db_manager.is_dirty:
            result = QMessageBox.question(
                self,
                'FirewallFabrik',
                self.tr(
                    'The file has been modified.\n'
                    'Do you want to discard your changes and reload from disk?'
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if result != QMessageBox.StandardButton.Yes:
                return
        file_path = self._current_file
        # Save tree state, close editors and MDI windows.
        display = getattr(self, '_display_file', None)
        if display:
            self._object_tree.save_tree_state(str(display))
            self._rs_mgr.save_state()
        self._close_editor()
        self._rs_mgr.close_all()
        # Reload.
        try:
            self._db_manager = DatabaseManager()
            self._db_manager.on_history_changed = self._on_history_changed
            self._editor_mgr.set_db_manager(self._db_manager)
            self._rs_mgr.set_db_manager(self._db_manager)
            self._db_manager.load(file_path)
        except Exception:
            logger.exception('Failed to reload %s', file_path)
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr(f"Failed to reload '{file_path}'"),
            )
            return
        self._update_title()
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=str(display or file_path))
        self._object_tree.set_db_manager(self._db_manager)
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_reload_callback(self._rs_mgr.reload_views)
        self._find_panel.set_open_rule_set_ids_callback(
            self._rs_mgr.get_active_firewall_rule_set_ids,
        )
        self._find_panel.reset()
        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.set_db_manager(self._db_manager)
        self._where_used_panel.reset()
        self.newObjectAction.setEnabled(
            bool(self._object_tree._actions._get_writable_libraries())
        )
        self._update_undo_actions()
        self._rs_mgr.restore_state(str(display or file_path))
        if not self.m_space.subWindowList():
            self._rs_mgr.open_first_firewall_policy()
        self._object_tree.focus_filter()

    @Slot()
    def fileExit(self):
        self.close()

    @Slot()
    def editPrefs(self):
        dlg = PreferencesDialog(self)
        dlg.exec()
        settings = QSettings()
        show = settings.value('UI/ShowObjectsAttributesInTree', True, type=bool)
        self._object_tree.set_show_attrs(show)
        tooltips = settings.value('UI/ObjTooltips', True, type=bool)
        self._object_tree.set_tooltips_enabled(tooltips)

    @Slot()
    def help(self):
        QDesktopServices.openUrl(
            QUrl(
                'https://github.com/Linuxfabrik/firewallfabrik/tree/main/docs/user-guide'
            ),
        )

    @Slot()
    def showChangelog(self):
        QDesktopServices.openUrl(
            QUrl(
                'https://github.com/Linuxfabrik/firewallfabrik/blob/main/CHANGELOG.md'
            ),
        )

    @Slot()
    def compile(self):
        if not getattr(self, '_display_file', None):
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('No file is loaded. Open or create a file first.'),
            )
            return
        if self._db_manager.is_dirty or not self._current_file:
            result = QMessageBox.question(
                self,
                'FirewallFabrik',
                self.tr(
                    'The file must be saved before compiling.\nDo you want to save now?'
                ),
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel,
            )
            if result != QMessageBox.StandardButton.Save:
                return
        self.fileSave()
        if not self._current_file:
            return

        from firewallfabrik.gui.compile_dialog import CompileDialog

        dlg = CompileDialog(self._db_manager, self._current_file, parent=self)
        dlg.exec()

        # Refresh the tree to show updated lastCompiled timestamps.
        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=file_key)

    @Slot()
    def install(self):
        if not getattr(self, '_display_file', None):
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('No file is loaded. Open or create a file first.'),
            )
            return
        if self._db_manager.is_dirty or not self._current_file:
            result = QMessageBox.question(
                self,
                'FirewallFabrik',
                self.tr(
                    'The file must be saved before installing.\nDo you want to save now?'
                ),
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel,
            )
            if result != QMessageBox.StandardButton.Save:
                return
        self.fileSave()
        if not self._current_file:
            return

        from firewallfabrik.gui.compile_dialog import CompileDialog

        dlg = CompileDialog(
            self._db_manager,
            self._current_file,
            parent=self,
            install_mode=True,
        )
        dlg.exec()

        # Refresh the tree to show updated lastInstalled timestamps.
        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=file_key)

    @Slot()
    def toolsUpdateStandardLibrary(self):
        """Replace the Standard Library with the latest bundled version."""
        if self._current_file is None:
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('No file is loaded. Open or create a file first.'),
            )
            return

        answer = QMessageBox.question(
            self,
            'FirewallFabrik',
            self.tr(
                'Replace the Standard Library with the latest version?\n'
                'Your user libraries and rules will be preserved.'
            ),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._close_editor()

        # Close MDI sub-windows — Standard Library device UUIDs will
        # change, making stale rule-set views unusable.
        self._rs_mgr.close_all()

        # Parse the bundled Standard Library.
        std_path = (
            Path(str(importlib.resources.files('firewallfabrik') / 'resources'))
            / 'libraries'
            / 'standard.fwf'
        )
        from firewallfabrik.core._yaml_reader import YamlReader

        reader = YamlReader()
        try:
            parse_result = reader.parse(std_path)
        except Exception:
            logger.exception(
                'Failed to parse standard library from %s',
                std_path,
            )
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr('Failed to parse the standard object library.'),
            )
            return

        # Find the Standard library in the parse result.
        new_std = None
        for lib in parse_result.database.libraries:
            if lib.name == 'Standard':
                new_std = lib
                break
        if new_std is None:
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr(
                    'The bundled standard library file does not contain '
                    'a "Standard" library.'
                ),
            )
            return

        # Phase 1: Build old path map from the DB, then delete.
        # We build the map by traversing the live objects (not from
        # ref_index, which may be empty for XML-imported files).
        session = self._db_manager.create_session()
        try:
            old_std = session.scalars(
                sqlalchemy.select(Library).where(
                    Library.name == 'Standard',
                ),
            ).first()

            if old_std is None:
                session.close()
                QMessageBox.warning(
                    self,
                    'FirewallFabrik',
                    self.tr('No Standard Library found in the current file.'),
                )
                return

            old_std_id = old_std.id
            old_ref_map = _build_library_path_map(session, old_std)

            # Subqueries for objects reachable via device/interface FKs
            # (these may have library_id=NULL but still belong to the
            # Standard Library through their parent device).
            std_device_ids = sqlalchemy.select(Host.id).where(
                Host.library_id == old_std_id,
            )
            std_iface_ids = sqlalchemy.select(Interface.id).where(
                sqlalchemy.or_(
                    Interface.library_id == old_std_id,
                    Interface.device_id.in_(std_device_ids),
                ),
            )
            std_ruleset_ids = sqlalchemy.select(RuleSet.id).where(
                RuleSet.device_id.in_(std_device_ids),
            )
            std_rule_ids = sqlalchemy.select(Rule.id).where(
                Rule.rule_set_id.in_(std_ruleset_ids),
            )

            # Collect all object IDs for group_membership cleanup.
            old_ids = {old_std_id}
            for cls in (Address, Group, Host, Interface, Interval, Service):
                for (oid,) in session.execute(
                    sqlalchemy.select(cls.id).where(
                        cls.library_id == old_std_id,
                    ),
                ):
                    old_ids.add(oid)
            # Also include device-owned interfaces/addresses with
            # NULL library_id.
            for (oid,) in session.execute(
                sqlalchemy.select(Interface.id).where(
                    Interface.device_id.in_(std_device_ids),
                ),
            ):
                old_ids.add(oid)
            for (oid,) in session.execute(
                sqlalchemy.select(Address.id).where(
                    Address.interface_id.in_(std_iface_ids),
                ),
            ):
                old_ids.add(oid)

            # Delete group_membership rows referencing old objects.
            session.execute(
                group_membership.delete().where(
                    group_membership.c.group_id.in_(old_ids),
                ),
            )

            # Delete children via Core SQL in FK-safe order.
            # 1. rule_elements → rules → rule_sets (device children)
            session.execute(
                rule_elements.delete().where(
                    rule_elements.c.rule_id.in_(std_rule_ids),
                ),
            )
            session.execute(
                sqlalchemy.delete(Rule).where(
                    Rule.rule_set_id.in_(std_ruleset_ids),
                ),
            )
            session.execute(
                sqlalchemy.delete(RuleSet).where(
                    RuleSet.device_id.in_(std_device_ids),
                ),
            )
            # 2. addresses (by library_id OR interface_id)
            session.execute(
                sqlalchemy.delete(Address).where(
                    sqlalchemy.or_(
                        Address.library_id == old_std_id,
                        Address.interface_id.in_(std_iface_ids),
                    ),
                ),
            )
            # 3. interfaces (by library_id OR device_id)
            session.execute(
                sqlalchemy.delete(Interface).where(
                    sqlalchemy.or_(
                        Interface.library_id == old_std_id,
                        Interface.device_id.in_(std_device_ids),
                    ),
                ),
            )
            # 4. services, intervals, devices
            session.execute(
                sqlalchemy.delete(Service).where(
                    Service.library_id == old_std_id,
                ),
            )
            session.execute(
                sqlalchemy.delete(Interval).where(
                    Interval.library_id == old_std_id,
                ),
            )
            session.execute(
                sqlalchemy.delete(Host).where(
                    Host.library_id == old_std_id,
                ),
            )
            # 5. groups: clear self-referencing FK first, then delete
            session.execute(
                sqlalchemy.update(Group)
                .where(Group.library_id == old_std_id)
                .values(parent_group_id=None),
            )
            session.execute(
                sqlalchemy.delete(Group).where(
                    Group.library_id == old_std_id,
                ),
            )
            # 6. library itself
            session.execute(
                sqlalchemy.delete(Library).where(Library.id == old_std_id),
            )
            session.commit()
        except Exception:
            session.rollback()
            logger.exception('Failed to delete old Standard Library')
            self._show_traceback_error(
                'Failed to delete the old Standard Library.',
            )
            return
        finally:
            session.close()

        # Phase 2: Insert new Standard Library.
        # Link the transient Library to the *existing* persistent
        # FWObjectDatabase — this is safe because the ORM simply
        # updates the FK and back-ref without touching child groups.
        session = self._db_manager.create_session()
        try:
            db_obj = session.scalars(
                sqlalchemy.select(FWObjectDatabase),
            ).first()
            new_std.database = db_obj
            session.add(new_std)
            session.flush()

            # Insert new group memberships (internal to Standard Library).
            if parse_result.memberships:
                session.execute(
                    group_membership.insert(),
                    parse_result.memberships,
                )

            # Remap user references: build old_uuid -> new_uuid mapping
            # by matching tree-paths between old and new Standard Library.
            new_ref_map = {
                path: uid
                for path, uid in parse_result.ref_index.items()
                if path.startswith('Library:Standard/')
            }
            uuid_remap = {}
            for path, old_uuid in old_ref_map.items():
                new_uuid = new_ref_map.get(path)
                if new_uuid is not None and new_uuid != old_uuid:
                    uuid_remap[old_uuid] = new_uuid

            for old_uuid, new_uuid in uuid_remap.items():
                session.execute(
                    rule_elements.update()
                    .where(rule_elements.c.target_id == old_uuid)
                    .values(target_id=new_uuid),
                )
                session.execute(
                    group_membership.update()
                    .where(group_membership.c.member_id == old_uuid)
                    .values(member_id=new_uuid),
                )

            session.commit()
        except Exception:
            session.rollback()
            logger.exception('Failed to insert new Standard Library')
            self._show_traceback_error(
                'Failed to insert the new Standard Library.',
            )
            return
        finally:
            session.close()

        # Merge ref_index: remove old Standard entries, add new ones.
        ref_index = {
            path: uid
            for path, uid in self._db_manager.ref_index.items()
            if not path.startswith('Library:Standard')
        }
        ref_index.update(parse_result.ref_index)
        self._db_manager.ref_index = ref_index

        # Save undo state and refresh UI.
        self._db_manager.save_state('Update Standard Library')

        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as sess:
            self._object_tree.populate(sess, file_key=file_key)

        QMessageBox.information(
            self,
            'FirewallFabrik',
            self.tr('Standard Library has been updated successfully.'),
        )

    @Slot()
    def debug(self):
        dlg = DebugDialog(self)
        dlg.exec()

    @Slot()
    def helpAbout(self):
        dlg = AboutDialog(self)
        dlg.exec()

    @Slot()
    def newObject(self):
        """Show the "New Object" popup at the cursor position.

        Called via keyboard shortcut (Ctrl+N) or the Object menu entry.
        The toolbar button uses the attached QMenu directly (dropdown
        arrow), which also calls :meth:`_populate_new_object_menu`.
        """
        self._new_object_menu.popup(QCursor.pos())

    def _get_target_library_id(self):
        """Return the writable library id for new-object creation, or None."""
        if self._db_manager is None:
            return None
        libs = self._object_tree._actions._get_writable_libraries()
        if not libs:
            return None
        writable_ids = {lid for lid, _name in libs}
        lib_id = None
        item = self._object_tree._tree.currentItem()
        if item is not None:
            item_lib_id = ObjectTree._get_item_library_id(item)
            if item_lib_id in writable_ids:
                lib_id = item_lib_id
        if lib_id is None:
            lib_id = libs[0][0]
        return lib_id

    def _populate_new_object_menu(self):
        """Rebuild the "New Object" dropdown menu entries."""
        self._new_object_menu.clear()
        lib_id = self._get_target_library_id()
        if lib_id is None:
            return
        for entry in _NEW_OBJECT_MENU_ENTRIES:
            if entry is None:
                self._new_object_menu.addSeparator()
                continue
            type_name, label = entry
            icon_path = ICON_MAP.get(type_name, '')
            action = self._new_object_menu.addAction(QIcon(icon_path), label)
            action.setData(type_name)
            action.triggered.connect(
                lambda checked=False, t=type_name, lid=lib_id: (
                    self._on_new_object_action(t, lid)
                )
            )

    def _on_new_object_action(self, type_name, lib_id):
        """Handle a selection from the "New Object" menu."""
        if type_name == 'Cluster':
            from firewallfabrik.gui.new_cluster_dialog import NewClusterDialog

            dlg = NewClusterDialog(
                db_manager=self._db_manager,
                parent=self,
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()
            self._object_tree._actions.create_new_object_in_library(
                type_name,
                lib_id,
                extra_data=extra_data,
                name=name,
            )
        elif type_name == 'Host':
            from firewallfabrik.gui.new_host_dialog import NewHostDialog

            dlg = NewHostDialog(parent=self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, interfaces = dlg.get_result()
            self._object_tree._actions.create_host_in_library(
                lib_id,
                name=name,
                interfaces=interfaces,
            )
        elif type_name == 'Firewall':
            from firewallfabrik.gui.new_device_dialog import NewDeviceDialog

            dlg = NewDeviceDialog(type_name, parent=self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()
            self._object_tree._actions.create_new_object_in_library(
                type_name,
                lib_id,
                extra_data=extra_data,
                name=name,
            )
        else:
            self._object_tree._actions.create_new_object_in_library(type_name, lib_id)

    def _on_create_group_member(self, type_name, group_id_hex):
        """Handle 'Create new object and add to this group'.

        Creates the new object in its standard folder, adds a
        ``group_membership`` entry linking it to the group, then
        opens the new object's editor.  Mirrors fwbuilder's
        ``GroupObjectDialog::newObject()`` → ``createNewObject()``
        → ``addRef()`` flow.
        """
        # Save group info before the editor switches away.
        group_id = uuid.UUID(group_id_hex)
        editor = self._editor_mgr.current_editor
        if editor is None or self._editor_mgr.current_session is None:
            return
        lib_id = editor._obj.library_id

        # Flush pending editor changes.
        self._flush_editor_changes()

        # Create the object (this refreshes tree and opens new editor).
        if type_name == 'Cluster':
            from firewallfabrik.gui.new_cluster_dialog import NewClusterDialog

            dlg = NewClusterDialog(
                db_manager=self._db_manager,
                parent=self,
            )
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()
            new_id = self._object_tree._actions.create_new_object_in_library(
                type_name, lib_id, extra_data=extra_data, name=name
            )
        elif type_name in ('Firewall', 'Host'):
            from firewallfabrik.gui.new_device_dialog import NewDeviceDialog

            dlg = NewDeviceDialog(type_name, parent=self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            name, extra_data = dlg.get_result()
            if type_name == 'Host' and extra_data.get('interfaces'):
                interfaces = extra_data.pop('interfaces')
                new_id = self._object_tree._actions.create_host_in_library(
                    lib_id, name=name, interfaces=interfaces
                )
            else:
                new_id = self._object_tree._actions.create_new_object_in_library(
                    type_name, lib_id, extra_data=extra_data, name=name
                )
        else:
            new_id = self._object_tree._actions.create_new_object_in_library(
                type_name, lib_id
            )

        if new_id is None:
            return

        # Add group_membership entry.
        session = self._db_manager.create_session()
        try:
            session.execute(
                group_membership.insert().values(
                    group_id=group_id,
                    member_id=new_id,
                )
            )
            session.commit()
            self._db_manager.save_state('Add to group')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # File loading & recent-files menu
    # ------------------------------------------------------------------

    def _load_file(self, file_path):
        """Load *file_path*, update the UI, and record it in the recent list."""
        if not file_path.is_file():
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr(f"File '{file_path}' does not exist or is not readable"),
            )
            return

        if not self._save_if_modified():
            return

        # Save tree state for the current file before switching.
        display = getattr(self, '_display_file', None)
        if display:
            self._object_tree.save_tree_state(str(display))
            self._rs_mgr.save_state()

        self._close_editor()
        self._rs_mgr.close_all()

        original_path = file_path
        try:
            self._db_manager = DatabaseManager()
            self._db_manager.on_history_changed = self._on_history_changed
            self._editor_mgr.set_db_manager(self._db_manager)
            self._rs_mgr.set_db_manager(self._db_manager)
            file_path = self._db_manager.load(file_path)
        except sqlalchemy.exc.IntegrityError as e:
            logger.exception('Failed to load %s', file_path)
            msg = self.tr(f"Failed to load '{file_path}'.")
            if 'UNIQUE constraint failed' in str(e):
                lib_names = getattr(self._db_manager, '_library_names', None)
                parent_names = getattr(self._db_manager, '_parent_names', None)
                dup = duplicate_object_name(
                    e,
                    library_names=lib_names,
                    parent_names=parent_names,
                )
                detail = f': {dup}' if dup else ''
                if original_path.suffix == '.fwb':
                    msg += self.tr(
                        f'\n\nDuplicate names are not allowed{detail}. '
                        'Open the database in Firewall Builder, rename the '
                        'affected objects and retry the import.'
                    )
                else:
                    msg += self.tr(
                        f'\n\nDuplicate names are not allowed{detail}. '
                        'This should not happen during normal operations. '
                        'If you edited the YAML manually, double-check '
                        'your changes.'
                    )
            QMessageBox.critical(self, 'FirewallFabrik', msg)
            return
        except Exception:
            logger.exception('Failed to load %s', file_path)
            QMessageBox.critical(
                self,
                'FirewallFabrik',
                self.tr(f"Failed to load '{file_path}'"),
            )
            return

        # When importing a .fwb file, the save target is the corresponding
        # .fwf.  If that .fwf already exists on disk, leave _current_file
        # unset so the first Ctrl+S routes through fileSaveAs() — its native
        # dialog will ask the user to confirm the overwrite.
        if original_path.suffix == '.fwb' and file_path.exists():
            self._current_file = None
        else:
            self._current_file = file_path
        self._display_file = original_path
        self._rs_mgr.set_display_file(original_path)
        self._update_title()
        self._add_to_recent(str(original_path))

        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=str(original_path))

        self._object_tree.set_db_manager(self._db_manager)
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_reload_callback(self._rs_mgr.reload_views)
        self._find_panel.set_open_rule_set_ids_callback(
            self._rs_mgr.get_active_firewall_rule_set_ids,
        )
        self._find_panel.reset()

        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.set_db_manager(self._db_manager)
        self._where_used_panel.reset()

        self.newObjectAction.setEnabled(
            bool(self._object_tree._actions._get_writable_libraries())
        )
        self._apply_file_loaded_state()
        self._rs_mgr.restore_state(str(original_path))

        # If no MDI sub-window was restored, open the first firewall's Policy.
        if not self.m_space.subWindowList():
            self._rs_mgr.open_first_firewall_policy()

        self._object_tree.focus_filter()

    def _prepare_recent_menu(self):
        """Populate the empty *menuOpen_Recent* with dynamic actions."""
        self.menuOpen_Recent.setToolTipsVisible(True)
        self._recent_actions = []
        for _ in range(_MAX_RECENT_FILES):
            action = QAction(self)
            action.setVisible(False)
            action.triggered.connect(self._open_recent_file)
            self.menuOpen_Recent.addAction(action)
            self._recent_actions.append(action)

        self._recent_separator = self.menuOpen_Recent.addSeparator()
        self.menuOpen_Recent.addAction(self.actionClearRecentFiles)

        self._update_recent_actions()

    def _update_recent_actions(self):
        """Refresh the visible recent-file actions from QSettings."""
        settings = QSettings()
        files = settings.value('recentFiles', []) or []
        if isinstance(files, str):
            files = [files]

        num = min(len(files), _MAX_RECENT_FILES)
        for i in range(num):
            self._recent_actions[i].setText(Path(files[i]).name)
            self._recent_actions[i].setToolTip(files[i])
            self._recent_actions[i].setData(files[i])
            self._recent_actions[i].setVisible(True)
            if i < 9:
                self._recent_actions[i].setShortcut(QKeySequence(f'Ctrl+{i + 1}'))
            else:
                self._recent_actions[i].setShortcut(QKeySequence())

        for i in range(num, _MAX_RECENT_FILES):
            self._recent_actions[i].setVisible(False)
            self._recent_actions[i].setShortcut(QKeySequence())

        self._recent_separator.setVisible(num > 0)

    def _add_to_recent(self, file_path):
        """Prepend *file_path* to the persisted recent-files list."""
        settings = QSettings()
        files = settings.value('recentFiles', []) or []
        if isinstance(files, str):
            files = [files]
        if file_path in files:
            files.remove(file_path)
        files.insert(0, file_path)
        del files[_MAX_RECENT_FILES:]
        settings.setValue('recentFiles', files)
        self._update_recent_actions()

    @Slot()
    def _open_recent_file(self):
        action = self.sender()
        if action:
            self._load_file(Path(action.data()))

    @Slot()
    def clearRecentFilesMenu(self):
        settings = QSettings()
        settings.setValue('recentFiles', [])
        self._update_recent_actions()

    @Slot(str, str)
    def _open_object_editor(self, obj_id, obj_type):
        """Open the editor panel for the given object (triggered by tree double-click)."""
        self._editor_mgr.open_object(obj_id, obj_type)

    @Slot()
    def _on_editor_changed(self):
        """Handle a change in the active editor: apply and commit."""
        self._editor_mgr.on_editor_changed()

    def _on_tree_changed(self, activate_obj_id='', activate_obj_type=''):
        """Refresh the tree, MDI views, and editor after a CRUD operation.

        When *activate_obj_id* is non-empty, the editor for that object is
        opened after the rebuild.  When empty, no editor is opened (the
        previous one was already closed).
        """
        self._close_editor()
        self._rs_mgr.reload_views()

        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=file_key)

        # Open the requested editor (if any).
        if activate_obj_id:
            self._open_object_editor(activate_obj_id, activate_obj_type)

    @Slot()
    def toggleViewObjectTree(self):
        """Show or hide the object tree panel."""
        visible = self.actionObject_Tree.isChecked()
        self._object_tree.setVisible(visible)
        QSettings().setValue('View/ObjectTree', visible)

    @Slot()
    def toggleViewEditor(self):
        """Show or hide the editor panel."""
        visible = self.actionEditor_panel.isChecked()
        self.editorDockWidget.setVisible(visible)
        QSettings().setValue('View/EditorPanel', visible)

    @Slot()
    def toggleViewUndo(self):
        """Show or hide the undo stack panel."""
        visible = self.actionUndo_view.isChecked()
        self.undoDockWidget.setVisible(visible)
        QSettings().setValue('View/UndoStack', visible)

    @Slot()
    def _show_editor_panel(self):
        """Show the editor dock and switch to the Editor tab."""
        self._editor_mgr.show_editor_panel()

    @Slot()
    def _show_find_panel(self):
        """Show the editor dock and switch to the Find tab."""
        if not self.editorDockWidget.isVisible():
            self.editorDockWidget.setVisible(True)
            self.actionEditor_panel.setChecked(True)
        self.editorPanelTabWidget.setCurrentIndex(1)
        self._find_panel.focus_input()

    def _show_where_used_panel(self):
        """Show the editor dock and switch to the Where Used tab."""
        if not self.editorDockWidget.isVisible():
            self.editorDockWidget.setVisible(True)
            self.actionEditor_panel.setChecked(True)
        self.editorPanelTabWidget.setCurrentIndex(2)

    def _show_output_panel(self):
        """Show the editor dock and switch to the Output tab."""
        if not self.editorDockWidget.isVisible():
            self.editorDockWidget.setVisible(True)
            self.actionEditor_panel.setChecked(True)
        self.editorPanelTabWidget.setCurrentIndex(3)

    def compile_single_rule(self, rule_id, rule_set_id):
        """Compile a single rule and display the output in the Output panel."""
        import re
        from html import escape

        from firewallfabrik.platforms.iptables._compiler_driver import (
            CompilerDriver_ipt,
        )
        from firewallfabrik.platforms.nftables._compiler_driver import (
            CompilerDriver_nft,
        )

        _PLATFORM_DRIVER = {
            'iptables': CompilerDriver_ipt,
            'nftables': CompilerDriver_nft,
        }

        with self._db_manager.session() as session:
            rs = session.get(RuleSet, rule_set_id)
            if rs is None:
                return
            device = rs.device
            if device is None:
                return
            device_id = device.id
            fw_name = device.name
            rs_name = rs.name
            platform = (device.data or {}).get('platform', '')
            rule = session.get(Rule, rule_id)
            rule_position = rule.position if rule is not None else '?'

        driver_cls = _PLATFORM_DRIVER.get(platform)
        if driver_cls is None:
            self.output_box.setHtml(
                f'<p style="color: red;"><b>Unsupported platform: '
                f'{escape(platform or "(none)")}</b></p>'
            )
            self._show_output_panel()
            return

        driver = driver_cls(self._db_manager)
        driver.single_rule_compile_on = True
        driver.single_rule_id = str(rule_id)

        result = driver.run(
            cluster_id='',
            fw_id=str(device_id),
            single_rule_id=str(rule_id),
        )

        # Collapse runs of whitespace (except newlines) for iptables output.
        # nftables uses meaningful indentation that must be preserved.
        if result and platform == 'iptables':
            result = re.sub(r'[^\S\n]+', ' ', result)

        # Build HTML output.
        header = (
            f'Compiling {escape(fw_name)} / {escape(rs_name)} / Rule {rule_position}'
        )
        parts = [f'<p><b>{header}</b></p>']
        if driver.all_errors:
            parts.append('<pre style="color: red;">')
            parts.append(escape('\n'.join(driver.all_errors)))
            parts.append('</pre>')
        if result:
            parts.append(f'<pre>{escape(result)}</pre>')
        elif not driver.all_errors:
            parts.append('<p><i>No output generated.</i></p>')

        self.output_box.setHtml('\n'.join(parts))
        self._show_output_panel()

    def open_comment_editor(self, model, index):
        """Open the comment editor panel in the editor pane."""
        self._editor_mgr.open_comment_editor(model, index)

    def open_rule_options(self, model, index):
        """Open the rule options panel in the editor pane."""
        self._editor_mgr.open_rule_options(model, index)

    def open_action_editor(self, model, index):
        """Open the action parameters panel in the editor pane."""
        self._editor_mgr.open_action_editor(model, index)

    def open_direction_editor(self, model, index):
        """Open the (blank) direction pane in the editor pane."""
        self._editor_mgr.open_direction_editor(model, index)

    def open_metric_editor(self, model, index):
        """Open the metric editor panel in the editor pane."""
        self._editor_mgr.open_metric_editor(model, index)

    def show_any_editor(self, slot):
        """Show the 'Any' object description in the editor pane."""
        self._editor_mgr.show_any_editor(slot)

    def show_where_used(self, obj_id, name, obj_type):
        """Show where-used results for the given object."""
        self._show_where_used_panel()
        self._where_used_panel.find_object(obj_id, name, obj_type)

    def _on_find_from_tree(self, obj_id, name, obj_type):
        """Handle Find request from the object tree context menu."""
        self._show_find_panel()
        self._find_panel.focus_input()

    def _on_where_used_from_tree(self, obj_id, name, obj_type):
        """Handle Where Used request from the object tree context menu."""
        self.show_where_used(obj_id, name, obj_type)

    @Slot()
    def editCopy(self):
        """Handle Ctrl+C — route to tree or policy view based on focus."""
        self._clipboard.copy()

    @Slot()
    def editCut(self):
        """Handle Ctrl+X — route to tree or policy view based on focus."""
        self._clipboard.cut()

    @Slot()
    def editDelete(self):
        """Handle Delete key — route to tree or policy view based on focus."""
        self._clipboard.delete()

    @Slot()
    def editPaste(self):
        """Handle Ctrl+V — route to tree or policy view based on focus."""
        self._clipboard.paste()

    @Slot(bool)
    def _on_editor_visibility_changed(self, visible):
        """Sync the View menu checkbox when the editor dock is closed via X."""
        if self._closing:
            return
        self.actionEditor_panel.setChecked(visible)
        QSettings().setValue('View/EditorPanel', visible)

    @Slot(bool)
    def _on_undo_visibility_changed(self, visible):
        """Sync the View menu checkbox when the undo dock is closed via X."""
        if self._closing:
            return
        self.actionUndo_view.setChecked(visible)
        QSettings().setValue('View/UndoStack', visible)

    # ------------------------------------------------------------------
    # Undo / redo
    # ------------------------------------------------------------------

    @Slot()
    def _do_undo(self):
        # Capture the active editor *before* closing, so that
        # _refresh_after_history_change can reopen it afterwards.
        obj_id = self._editor_mgr.current_obj_id
        obj_type = self._editor_mgr.current_obj_type
        # Close the editor session *before* the restore so that no stale
        # ORM connection interferes with ``_restore_db`` (which drops and
        # recreates all tables via raw SQL on the shared StaticPool
        # connection).
        self._close_editor()
        if self._db_manager.undo():
            self._refresh_after_history_change(obj_id, obj_type)

    @Slot()
    def _do_redo(self):
        obj_id = self._editor_mgr.current_obj_id
        obj_type = self._editor_mgr.current_obj_type
        self._close_editor()
        if self._db_manager.redo():
            self._refresh_after_history_change(obj_id, obj_type)

    @Slot(int)
    def _on_undo_list_clicked(self, row):
        if row < 0:
            return
        obj_id = self._editor_mgr.current_obj_id
        obj_type = self._editor_mgr.current_obj_type
        self._close_editor()
        # List rows are offset by 1 because State 0 is hidden.
        if self._db_manager.jump_to(row + 1):
            self._refresh_after_history_change(obj_id, obj_type)

    def _on_history_changed(self):
        self._update_undo_actions()
        self._update_undo_list()
        self._update_title()

    def _update_undo_actions(self):
        self._undo_action.setEnabled(self._db_manager.can_undo)
        self._redo_action.setEnabled(self._db_manager.can_redo)

    def _update_undo_list(self):
        self.undoView.blockSignals(True)
        self.undoView.clear()
        for snap in self._db_manager.get_history():
            if snap.index == 0:
                continue
            self.undoView.addItem(snap.description or f'State {snap.index}')
            if snap.is_current:
                self.undoView.setCurrentRow(snap.index - 1)
        self.undoView.blockSignals(False)

    def _refresh_after_history_change(self, obj_id=None, obj_type=None):
        self._rs_mgr.reload_views()

        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=file_key)
        self._find_panel.reset()
        self._where_used_panel.reset()
        if obj_id is not None:
            self._open_object_editor(obj_id, obj_type)

    def _flush_editor_changes(self):
        """Apply any pending editor widget changes to the database."""
        self._editor_mgr.flush()

    def _close_editor(self):
        """Close the current editor session."""
        self._editor_mgr.close()

    def _on_editor_object_saved(self, obj):
        """Update tree item after editor saves an object."""
        self._object_tree.update_item(obj)

    def _on_firewall_modified(self, fw_id):
        """Update the Firewall tree item after a rule mutation stamped it."""
        with self._db_manager.session() as session:
            fw = session.get(Firewall, fw_id)
            if fw is not None:
                self._object_tree.update_item(fw)

    def _show_traceback_error(self, summary):
        """Show a critical error dialog with the current traceback.

        The traceback is placed in a scrollable detailed-text area so
        it does not dominate the screen and can easily be copied.
        """
        dlg = QMessageBox(
            QMessageBox.Icon.Critical,
            'FirewallFabrik',
            summary,
            QMessageBox.StandardButton.Ok,
            self,
        )
        dlg.setDetailedText(traceback.format_exc())
        dlg.exec()

    # ------------------------------------------------------------------
    # Stub slots for .ui connections not yet implemented
    # ------------------------------------------------------------------

    @Slot()
    def editFind(self):
        # TODO
        pass

    @Slot(int)
    def editorPanelTabChanged(self, _index):
        # TODO
        pass

    @Slot()
    def fileCompare(self):
        # TODO
        pass

    @Slot()
    def fileExport(self):
        # TODO
        pass

    @Slot()
    def fileImport(self):
        # TODO
        pass

    @Slot()
    def filePrint(self):
        # TODO
        pass

    @Slot()
    def helpContents(self):
        # TODO
        pass

    @Slot()
    def helpIndex(self):
        # TODO
        pass

    @Slot()
    def importPolicy(self):
        # TODO
        pass

    @Slot()
    def lockObject(self):
        # TODO
        pass

    @Slot()
    def toolsImportAddressesFromFile(self):
        # TODO
        pass

    @Slot()
    def toolsSNMPDiscovery(self):
        # TODO
        pass

    @Slot()
    def unlockObject(self):
        # TODO
        pass

    @staticmethod
    def _gather_all_tags(session):
        """Collect every tag used across all object tables."""
        return EditorManager.gather_all_tags(session)
