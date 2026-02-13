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
import uuid
from pathlib import Path

import sqlalchemy
import sqlalchemy.exc
from PySide6.QtCore import (
    QByteArray,
    QModelIndex,
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
    QApplication,
    QDialog,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMdiSubWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QVBoxLayout,
)

from firewallfabrik import __version__
from firewallfabrik.core import DatabaseManager, duplicate_object_name
from firewallfabrik.core.objects import (
    Address,
    FWObjectDatabase,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    Rule,
    RuleSet,
    Service,
)
from firewallfabrik.gui.about_dialog import AboutDialog
from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.debug_dialog import DebugDialog
from firewallfabrik.gui.find_panel import FindPanel
from firewallfabrik.gui.find_where_used_panel import FindWhereUsedPanel
from firewallfabrik.gui.object_tree import (
    ICON_MAP,
    ObjectTree,
    create_library_folder_structure,
)
from firewallfabrik.gui.policy_model import (
    PolicyTreeModel,
    _action_label,
)
from firewallfabrik.gui.policy_view import PolicyView, RuleSetPanel
from firewallfabrik.gui.preferences_dialog import PreferencesDialog
from firewallfabrik.gui.ui_loader import FWFUiLoader

logger = logging.getLogger(__name__)

_DEFAULT_WIDTH = 1024
_DEFAULT_HEIGHT = 768

# Messages shown when double-clicking an "Any" element in a rule cell.
# Keyed by slot name so they work for Policy, NAT and Routing rule sets.
_ANY_MSG_ADDRESS = (
    'When used in the Source or Destination field of a rule, '
    'the Any object will match all IP addresses. '
    'To update your rule to match only specific IP addresses, '
    'drag-and-drop an object from the Object tree into the field '
    'in the rule.'
)
_ANY_MSG_INTERFACE = (
    'When used in an Interface field of a rule, '
    'the Any object will match all interfaces. '
    'To update your rule to match only a specific interface, '
    'drag-and-drop an object from the Object tree into the field '
    'in the rule.'
)
_ANY_MSG_SERVICE = (
    'When used in the Service field of a rule, '
    'the Any object will match all IP, ICMP, TCP or UDP services. '
    'To update your rule to match only specific service, '
    'drag-and-drop an object from the Object tree into the field '
    'in the rule.'
)
_ANY_MSG_TIME = (
    'When used in the Time Interval field of a rule, '
    'the Any object will match any time of the day or day '
    'of the week. To update your rule to match only specific '
    'service, drag-and-drop an object from the Object tree into '
    'the field in the rule.'
)
_ANY_MESSAGES = {
    # Policy
    'dst': _ANY_MSG_ADDRESS,
    'itf': _ANY_MSG_INTERFACE,
    'src': _ANY_MSG_ADDRESS,
    'srv': _ANY_MSG_SERVICE,
    'when': _ANY_MSG_TIME,
    # NAT
    'itf_inb': _ANY_MSG_INTERFACE,
    'itf_outb': _ANY_MSG_INTERFACE,
    'odst': _ANY_MSG_ADDRESS,
    'osrc': _ANY_MSG_ADDRESS,
    'osrv': _ANY_MSG_SERVICE,
    'tdst': _ANY_MSG_ADDRESS,
    'tsrc': _ANY_MSG_ADDRESS,
    'tsrv': _ANY_MSG_SERVICE,
    # Routing
    'rdst': _ANY_MSG_ADDRESS,
    'rgtw': _ANY_MSG_ADDRESS,
    'ritf': _ANY_MSG_INTERFACE,
}
_ANY_ICON_TYPE = {
    'dst': 'Network',
    'itf': 'Interface',
    'itf_inb': 'Interface',
    'itf_outb': 'Interface',
    'odst': 'Network',
    'osrc': 'Network',
    'osrv': 'IPService',
    'rdst': 'Network',
    'rgtw': 'Network',
    'ritf': 'Interface',
    'src': 'Network',
    'srv': 'IPService',
    'tdst': 'Network',
    'tsrc': 'Network',
    'tsrv': 'IPService',
    'when': 'Interval',
}

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


def _device_prefix(obj):
    """Return ``'device_name: '`` if *obj* is a child of a device, else ``''``.

    Walks up the ORM parent chain looking for a :class:`Host` (the base
    class for Firewall / Cluster / Host).
    """
    current = obj
    while current is not None:
        if isinstance(current, Host):
            return f'{current.name}: '
        if isinstance(current, Address):
            current = current.interface or current.group or current.library
        elif isinstance(current, Interface):
            current = current.device or current.library
        elif isinstance(current, RuleSet):
            current = current.device
        elif isinstance(current, Rule):
            rs = current.rule_set
            current = rs.device if rs else None
        else:
            break
    return ''


def _undo_desc(action, obj_type, name, old_name=None, prefix=''):
    """Build a short undo description.

    Supported *action* values: ``Delete``, ``Edit``, ``New``, ``Rename``.
    For ``Rename``, *old_name* must be provided.
    *prefix* is prepended as-is (e.g. ``"fw-test: "``).
    """
    if action == 'Rename':
        return f'{prefix}Rename {obj_type} {old_name} > {name}'
    return f'{prefix}{action} {obj_type} {name}'


def _build_editor_path(obj):
    """Build a ``" / "``-separated path from *obj* up to its Library.

    Mirrors fwbuilder's ``buildEditorTitleAndIcon()`` — walk up the ORM
    parent chain, collect names, and join them root-first.
    """
    parts = []
    current = obj
    while current is not None:
        parts.append(current.name)
        if isinstance(current, Library):
            break
        # Determine the parent depending on object type.
        if isinstance(current, Address):
            current = current.interface or current.group or current.library
        elif isinstance(current, Interface):
            current = current.device or current.library
        elif isinstance(current, (Host, Service, Interval)):
            current = current.group or current.library
        elif isinstance(current, Group):
            current = current.parent_group or current.library
        else:
            break
    parts.reverse()
    return ' / '.join(parts)


FILE_FILTERS = 'FirewallFabrik Files *.fwf (*.fwf);;Firewall Builder Files *.fwb (*.fwb);;All Files (*)'
_MAX_RECENT_FILES = 20

# Map object type discriminator strings to their SQLAlchemy model class.
_MODEL_MAP = {
    'AddressRange': Address,
    'AddressTable': Group,
    'Cluster': Host,
    'CustomService': Service,
    'DNSName': Group,
    'DynamicGroup': Group,
    'Firewall': Host,
    'Host': Host,
    'ICMP6Service': Service,
    'ICMPService': Service,
    'IPService': Service,
    'IPv4': Address,
    'IPv6': Address,
    'Interface': Interface,
    'Interval': Interval,
    'IntervalGroup': Group,
    'Library': Library,
    'Network': Address,
    'NetworkIPv6': Address,
    'ObjectGroup': Group,
    'PhysAddress': Address,
    'ServiceGroup': Group,
    'TCPService': Service,
    'TagService': Service,
    'UDPService': Service,
    'UserService': Service,
}


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
        self.toolBar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
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
        self._object_tree.rule_set_activated.connect(self._open_rule_set)
        self._object_tree.object_activated.connect(self._open_object_editor)
        self._object_tree.tree_changed.connect(self._on_tree_changed)
        self._object_tree.set_db_manager(self._db_manager)

        self._editor_map = {
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
            'Network': self.w_NetworkDialog,
            'NetworkIPv6': self.w_NetworkDialogIPv6,
            'ObjectGroup': self.w_ObjectGroupDialog,
            'PhysAddress': self.w_PhysicalAddressDialog,
            'ServiceGroup': self.w_ServiceGroupDialog,
            'TCPService': self.w_TCPServiceDialog,
            'TagService': self.w_TagServiceDialog,
            'UDPService': self.w_UDPServiceDialog,
            'UserService': self.w_UserDialog,
        }

        # Connect changed signal on all editor dialogs for auto-save.
        for widget in set(self._editor_map.values()):
            if isinstance(widget, BaseObjectDialog):
                widget.changed.connect(self._on_editor_changed)

        self._current_editor = None
        self._editor_session = None

        # Blank-dialog label for "Any" object messages.
        self._blank_label = QLabel(self.w_BlankDialog)
        self._blank_label.setWordWrap(True)
        self._blank_label.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft,
        )
        self._blank_label.setContentsMargins(10, 10, 10, 10)
        QVBoxLayout(self.w_BlankDialog).addWidget(self._blank_label)

        # Find panel — embedded in the "Find" tab of the editor dock.
        self._find_panel = FindPanel()
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_reload_callback(self._reload_rule_set_views)
        self._find_panel.set_open_rule_set_ids_callback(self._get_open_rule_set_ids)
        self.find_panel.layout().addWidget(self._find_panel)
        self._find_panel.object_found.connect(self._open_object_editor)
        self._find_panel.navigate_to_rule.connect(self._navigate_to_rule_match)
        self.findAction.triggered.connect(self._show_find_panel)

        # Where Used panel — embedded in the "Where Used" tab.
        self._where_used_panel = FindWhereUsedPanel()
        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.set_db_manager(self._db_manager)
        self.where_used_panel.layout().addWidget(self._where_used_panel)
        self._where_used_panel.object_found.connect(self._open_object_editor)
        self._where_used_panel.navigate_to_rule.connect(self._navigate_to_rule_match)

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

    @staticmethod
    def _register_resources(ui_path):
        """Compile MainRes.qrc to a binary .rcc (if needed) and register it."""
        qrc = ui_path / 'MainRes.qrc'
        rcc = ui_path / 'MainRes.rcc'
        if not rcc.exists() or rcc.stat().st_mtime < qrc.stat().st_mtime:
            subprocess.run(
                ['pyside6-rcc', '--binary', str(qrc), '-o', str(rcc)],
                check=True,
            )
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
        """Hide panels when no database file is loaded."""
        self._object_tree.setVisible(False)
        self.editorDockWidget.setVisible(False)
        self.undoDockWidget.setVisible(False)

    def _apply_file_loaded_state(self):
        """Restore panel visibility from QSettings after loading a file."""
        settings = QSettings()
        tree_visible = settings.value('View/ObjectTree', True, type=bool)
        self._object_tree.setVisible(tree_visible)
        self.actionObject_Tree.setChecked(tree_visible)
        editor_visible = settings.value('View/EditorPanel', True, type=bool)
        self.editorDockWidget.setVisible(editor_visible)
        self.actionEditor_panel.setChecked(editor_visible)
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
        name = display.name if display else 'Untitled'
        result = QMessageBox.information(
            self,
            'FirewallFabrik',
            self.tr(
                f'Some objects have been modified but not saved.\n'
                f'Do you want to save {name} now?'
            ),
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel,
        )
        if result == QMessageBox.StandardButton.Save:
            self.fileSave()
            return True
        return result == QMessageBox.StandardButton.Discard

    def _update_title(self):
        display = getattr(self, '_display_file', None) or self._current_file
        if display:
            self.setWindowTitle(
                f'{display.name} - FirewallFabrik {__version__}',
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

        # Close current state (mirrors fileClose but without the save prompt).
        self._close_editor()
        self.m_space.closeAllSubWindows()
        self._object_tree._tree.clear()
        self._object_tree._filter.clear()
        self.undoView.clear()

        # Create new database: load the Standard library, then add an
        # empty "User" library (mirrors fwbuilder's loadStandardObjects).
        self._db_manager = DatabaseManager()
        self._db_manager.on_history_changed = self._on_history_changed
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
        self._update_title()
        self._add_to_recent(str(file_path))

        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=str(file_path))

        self._object_tree.set_db_manager(self._db_manager)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_reload_callback(self._reload_rule_set_views)
        self._find_panel.set_open_rule_set_ids_callback(self._get_open_rule_set_ids)
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
            self._update_title()
            self._add_to_recent(str(self._current_file))

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
        self._update_title()
        self._add_to_recent(str(file_path))

    @Slot()
    def fileClose(self):
        if not self._save_if_modified():
            return
        display = getattr(self, '_display_file', None)
        if display:
            self._object_tree.save_tree_state(str(display))
        self._close_editor()
        self.m_space.closeAllSubWindows()
        self._object_tree._tree.clear()
        self._object_tree._filter.clear()
        self.undoView.clear()
        self._db_manager = DatabaseManager()
        self._db_manager.on_history_changed = self._on_history_changed
        self._current_file = None
        self._display_file = None
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
        if not self._current_file:
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr('No file is loaded. Open or create a file first.'),
            )
            return
        if self._db_manager.is_dirty:
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
        libs = self._object_tree._get_writable_libraries()
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
            self._object_tree.create_new_object_in_library(
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
            self._object_tree.create_host_in_library(
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
            self._object_tree.create_new_object_in_library(
                type_name,
                lib_id,
                extra_data=extra_data,
                name=name,
            )
        else:
            self._object_tree.create_new_object_in_library(type_name, lib_id)

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

        self._close_editor()
        self.m_space.closeAllSubWindows()

        original_path = file_path
        try:
            self._db_manager = DatabaseManager()
            self._db_manager.on_history_changed = self._on_history_changed
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

        self._current_file = file_path
        self._display_file = original_path
        self._update_title()
        self._add_to_recent(str(original_path))

        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=str(original_path))

        self._object_tree.set_db_manager(self._db_manager)
        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_reload_callback(self._reload_rule_set_views)
        self._find_panel.set_open_rule_set_ids_callback(self._get_open_rule_set_ids)
        self._find_panel.reset()

        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.set_db_manager(self._db_manager)
        self._where_used_panel.reset()

        self.newObjectAction.setEnabled(
            bool(self._object_tree._get_writable_libraries())
        )
        self._apply_file_loaded_state()
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

    @Slot(str, str, str, str)
    def _open_rule_set(self, rule_set_id, fw_name, rs_name, rs_type='Policy'):
        """Open a rule set in a new MDI sub-window (triggered by tree double-click)."""
        model = PolicyTreeModel(
            self._db_manager,
            uuid.UUID(rule_set_id),
            rule_set_type=rs_type,
            object_name=fw_name,
        )
        panel = RuleSetPanel()
        panel.policy_view.setModel(model)

        sub = QMdiSubWindow()
        sub.setWidget(panel)
        sub.setWindowTitle(f'{fw_name} / {rs_name}')
        sub.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.m_space.addSubWindow(sub)
        sub.showMaximized()

    @Slot(str, str)
    def _open_object_editor(self, obj_id, obj_type):
        """Open the editor panel for the given object (triggered by tree double-click)."""
        dialog_widget = self._editor_map.get(obj_type)
        if dialog_widget is None:
            return

        model_cls = _MODEL_MAP.get(obj_type)
        if model_cls is None:
            return

        # Flush pending changes from the current editor before switching.
        self._flush_editor_changes()

        # Close any previous editor session to avoid leaks.
        if self._editor_session is not None:
            self._editor_session.close()

        self._editor_session = self._db_manager.create_session()
        obj = self._editor_session.get(model_cls, uuid.UUID(obj_id))
        if obj is None:
            self._editor_session.close()
            self._editor_session = None
            return

        all_tags = self._gather_all_tags(self._editor_session)
        dialog_widget.load_object(obj, all_tags=all_tags)
        self._current_editor = dialog_widget
        self._editor_obj_id = obj_id
        self._editor_obj_name = obj.name
        self._editor_obj_type = obj_type

        # The dialog widget sits inside a page's layout, not as a direct
        # page of the stacked widget — switch to its parent page instead.
        self.objectEditorStack.setCurrentWidget(dialog_widget.parentWidget())
        self._show_editor_panel()

        path = _build_editor_path(obj)
        if self._current_file:
            path = f'[{self._current_file}] / {path}'
        self.editorDockWidget.setWindowTitle(path)

        icon_path = f':/Icons/{obj_type}/icon-big'
        pixmap = QIcon(icon_path).pixmap(64, 64)
        if not pixmap.isNull():
            self.objectTypeIcon.setPixmap(pixmap)

        if not self.editorDockWidget.isVisible():
            self.editorDockWidget.setVisible(True)
            self.actionEditor_panel.setChecked(True)

    @Slot()
    def _on_editor_changed(self):
        """Handle a change in the active editor: apply and commit."""
        editor = self._current_editor
        session = self._editor_session
        if editor is None or session is None:
            return
        editor.apply_all()
        # Capture path while the session is still usable (before a
        # potential rollback which would expire all ORM state).
        obj = getattr(editor, '_obj', None)
        obj_path = _build_editor_path(obj) if obj else None

        # Nothing to persist (e.g. checkbox toggled back to the same
        # value) — skip the commit and undo-stack entry entirely.
        if not (session.new or session.dirty or session.deleted):
            return

        try:
            session.commit()
        except sqlalchemy.exc.IntegrityError as e:
            session.rollback()
            if 'UNIQUE constraint failed' in str(e):
                if obj_path:
                    detail = obj_path.replace(' / ', ' > ')
                    msg = self.tr(f'Duplicate names are not allowed: {detail}')
                else:
                    msg = self.tr('Duplicate names are not allowed.')
                QMessageBox.critical(self, 'FirewallFabrik', msg)
            else:
                logger.exception('Commit failed')
            return

        # Build a human-readable undo description.
        obj = getattr(editor, '_obj', None)
        if obj is not None:
            prefix = _device_prefix(obj)
            obj_type = getattr(obj, 'type', type(obj).__name__)
            old_name = getattr(self, '_editor_obj_name', '')
            new_name = obj.name
            if old_name and new_name != old_name:
                desc = _undo_desc(
                    'Rename',
                    obj_type,
                    new_name,
                    old_name=old_name,
                    prefix=prefix,
                )
            else:
                desc = _undo_desc('Edit', obj_type, new_name, prefix=prefix)
            self._editor_obj_name = new_name
        else:
            desc = 'Editor change'
        self._db_manager.save_state(desc)

        # Keep the tree in sync with the editor.
        if obj is not None:
            self._object_tree.update_item(obj)

    def _on_tree_changed(self):
        """Refresh the tree and editor after a CRUD operation (e.g. duplicate, delete)."""
        obj_id = getattr(self, '_editor_obj_id', None)
        obj_type = getattr(self, '_editor_obj_type', None)
        self._close_editor()

        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=file_key)

        # Re-open the editor for the same object (refreshes all fields).
        if obj_id is not None:
            self._open_object_editor(obj_id, obj_type)

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
        if not self.editorDockWidget.isVisible():
            self.editorDockWidget.setVisible(True)
            self.actionEditor_panel.setChecked(True)
        self.editorPanelTabWidget.setCurrentIndex(0)

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

        # Collapse runs of whitespace (except newlines) in the output.
        if result:
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
        self._close_editor()

        self.w_CommentEditorPanel.load_rule(model, index)
        self.objectEditorStack.setCurrentWidget(
            self.w_CommentEditorPanel.parentWidget(),
        )
        self._show_editor_panel()
        self.editorDockWidget.setWindowTitle('Comment')

        pixmap = QIcon(':/Icons/Comment/icon-big').pixmap(64, 64)
        if pixmap.isNull():
            pixmap = QIcon(':/Icons/Policy/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self.objectTypeIcon.setPixmap(pixmap)

    def open_rule_options(self, model, index):
        """Open the rule options panel in the editor pane."""
        # Close any current object editor session.
        self._close_editor()

        self.w_RuleOptionsDialog.load_rule(model, index)
        self.objectEditorStack.setCurrentWidget(
            self.w_RuleOptionsDialog.parentWidget(),
        )
        self._show_editor_panel()
        self.editorDockWidget.setWindowTitle('Rule Options')

        pixmap = QIcon(':/Icons/Options/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self.objectTypeIcon.setPixmap(pixmap)

    def open_action_editor(self, model, index):
        """Open the action parameters panel in the editor pane."""
        self._close_editor()

        self.w_ActionsDialog.load_rule(model, index)
        self.objectEditorStack.setCurrentWidget(
            self.w_ActionsDialog.parentWidget(),
        )
        self._show_editor_panel()

        # Determine the action name for title and icon.
        row_data = model.get_row_data(index)
        action_enum = 'Policy'
        if row_data is not None:
            action_enum = row_data.action or 'Policy'
        self.editorDockWidget.setWindowTitle(
            f'Action: {_action_label(action_enum)}',
        )

        icon_path = f':/Icons/{action_enum}/icon-big'
        pixmap = QIcon(icon_path).pixmap(64, 64)
        if pixmap.isNull():
            pixmap = QIcon(':/Icons/Policy/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self.objectTypeIcon.setPixmap(pixmap)

    def open_direction_editor(self, model, index):
        """Open the (blank) direction pane in the editor pane."""
        self._close_editor()

        self._blank_label.clear()
        self.objectEditorStack.setCurrentWidget(
            self.w_BlankDialog.parentWidget(),
        )
        self._show_editor_panel()

        row_data = model.get_row_data(index)
        direction_name = 'Both'
        if row_data is not None:
            direction_name = row_data.direction or 'Both'
        self.editorDockWidget.setWindowTitle(f'Direction: {direction_name}')

        icon_path = f':/Icons/{direction_name}/icon-big'
        pixmap = QIcon(icon_path).pixmap(64, 64)
        if pixmap.isNull():
            pixmap = QIcon(':/Icons/Policy/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self.objectTypeIcon.setPixmap(pixmap)

    def show_any_editor(self, slot):
        """Show the 'Any' object description in the editor pane."""
        self._close_editor()

        msg = _ANY_MESSAGES.get(slot, '')
        self._blank_label.setText(msg)
        self.objectEditorStack.setCurrentWidget(
            self.w_BlankDialog.parentWidget(),
        )
        self._show_editor_panel()
        self.editorDockWidget.setWindowTitle('Any')

        icon_type = _ANY_ICON_TYPE.get(slot, 'Policy')
        pixmap = QIcon(f':/Icons/{icon_type}/icon-big').pixmap(64, 64)
        if not pixmap.isNull():
            self.objectTypeIcon.setPixmap(pixmap)

    def show_where_used(self, obj_id, name, obj_type):
        """Show where-used results for the given object."""
        self._show_where_used_panel()
        self._where_used_panel.find_object(obj_id, name, obj_type)

    @staticmethod
    def _policy_view_from_widget(widget):
        """Extract a :class:`PolicyView` from a sub-window widget."""
        if isinstance(widget, RuleSetPanel):
            return widget.policy_view
        if isinstance(widget, PolicyView):
            return widget
        return None

    def _active_policy_view(self):
        """Return the active :class:`PolicyView`, or *None*."""
        sub = self.m_space.activeSubWindow()
        if sub is not None:
            return self._policy_view_from_widget(sub.widget())
        return None

    def _tree_has_focus(self):
        """Return True if the object tree widget has keyboard focus.

        Specifically checks for the tree widget itself (not the filter
        QLineEdit) so that Ctrl+C in the filter field still copies text.
        """
        focus = QApplication.focusWidget()
        if focus is None:
            return False
        tree_widget = self._object_tree._tree
        return focus is tree_widget or tree_widget.isAncestorOf(focus)

    @Slot()
    def editCopy(self):
        """Handle Ctrl+C — route to tree or policy view based on focus.

        In the policy view this mimics fwbuilder: if a single element
        is selected in an element column, copy that element; otherwise
        copy whole rules.
        """
        if self._tree_has_focus():
            self._object_tree._shortcut_copy()
            return
        view = self._active_policy_view()
        if view is not None:
            view.copy_object()

    @Slot()
    def editCut(self):
        """Handle Ctrl+X — route to tree or policy view based on focus.

        In the policy view this mimics fwbuilder: if a single element
        is selected in an element column, cut that element; otherwise
        cut whole rules.
        """
        if self._tree_has_focus():
            self._object_tree._shortcut_cut()
            return
        view = self._active_policy_view()
        if view is not None:
            view.cut_object()

    @Slot()
    def editPaste(self):
        """Handle Ctrl+V — route to tree or policy view based on focus.

        Connected via the .ui file: ``editPasteAction.triggered() → editPaste()``.

        In the policy view, this mimics fwbuilder's
        ``RuleSetView::pasteObject()`` — if the clipboard holds a
        regular object (not a rule), paste it into the current cell;
        otherwise paste rules below.
        """
        if self._tree_has_focus():
            self._object_tree._shortcut_paste()
            return
        view = self._active_policy_view()
        if view is not None:
            view.paste_object()

    @Slot()
    def editDelete(self):
        """Handle Delete key — route to tree or policy view based on focus."""
        if self._tree_has_focus():
            self._object_tree._shortcut_delete()
            return
        view = self._active_policy_view()
        if view is not None:
            view.delete_selection()

    def _reload_rule_set_views(self):
        """Reload all open PolicyTreeModel views (after replace)."""
        for sub in self.m_space.subWindowList():
            view = self._policy_view_from_widget(sub.widget())
            if view is not None and isinstance(view.model(), PolicyTreeModel):
                view.model().reload()

    def _get_open_rule_set_ids(self) -> set[uuid.UUID]:
        """Return the set of rule set IDs currently open in MDI sub-windows."""
        ids = set()
        for sub in self.m_space.subWindowList():
            view = self._policy_view_from_widget(sub.widget())
            if view is not None and isinstance(view.model(), PolicyTreeModel):
                ids.add(view.model().rule_set_id)
        return ids

    @Slot(str, str, str)
    def _navigate_to_rule_match(self, rule_set_id, rule_id, slot):
        """Navigate to a rule element match in a policy view."""
        rs_uuid = uuid.UUID(rule_set_id)
        r_uuid = uuid.UUID(rule_id)

        # Look for an existing sub-window with this rule set.
        for sub in self.m_space.subWindowList():
            view = self._policy_view_from_widget(sub.widget())
            if (
                view is not None
                and isinstance(view.model(), PolicyTreeModel)
                and view.model().rule_set_id == rs_uuid
            ):
                self.m_space.setActiveSubWindow(sub)
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
        panel = RuleSetPanel()
        panel.policy_view.setModel(model)

        sub = QMdiSubWindow()
        sub.setWidget(panel)
        sub.setWindowTitle(f'{fw_name} / {rs_name}')
        sub.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.m_space.addSubWindow(sub)
        sub.showMaximized()

        self._scroll_to_rule(panel.policy_view, model, r_uuid, slot)

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
        # Close the editor session *before* the restore so that no stale
        # ORM connection interferes with ``_restore_db`` (which drops and
        # recreates all tables via raw SQL on the shared StaticPool
        # connection).
        self._close_editor()
        if self._db_manager.undo():
            self._refresh_after_history_change()

    @Slot()
    def _do_redo(self):
        self._close_editor()
        if self._db_manager.redo():
            self._refresh_after_history_change()

    @Slot(int)
    def _on_undo_list_clicked(self, row):
        if row < 0:
            return
        self._close_editor()
        # List rows are offset by 1 because State 0 is hidden.
        if self._db_manager.jump_to(row + 1):
            self._refresh_after_history_change()

    def _on_history_changed(self):
        self._update_undo_actions()
        self._update_undo_list()

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

    def _refresh_after_history_change(self):
        obj_id = getattr(self, '_editor_obj_id', None)
        obj_type = getattr(self, '_editor_obj_type', None)
        self._close_editor()

        # Reload open rule set models instead of closing all subwindows.
        for sub in self.m_space.subWindowList():
            view = self._policy_view_from_widget(sub.widget())
            if view is not None and isinstance(view.model(), PolicyTreeModel):
                view.model().reload()

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
        """Apply any pending editor widget changes to the database.

        QLineEdit only fires ``editingFinished`` on focus loss or Enter.
        When the user presses Ctrl+S (or switches objects, closes files,
        etc.) while a QLineEdit still has focus, the signal hasn't fired
        yet.  Calling this method ensures the current widget values are
        written to the ORM object and committed before any save/close
        operation.
        """
        if self._current_editor is not None and self._editor_session is not None:
            self._on_editor_changed()

    def _close_editor(self):
        self._flush_editor_changes()
        if self._editor_session is not None:
            self._editor_session.close()
        self._editor_session = None
        self._current_editor = None
        self.editorDockWidget.setWindowTitle('Editor')

    @staticmethod
    def _gather_all_tags(session):
        """Collect every tag used across all object tables."""
        all_tags = set()
        for cls in (Address, Group, Host, Interface, Interval, Service):
            for (tag_set,) in session.execute(sqlalchemy.select(cls.keywords)):
                if tag_set:
                    all_tags.update(tag_set)
        return all_tags
