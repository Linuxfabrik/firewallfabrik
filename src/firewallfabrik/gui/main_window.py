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

import logging
import subprocess
import uuid
from pathlib import Path

import sqlalchemy
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
    QDesktopServices,
    QGuiApplication,
    QIcon,
    QKeySequence,
)
from PySide6.QtWidgets import (
    QFileDialog,
    QMainWindow,
    QMdiSubWindow,
    QMessageBox,
    QSplitter,
)

from firewallfabrik import __version__
from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    RuleSet,
    Service,
)
from firewallfabrik.gui.about_dialog import AboutDialog
from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.debug_dialog import DebugDialog
from firewallfabrik.gui.find_panel import FindPanel
from firewallfabrik.gui.find_where_used_panel import FindWhereUsedPanel
from firewallfabrik.gui.object_tree import ObjectTree
from firewallfabrik.gui.policy_model import PolicyTreeModel
from firewallfabrik.gui.policy_view import PolicyView
from firewallfabrik.gui.preferences_dialog import PreferencesDialog
from firewallfabrik.gui.ui_loader import FWFUiLoader

logger = logging.getLogger(__name__)

_DEFAULT_WIDTH = 1024
_DEFAULT_HEIGHT = 768


def _undo_desc(action, obj_type, name, old_name=None):
    """Build a short undo description.

    Supported *action* values: ``Delete``, ``Edit``, ``New``, ``Rename``.
    For ``Rename``, *old_name* must be provided.
    """
    if action == 'Rename':
        return f'Rename {obj_type} {old_name} > {name}'
    return f'{action} {obj_type} {name}'


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
    'IPv4': Address,
    'IPv6': Address,
    'Network': Address,
    'NetworkIPv6': Address,
    'AddressRange': Address,
    'PhysAddress': Address,
    'Host': Host,
    'Firewall': Host,
    'Cluster': Host,
    'Interface': Interface,
    'TCPService': Service,
    'UDPService': Service,
    'ICMPService': Service,
    'ICMP6Service': Service,
    'IPService': Service,
    'ObjectGroup': Group,
    'ServiceGroup': Group,
    'IntervalGroup': Group,
    'Interval': Interval,
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
        icon_path = (
            Path(__file__).resolve().parent / 'ui' / 'Images' / 'fwbuilder3-128x128.png'
        )
        self.setWindowIcon(QIcon(str(icon_path)))
        self.toolBar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

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

        self._editor_map = {
            'IPv4': self.w_IPv4Dialog,
            'IPv6': self.w_IPv6Dialog,
            'Network': self.w_NetworkDialog,
            'NetworkIPv6': self.w_NetworkDialogIPv6,
            'AddressRange': self.w_AddressRangeDialog,
            'PhysAddress': self.w_PhysicalAddressDialog,
            'Host': self.w_HostDialog,
            'Firewall': self.w_FirewallDialog,
            'Cluster': self.w_FirewallDialog,
            'Interface': self.w_InterfaceDialog,
            'TCPService': self.w_TCPServiceDialog,
            'UDPService': self.w_UDPServiceDialog,
            'ICMPService': self.w_ICMPServiceDialog,
            'ICMP6Service': self.w_ICMP6ServiceDialog,
            'IPService': self.w_IPServiceDialog,
            'ObjectGroup': self.w_ObjectGroupDialog,
            'ServiceGroup': self.w_ServiceGroupDialog,
            'IntervalGroup': self.w_IntervalGroupDialog,
            'Interval': self.w_TimeDialog,
        }

        # Connect changed signal on all editor dialogs for auto-save.
        for widget in self._editor_map.values():
            if isinstance(widget, BaseObjectDialog):
                widget.changed.connect(self._on_editor_changed)

        self._current_editor = None
        self._editor_session = None

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
        self._undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self._undo_action.setEnabled(False)
        self._undo_action.triggered.connect(self._do_undo)
        self._redo_action = QAction('&Redo', self)
        self._redo_action.setShortcuts(
            [QKeySequence.StandardKey.Redo, QKeySequence('Ctrl+Y')]
        )
        self._redo_action.setEnabled(False)
        self._redo_action.triggered.connect(self._do_redo)
        first_action = self.editMenu.actions()[0] if self.editMenu.actions() else None
        self.editMenu.insertAction(first_action, self._undo_action)
        self.editMenu.insertAction(first_action, self._redo_action)

        # Clipboard actions — forward to the active PolicyView.
        self.editCopyAction.triggered.connect(self._on_edit_copy)
        self.editCutAction.triggered.connect(self._on_edit_cut)
        self.editPasteAction.triggered.connect(self._on_edit_paste)

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
        # reads after restoreState().
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

    def _save_if_modified(self):
        """Prompt the user to save unsaved changes.

        Returns ``True`` if the caller may proceed (saved or discarded),
        ``False`` if the user chose Cancel.
        """
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
        # Like C++ ProjectPanel::fileNew() / chooseNewFileName():
        # prompt for a location, enforce .fwf suffix, then create the file.
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

        file_path.touch()
        self._current_file = file_path
        self._display_file = file_path
        self._update_title()

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
    def debug(self):
        dlg = DebugDialog(self)
        dlg.exec()

    @Slot()
    def helpAbout(self):
        dlg = AboutDialog(self)
        dlg.exec()

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

        self._find_panel.set_tree(self._object_tree._tree)
        self._find_panel.set_db_manager(self._db_manager)
        self._find_panel.set_reload_callback(self._reload_rule_set_views)
        self._find_panel.set_open_rule_set_ids_callback(self._get_open_rule_set_ids)
        self._find_panel.reset()

        self._where_used_panel.set_tree(self._object_tree._tree)
        self._where_used_panel.set_db_manager(self._db_manager)
        self._where_used_panel.reset()

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

    @Slot(str, str, str)
    def _open_rule_set(self, rule_set_id, fw_name, rs_name):
        """Open a rule set in a new MDI sub-window (triggered by tree double-click)."""
        model = PolicyTreeModel(
            self._db_manager, uuid.UUID(rule_set_id), object_name=fw_name
        )
        view = PolicyView()
        view.setModel(model)

        sub = QMdiSubWindow()
        sub.setWidget(view)
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
        session.commit()

        # Build a human-readable undo description.
        obj = getattr(editor, '_obj', None)
        if obj is not None:
            obj_type = getattr(obj, 'type', type(obj).__name__)
            old_name = getattr(self, '_editor_obj_name', '')
            new_name = obj.name
            if old_name and new_name != old_name:
                desc = _undo_desc('Rename', obj_type, new_name, old_name=old_name)
            else:
                desc = _undo_desc('Edit', obj_type, new_name)
            self._editor_obj_name = new_name
        else:
            desc = 'Editor change'
        self._db_manager.save_state(desc)

        # Keep the tree in sync with the editor.
        if obj is not None:
            self._object_tree.update_item(obj)

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

    def show_where_used(self, obj_id, name, obj_type):
        """Show where-used results for the given object."""
        self._show_where_used_panel()
        self._where_used_panel.find_object(obj_id, name, obj_type)

    def _active_policy_view(self):
        """Return the active :class:`PolicyView`, or *None*."""
        sub = self.m_space.activeSubWindow()
        if sub is not None:
            widget = sub.widget()
            if isinstance(widget, PolicyView):
                return widget
        return None

    @Slot()
    def _on_edit_copy(self):
        view = self._active_policy_view()
        if view is not None:
            view.copy_selection()

    @Slot()
    def _on_edit_cut(self):
        view = self._active_policy_view()
        if view is not None:
            view.cut_selection()

    @Slot()
    def _on_edit_paste(self):
        view = self._active_policy_view()
        if view is not None:
            view.paste_below()

    def _reload_rule_set_views(self):
        """Reload all open PolicyTreeModel views (after replace)."""
        for sub in self.m_space.subWindowList():
            widget = sub.widget()
            if isinstance(widget, PolicyView) and isinstance(
                widget.model(), PolicyTreeModel
            ):
                widget.model().reload()

    def _get_open_rule_set_ids(self) -> set[uuid.UUID]:
        """Return the set of rule set IDs currently open in MDI sub-windows."""
        ids = set()
        for sub in self.m_space.subWindowList():
            widget = sub.widget()
            if isinstance(widget, PolicyView) and isinstance(
                widget.model(), PolicyTreeModel
            ):
                ids.add(widget.model().rule_set_id)
        return ids

    @Slot(str, str, str)
    def _navigate_to_rule_match(self, rule_set_id, rule_id, slot):
        """Navigate to a rule element match in a policy view."""
        rs_uuid = uuid.UUID(rule_set_id)
        r_uuid = uuid.UUID(rule_id)

        # Look for an existing sub-window with this rule set.
        for sub in self.m_space.subWindowList():
            widget = sub.widget()
            if (
                isinstance(widget, PolicyView)
                and isinstance(widget.model(), PolicyTreeModel)
                and widget.model().rule_set_id == rs_uuid
            ):
                self.m_space.setActiveSubWindow(sub)
                self._scroll_to_rule(widget, widget.model(), r_uuid, slot)
                return

        # Open a new sub-window for this rule set.
        with self._db_manager.session() as session:
            rs = session.get(RuleSet, rs_uuid)
            if rs is None:
                return
            fw_name = rs.device.name if rs.device else ''
            rs_name = rs.name

        model = PolicyTreeModel(self._db_manager, rs_uuid)
        view = PolicyView()
        view.setModel(model)

        sub = QMdiSubWindow()
        sub.setWidget(view)
        sub.setWindowTitle(f'{fw_name} / {rs_name}')
        sub.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.m_space.addSubWindow(sub)
        sub.showMaximized()

        self._scroll_to_rule(view, model, r_uuid, slot)

    @staticmethod
    def _scroll_to_rule(view, model, rule_id, slot):
        """Scroll *view* to the rule node matching *rule_id*."""

        def _walk(parent_index, row_count):
            for row in range(row_count):
                idx = model.index(row, 0, parent_index)
                rd = model.get_row_data(idx)
                if rd is not None and rd.rule_id == rule_id:
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
        if self._db_manager.undo():
            self._refresh_after_history_change()

    @Slot()
    def _do_redo(self):
        if self._db_manager.redo():
            self._refresh_after_history_change()

    @Slot(int)
    def _on_undo_list_clicked(self, row):
        if row < 0:
            return
        if self._db_manager.jump_to(row):
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
            self.undoView.addItem(snap.description or f'State {snap.index}')
            if snap.is_current:
                self.undoView.setCurrentRow(snap.index)
        self.undoView.blockSignals(False)

    def _refresh_after_history_change(self):
        obj_id = getattr(self, '_editor_obj_id', None)
        obj_type = getattr(self, '_editor_obj_type', None)
        self._close_editor()

        # Reload open rule set models instead of closing all subwindows.
        for sub in self.m_space.subWindowList():
            widget = sub.widget()
            if isinstance(widget, PolicyView) and isinstance(
                widget.model(), PolicyTreeModel
            ):
                widget.model().reload()

        file_key = (
            str(self._display_file) if getattr(self, '_display_file', None) else ''
        )
        with self._db_manager.session() as session:
            self._object_tree.populate(session, file_key=file_key)
        self._find_panel.reset()
        self._where_used_panel.reset()
        if obj_id is not None:
            self._open_object_editor(obj_id, obj_type)

    def _close_editor(self):
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
