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
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QResource, QSettings, Qt, QUrl, Slot
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QMainWindow,
    QMdiSubWindow,
    QMessageBox,
)

from firewallfabrik import __version__
from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import (
    Address,
    Direction,
    Firewall,
    Group,
    Host,
    Interface,
    Interval,
    Policy,
    PolicyAction,
    PolicyRule,
    Service,
    rule_elements,
)
from firewallfabrik.gui.about_dialog import AboutDialog
from firewallfabrik.gui.debug_dialog import DebugDialog
from firewallfabrik.gui.policy_model import PolicyTableModel
from firewallfabrik.gui.policy_view import PolicyView
from firewallfabrik.gui.ui_loader import FWFUiLoader

logger = logging.getLogger(__name__)

FILE_FILTERS = 'FirewallFabrik Files *.fwf (*.fwf);;Firewall Builder Files *.fwb (*.fwb);;All Files (*)'
_MAX_RECENT_FILES = 5


class FWWindow(QMainWindow):
    """Main application window, equivalent to FWWindow in the C++ codebase."""

    def __init__(self):
        super().__init__()

        ui_path = Path(__file__).resolve().parent / 'ui'
        self._register_resources(ui_path)

        ui_path = ui_path / 'FWBMainWindow_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._current_file = None
        self._db_manager = DatabaseManager()

        self.setWindowTitle(f'FirewallFabrik {__version__}')
        self.toolBar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

        self._prepare_recent_menu()

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

    def _update_title(self):
        if self._current_file:
            self.setWindowTitle(
                f'{self._current_file.name} - FirewallFabrik {__version__}',
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
        if self._current_file:
            return
        self.fileSaveAs()

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

        self._current_file = file_path
        self._update_title()

    @Slot()
    def fileExit(self):
        self.close()

    @Slot()
    def help(self):
        QDesktopServices.openUrl(
            QUrl('https://github.com/Linuxfabrik/firewallfabrik/tree/main/docs/user-guide'),
        )

    @Slot()
    def showChangelog(self):
        QDesktopServices.openUrl(
            QUrl('https://github.com/Linuxfabrik/firewallfabrik/blob/main/CHANGELOG.md'),
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

        try:
            self._db_manager = DatabaseManager()
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
        self._update_title()
        self._add_to_recent(str(file_path))
        self._show_policies()

    def _prepare_recent_menu(self):
        """Populate the empty *menuOpen_Recent* with dynamic actions."""
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

        # If two files share the same basename, show the full path for both.
        name_counts = {}
        for f in files:
            name = Path(f).name
            name_counts[name] = name_counts.get(name, 0) + 1

        num = min(len(files), _MAX_RECENT_FILES)
        for i in range(num):
            name = Path(files[i]).name
            text = files[i] if name_counts.get(name, 0) > 1 else name
            self._recent_actions[i].setText(text)
            self._recent_actions[i].setData(files[i])
            self._recent_actions[i].setVisible(True)

        for i in range(num, _MAX_RECENT_FILES):
            self._recent_actions[i].setVisible(False)

        self._recent_separator.setVisible(num > 0)

    def _add_to_recent(self, file_path):
        """Prepend *file_path* to the persisted recent-files list."""
        settings = QSettings()
        files = settings.value('recentFiles', []) or []
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

    def _show_policies(self):
        """Load firewalls from the database and display their policies as MDI sub-windows."""
        self.m_space.closeAllSubWindows()

        with self._db_manager.session() as session:
            name_map = self._build_name_map(session)

            firewalls = session.scalars(
                sqlalchemy.select(Firewall),
            ).all()

            for fw in firewalls:
                for rule_set in fw.rule_sets:
                    if not isinstance(rule_set, Policy):
                        continue
                    rows = self._build_policy_rows(session, rule_set, name_map)
                    model = PolicyTableModel(rows)
                    view = PolicyView()
                    view.setModel(model)

                    sub = QMdiSubWindow()
                    sub.setWidget(view)
                    sub.setWindowTitle(f'{fw.name} / {rule_set.name}')
                    sub.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
                    self.m_space.addSubWindow(sub)
                    sub.show()

    @staticmethod
    def _build_name_map(session):
        """Build a {uuid: name} lookup from all name-bearing tables."""
        name_map = {}
        for cls in (Address, Service, Group, Host, Interface, Interval):
            for obj_id, name in session.execute(
                sqlalchemy.select(cls.id, cls.name),
            ):
                name_map[obj_id] = name
        return name_map

    @staticmethod
    def _build_policy_rows(session, policy, name_map):
        """Build a list of row dicts for a Policy rule set."""
        rules = session.scalars(
            sqlalchemy.select(PolicyRule)
            .where(PolicyRule.rule_set_id == policy.id)
            .order_by(PolicyRule.position),
        ).all()

        # Gather all rule_elements for this policy's rules in one query.
        rule_ids = [r.id for r in rules]
        slot_map = {}  # {rule_id: {slot: [name, ...]}}
        if rule_ids:
            re_rows = session.execute(
                sqlalchemy.select(rule_elements).where(
                    rule_elements.c.rule_id.in_(rule_ids),
                ),
            ).all()
            for rule_id, slot, target_id in re_rows:
                slot_map.setdefault(rule_id, {}).setdefault(slot, []).append(
                    name_map.get(target_id, str(target_id)),
                )

        rows = []
        for rule in rules:
            slots = slot_map.get(rule.id, {})
            try:
                direction = Direction(rule.policy_direction).name
            except (ValueError, TypeError):
                direction = ''
            try:
                action = PolicyAction(rule.policy_action).name
            except (ValueError, TypeError):
                action = ''

            rows.append({
                'position': rule.position,
                'src': ', '.join(slots.get('src', [])),
                'dst': ', '.join(slots.get('dst', [])),
                'srv': ', '.join(slots.get('srv', [])),
                'itf': ', '.join(slots.get('itf', [])),
                'direction': direction,
                'action': action,
                'comment': rule.comment or '',
            })
        return rows
