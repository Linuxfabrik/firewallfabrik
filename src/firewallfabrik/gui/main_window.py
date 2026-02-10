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

import subprocess
from pathlib import Path

from PySide6.QtCore import QResource, Qt, QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QMainWindow,
    QMessageBox,
)

from firewallfabrik import __version__
from firewallfabrik.gui.about_dialog import AboutDialog
from firewallfabrik.gui.debug_dialog import DebugDialog
from firewallfabrik.gui.ui_loader import FWFUiLoader

FILE_FILTERS = 'YAML Files (*.yml *.yaml);;FWB Files (*.fwb);;All Files (*)'


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

        self.setWindowTitle(f'FirewallFabrik {__version__}')
        self.toolBar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

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
        # prompt for a location, enforce .fwb suffix, then create the file.
        fd = QFileDialog(self)
        fd.setFileMode(QFileDialog.FileMode.AnyFile)
        fd.setDefaultSuffix('yml')
        fd.setNameFilter(FILE_FILTERS)
        fd.setWindowTitle(self.tr('Create New File'))
        fd.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        if not fd.exec():
            return

        file_path = Path(fd.selectedFiles()[0]).resolve()
        if file_path.suffix == '':
            file_path = file_path.with_suffix('.yml')

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

        file_path = Path(file_name).resolve()
        if not file_path.is_file():
            QMessageBox.warning(
                self,
                'FirewallFabrik',
                self.tr(f"File '{file_path}' does not exist or is not readable"),
            )
            return

        self._current_file = file_path
        self._update_title()

    @Slot()
    def fileSave(self):
        if self._current_file:
            return
        self.fileSaveAs()

    @Slot()
    def fileSaveAs(self):
        fd = QFileDialog(self)
        fd.setFileMode(QFileDialog.FileMode.AnyFile)
        fd.setDefaultSuffix('yml')
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
            file_path = file_path.with_suffix('.yml')

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
