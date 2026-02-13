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

"""Compile dialog — 2-page wizard using compileinstalldialog_q.ui."""

import shutil
import uuid
from datetime import UTC, datetime
from html import escape
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QProcess, Qt, QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHeaderView,
    QMessageBox,
    QTreeWidgetItem,
)

from firewallfabrik.core._util import escape_obj_name
from firewallfabrik.core.objects import Firewall
from firewallfabrik.gui.ui_loader import FWFUiLoader

# Platform -> CLI tool mapping
_PLATFORM_CLI = {
    'iptables': 'fwf-ipt',
    'nftables': 'fwf-nft',
}


def _format_epoch(value):
    """Format an epoch timestamp for display, or return ``'-'``."""
    ts = int(value or 0)
    if not ts:
        return '-'
    return datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%d %H:%M:%S')


def _fw_tree_path(fw):
    """Build a stable tree-path identifier for a firewall."""
    parts = [f'Library:{escape_obj_name(fw.library.name)}']
    group_parts = []
    grp = fw.group
    while grp is not None:
        group_parts.append(f'{grp.type}:{escape_obj_name(grp.name)}')
        grp = grp.parent_group
    group_parts.reverse()
    parts.extend(group_parts)
    parts.append(f'{fw.type}:{escape_obj_name(fw.name)}')
    return '/'.join(parts)


class CompileDialog(QDialog):
    """Modal 2-page wizard for compiling firewalls via ``cli tools``."""

    def __init__(self, db_manager, current_file, parent=None):
        super().__init__(parent)
        self._db_manager = db_manager
        self._current_file = current_file
        self._dest_dir = current_file.parent
        self._process = None
        self._compile_queue = []
        self._compiled_fw_ids = []
        self._current_fw_name = ''
        self._current_fw_id = None
        self._compiling = False
        self._work_items = {}  # fw_id -> QTreeWidgetItem in fwWorkList

        # Load UI from .ui file
        ui_path = Path(__file__).resolve().parent / 'ui' / 'compileinstalldialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        # Compile-only mode: hide install column and batch install frame
        self.selectTable.hideColumn(2)  # Install column
        self.batchInstFlagFrame.hide()
        self.warning_space.hide()
        self.titleLabel.setText('Compile Firewalls')
        self.selectInfoLabel.setText(
            '<p align="center"><b><font size="+2">'
            'Select firewalls to compile.'
            '</font></b></p>'
        )

        # Wizard navigation
        self.stackedWidget.setCurrentIndex(0)
        self.backButton.setEnabled(False)
        self.finishButton.setEnabled(False)
        self.nextButton.setEnabled(True)

        self.nextButton.clicked.connect(self._next_clicked)
        self.backButton.clicked.connect(self._back_clicked)
        self.finishButton.clicked.connect(self.accept)
        self.cancelButton.clicked.connect(self._cancel_clicked)
        self.stopButton.clicked.connect(self._stop_clicked)

        # Resize columns for selectTable
        header = self.selectTable.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 3, 4, 5):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        # Progress bars start at zero
        self.compFirewallProgress.setValue(0)
        self.compProgress.setValue(0)
        self.fwMCLabel.setText('')
        self.infoMCLabel.setText('')

        self._populate_select_table()

    # ------------------------------------------------------------------
    # Page 0 — Firewall selection
    # ------------------------------------------------------------------

    def _populate_select_table(self):
        with self._db_manager.session() as session:
            firewalls = (
                session.execute(
                    sqlalchemy.select(Firewall).order_by(Firewall.name),
                )
                .scalars()
                .all()
            )
            for fw in firewalls:
                data = fw.data or {}
                options = fw.options or {}
                platform = data.get('platform', '')
                inactive = data.get('inactive', '') == 'True'
                supported = platform in _PLATFORM_CLI
                last_modified = int(data.get('lastModified', 0) or 0)
                last_compiled = int(data.get('lastCompiled', 0) or 0)
                needs_compile = last_modified > last_compiled or last_compiled == 0

                tree_path = _fw_tree_path(fw)

                item = QTreeWidgetItem()
                item.setData(0, Qt.ItemDataRole.UserRole, tree_path)
                item.setData(0, Qt.ItemDataRole.UserRole + 1, fw.name)
                item.setData(0, Qt.ItemDataRole.UserRole + 2, platform)
                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole + 3,
                    options.get('output_file', '') or options.get('outputFileName', ''),
                )
                item.setData(0, Qt.ItemDataRole.UserRole + 4, str(fw.id))
                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole + 5,
                    options.get('cmdline', '') or options.get('compilerArgs', ''),
                )
                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole + 6,
                    options.get('compiler', ''),
                )
                item.setData(0, Qt.ItemDataRole.UserRole + 7, needs_compile)

                item.setText(0, fw.name)

                # Col 1 (Compile): checkbox
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                if supported and not inactive and needs_compile:
                    item.setCheckState(1, Qt.CheckState.Checked)
                else:
                    item.setCheckState(1, Qt.CheckState.Unchecked)

                # Col 3-5: timestamps (stored as epoch ints)
                item.setText(3, _format_epoch(data.get('lastModified', 0)))
                item.setText(4, _format_epoch(data.get('lastCompiled', 0)))
                item.setText(5, _format_epoch(data.get('lastInstalled', 0)))

                # Unsupported platform: disable the item
                if not supported:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                    item.setToolTip(
                        0, f'Platform "{platform or "(none)"}" is not supported yet'
                    )

                if needs_compile and supported:
                    font = item.font(0)
                    font.setBold(True)
                    for col in range(self.selectTable.columnCount()):
                        item.setFont(col, font)

                self.selectTable.addTopLevelItem(item)

    # Slots declared in .ui connections
    @Slot()
    def selectAllFirewalls(self):
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            if item.flags() & Qt.ItemFlag.ItemIsEnabled:
                item.setCheckState(1, Qt.CheckState.Checked)

    @Slot()
    def deselectAllFirewalls(self):
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            item.setCheckState(1, Qt.CheckState.Unchecked)

    @Slot()
    def selectChangedFirewalls(self):
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            if item.flags() & Qt.ItemFlag.ItemIsEnabled and item.data(
                0, Qt.ItemDataRole.UserRole + 7
            ):
                item.setCheckState(1, Qt.CheckState.Checked)
            else:
                item.setCheckState(1, Qt.CheckState.Unchecked)

    @Slot(QTreeWidgetItem, int)
    def tableItemChanged(self, item, col):
        pass  # No validation needed

    # ------------------------------------------------------------------
    # Wizard navigation
    # ------------------------------------------------------------------

    @Slot()
    def _next_clicked(self):
        """Collect checked firewalls and start compilation."""
        self._compile_queue = []
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            if item.checkState(1) == Qt.CheckState.Checked:
                fw_id = item.data(0, Qt.ItemDataRole.UserRole)
                fw_name = item.data(0, Qt.ItemDataRole.UserRole + 1)
                platform = item.data(0, Qt.ItemDataRole.UserRole + 2)
                output_file = item.data(0, Qt.ItemDataRole.UserRole + 3)
                cmdline = item.data(0, Qt.ItemDataRole.UserRole + 5) or ''
                compiler_path = item.data(0, Qt.ItemDataRole.UserRole + 6) or ''
                self._compile_queue.append(
                    (fw_id, fw_name, platform, output_file, cmdline, compiler_path)
                )

        if not self._compile_queue:
            QMessageBox.information(
                self,
                'Compile Firewalls',
                'No firewalls selected for compilation.',
            )
            return

        # Switch to the progress page
        self.stackedWidget.setCurrentIndex(1)
        self.nextButton.setEnabled(False)
        self.backButton.setEnabled(False)
        self.finishButton.setEnabled(False)

        # Populate fwWorkList sidebar
        self.fwWorkList.clear()
        self._work_items = {}
        for fw_id, fw_name, *_rest in self._compile_queue:
            item = QTreeWidgetItem()
            item.setText(0, fw_name)
            item.setText(1, 'Waiting')
            self.fwWorkList.addTopLevelItem(item)
            self._work_items[fw_id] = item

        # Set up the overall progress bar
        self._compiled_fw_ids = []
        self.compFirewallProgress.setMaximum(len(self._compile_queue))
        self.compFirewallProgress.setValue(0)
        self.compProgress.setMaximum(0)  # indeterminate per-fw progress
        self.compProgress.setValue(0)
        self.procLogDisplay.clear()

        self._compiling = True
        self._compile_next()

    @Slot()
    def _back_clicked(self):
        if not self._compiling:
            self.stackedWidget.setCurrentIndex(0)
            self.nextButton.setEnabled(True)
            self.backButton.setEnabled(False)
            self.finishButton.setEnabled(False)
            self.cancelButton.setEnabled(True)

    @Slot()
    def _cancel_clicked(self):
        if self._compiling:
            result = QMessageBox.question(
                self,
                'Compilation in Progress',
                'A compilation is still running. Do you want to stop it?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if result == QMessageBox.StandardButton.No:
                return
            self._stop_compilation()
        self.reject()

    @Slot()
    def _stop_clicked(self):
        """Stop button on the progress page."""
        if self._compiling:
            self._stop_compilation()

    def _stop_compilation(self):
        """Kill the running process and clear the queue."""
        self._compile_queue.clear()
        if (
            self._process is not None
            and self._process.state() != QProcess.ProcessState.NotRunning
        ):
            self._process.kill()
            self._process.waitForFinished(3000)
        self._compiling = False
        self.procLogDisplay.append(
            '<p style="color: orange;"><b>Compilation stopped by user.</b></p>'
        )
        self.backButton.setEnabled(True)
        self.finishButton.setEnabled(True)

    def _compile_next(self):
        if not self._compile_queue:
            self._finish_compilation()
            return

        fw_id, fw_name, platform, output_file, cmdline, compiler_path = (
            self._compile_queue.pop(0)
        )
        self._current_fw_name = fw_name
        self._current_fw_id = fw_id

        # Update sidebar
        work_item = self._work_items.get(fw_id)
        if work_item is not None:
            work_item.setText(1, 'Compiling...')

        self.fwMCLabel.setText(fw_name)
        self.infoMCLabel.setText('Compiling...')

        # Add anchor for this firewall in the log
        self.procLogDisplay.append(
            f'<a name="{escape(fw_id)}"></a>'
            f'<p><b>Compiling {escape(fw_name)} ...</b></p>'
        )

        # Resolve compiler binary: custom path from settings, else PATH lookup.
        cli_tool = _PLATFORM_CLI[platform]
        program = compiler_path or shutil.which(cli_tool) or cli_tool

        # Build CLI args matching legacy C++ instDialog_compile behaviour:
        # custom cmdline args first, then standard flags.
        args = []
        if cmdline:
            args.extend(cmdline.split())

        args.extend(
            [
                fw_id,
                '-p',
                '-f',
                str(self._current_file),
                '-d',
                str(self._dest_dir),
                '-v',
            ]
        )
        if output_file:
            args.extend(['-o', output_file])

        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_process_output)
        self._process.finished.connect(self._on_process_finished)
        self._process.start(program, args)

    @Slot()
    def _on_process_output(self):
        if self._process is None:
            return
        data = self._process.readAllStandardOutput().data()
        text = data.decode('utf-8', errors='replace')
        for line in text.splitlines():
            if line.lower().startswith('error'):
                self.procLogDisplay.append(
                    f'<span style="color: red;">{escape(line)}</span>'
                )
            else:
                self.procLogDisplay.append(line)

    @Slot(int, QProcess.ExitStatus)
    def _on_process_finished(self, exit_code, exit_status):
        work_item = self._work_items.get(self._current_fw_id)

        if exit_code == 0 and exit_status == QProcess.ExitStatus.NormalExit:
            self.procLogDisplay.append(
                f'<p style="color: green;"><b>{escape(self._current_fw_name)}: '
                f'compiled successfully.</b></p>'
            )
            self._compiled_fw_ids.append(self._current_fw_id)
            if work_item is not None:
                work_item.setText(1, 'Success')
        else:
            self.procLogDisplay.append(
                f'<p style="color: red;"><b>{escape(self._current_fw_name)}: '
                f'compilation failed (exit code {exit_code}).</b></p>'
            )
            if work_item is not None:
                work_item.setText(1, 'Error')

        self._process = None
        self.compFirewallProgress.setValue(self.compFirewallProgress.value() + 1)
        self._compile_next()

    def _finish_compilation(self):
        self._compiling = False
        self.finishButton.setEnabled(True)
        self.backButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.cancelButton.setEnabled(False)

        self.infoMCLabel.setText('Done')
        self.compProgress.setMaximum(1)
        self.compProgress.setValue(1)

        total = self.compFirewallProgress.maximum()
        ok = len(self._compiled_fw_ids)
        failed = total - ok
        self.procLogDisplay.append(
            f'<p><b>Done: {ok} succeeded, {failed} failed.</b></p>'
        )

        if self._compiled_fw_ids:
            now = datetime.now(tz=UTC)
            epoch = int(now.timestamp())
            display = now.strftime('%Y-%m-%d %H:%M:%S')
            # Recover UUIDs from the select table item data
            fw_uuids = []
            for i in range(self.selectTable.topLevelItemCount()):
                item = self.selectTable.topLevelItem(i)
                if item.data(0, Qt.ItemDataRole.UserRole) in self._compiled_fw_ids:
                    fw_uuids.append(
                        uuid.UUID(item.data(0, Qt.ItemDataRole.UserRole + 4))
                    )
            with self._db_manager.session() as session:
                session.execute(
                    sqlalchemy.update(Firewall)
                    .where(Firewall.id.in_(fw_uuids))
                    .values(
                        data=sqlalchemy.func.json_set(
                            sqlalchemy.func.coalesce(
                                Firewall.data,
                                sqlalchemy.literal_column("'{}'"),
                            ),
                            '$.lastCompiled',
                            epoch,
                        )
                    )
                )
            self._db_manager.save_state('Compile firewalls')

            # Update the select table display
            for i in range(self.selectTable.topLevelItemCount()):
                item = self.selectTable.topLevelItem(i)
                if item.data(0, Qt.ItemDataRole.UserRole) in self._compiled_fw_ids:
                    item.setText(4, display)

    @Slot()
    def saveLog(self):
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            'Save Compile Log',
            str(self._dest_dir / 'compile.log'),
            'Log Files (*.log);;Text Files (*.txt);;All Files (*)',
        )
        if file_name:
            Path(file_name).write_text(
                self.procLogDisplay.toPlainText(), encoding='utf-8'
            )

    @Slot(QTreeWidgetItem)
    def findFirewallInCompileLog(self, item):
        """Scroll procLogDisplay to the anchor for the selected firewall."""
        fw_name = item.text(0)
        # Find the matching fw_id from _work_items
        for fw_id, work_item in self._work_items.items():
            if work_item is item:
                self.procLogDisplay.scrollToAnchor(fw_id)
                return
        # Fallback: search by name
        self.procLogDisplay.find(fw_name)

    @Slot(QUrl)
    def logItemClicked(self, url):
        pass  # Reserved for future rule-error navigation

    @Slot()
    def inspectFiles(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._dest_dir)))

    def closeEvent(self, event):
        if (
            self._process is not None
            and self._process.state() != QProcess.ProcessState.NotRunning
        ):
            result = QMessageBox.question(
                self,
                'Compilation in Progress',
                'A compilation is still running. Do you want to stop it?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if result == QMessageBox.StandardButton.No:
                event.ignore()
                return
            self._stop_compilation()
        super().closeEvent(event)
