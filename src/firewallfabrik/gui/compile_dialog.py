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

"""Compile/install dialog — 2-page wizard using compileinstalldialog_q.ui."""

import shutil
import uuid
from datetime import UTC, datetime
from html import escape
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QByteArray, QProcess, QSettings, Qt, QUrl, Slot
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

# UserRole offsets for item data stored on selectTable items.
_R = Qt.ItemDataRole.UserRole
_R_TREE_PATH = _R  # +0
_R_FW_NAME = _R + 1
_R_PLATFORM = _R + 2
_R_OUTPUT_FILE = _R + 3
_R_FW_UUID = _R + 4
_R_CMDLINE = _R + 5
_R_COMPILER = _R + 6
_R_NEEDS_COMPILE = _R + 7
_R_NEEDS_INSTALL = _R + 8
_R_MGMT_ADDRESS = _R + 9


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


def _resolve_mgmt_address(fw):
    """Return the management address for a firewall.

    Checks ``fw.options['altAddress']`` first, then scans interfaces
    for one flagged as management and returns its first address.
    """
    options = fw.options or {}
    alt = options.get('altAddress', '')
    if alt:
        return alt
    for iface in fw.interfaces:
        iface_data = iface.data or {}
        if str(iface_data.get('management', '')).lower() in ('true', '1'):
            for addr in iface.addresses:
                return str(addr.address) if hasattr(addr, 'address') else addr.name
    return ''


class CompileDialog(QDialog):
    """Modal 2-page wizard for compiling firewalls via ``cli tools``."""

    def __init__(
        self,
        db_manager,
        current_file,
        parent=None,
        install_mode=False,
        preselect_names=None,
    ):
        super().__init__(parent)
        self._db_manager = db_manager
        self._current_file = current_file
        self._dest_dir = current_file.parent
        self._install_mode = install_mode
        self._preselect_names = set(preselect_names) if preselect_names else None

        # Compile state
        self._process = None
        self._compile_queue = []
        self._compiled_fw_ids = []
        self._current_fw_name = ''
        self._current_fw_id = None
        self._compiling = False
        self._work_items = {}  # fw_id -> QTreeWidgetItem in fwWorkList

        # Install state
        self._installing = False
        self._install_queue = []
        self._installed_fw_ids = []
        self._installer = None
        self._canceled_all = False
        self._batch_config = None

        # Load UI from .ui file
        ui_path = Path(__file__).resolve().parent / 'ui' / 'compileinstalldialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        if install_mode:
            # Show install column, keep batch install frame visible.
            self.warning_space.hide()
            self.titleLabel.setText('Compile and Install Firewalls')
            self.selectInfoLabel.setText(
                '<p align="center"><b><font size="+2">'
                'Select firewalls to compile and install.'
                '</font></b></p>'
            )
        else:
            # Compile-only mode: hide install column and batch install frame.
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
        for col in (1, 2, 3, 4, 5):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        # Progress bars start at zero
        self.compFirewallProgress.setValue(0)
        self.compProgress.setValue(0)
        self.fwMCLabel.setText('')
        self.infoMCLabel.setText('')

        self._populate_select_table()
        self._restore_geometry()

    # ------------------------------------------------------------------
    # Geometry persistence
    # ------------------------------------------------------------------

    def _restore_geometry(self):
        """Restore saved dialog geometry, falling back to centered default."""
        settings = QSettings()
        geometry = settings.value('CompileDialog/geometry', type=QByteArray)
        if geometry and self.restoreGeometry(geometry):
            return
        # No saved geometry — center on parent.
        self.resize(900, 600)
        parent = self.parentWidget()
        if parent is not None:
            center = parent.geometry().center()
            geo = self.geometry()
            geo.moveCenter(center)
            self.setGeometry(geo)

    def done(self, result):
        QSettings().setValue('CompileDialog/geometry', self.saveGeometry())
        super().done(result)

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
                inactive = data.get('inactive') in (True, 'True')
                supported = platform in _PLATFORM_CLI
                last_modified = int(data.get('lastModified', 0) or 0)
                last_compiled = int(data.get('lastCompiled', 0) or 0)
                last_installed = int(data.get('lastInstalled', 0) or 0)
                needs_compile = last_modified > last_compiled or last_compiled == 0
                needs_install = last_compiled > last_installed or last_installed == 0

                tree_path = _fw_tree_path(fw)
                mgmt_address = _resolve_mgmt_address(fw) if self._install_mode else ''

                item = QTreeWidgetItem()
                item.setData(0, _R_TREE_PATH, tree_path)
                item.setData(0, _R_FW_NAME, fw.name)
                item.setData(0, _R_PLATFORM, platform)
                item.setData(
                    0,
                    _R_OUTPUT_FILE,
                    options.get('output_file', '') or options.get('outputFileName', ''),
                )
                item.setData(0, _R_FW_UUID, str(fw.id))
                item.setData(
                    0,
                    _R_CMDLINE,
                    options.get('cmdline', '') or options.get('compilerArgs', ''),
                )
                item.setData(0, _R_COMPILER, options.get('compiler', ''))
                item.setData(0, _R_NEEDS_COMPILE, needs_compile)
                item.setData(0, _R_NEEDS_INSTALL, needs_install)
                item.setData(0, _R_MGMT_ADDRESS, mgmt_address)

                item.setText(0, fw.name)

                # Col 1 (Compile): checkbox
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                if self._preselect_names is not None:
                    check_compile = (
                        supported and not inactive and fw.name in self._preselect_names
                    )
                else:
                    check_compile = supported and not inactive and needs_compile
                item.setCheckState(
                    1,
                    Qt.CheckState.Checked if check_compile else Qt.CheckState.Unchecked,
                )

                # Col 2 (Install): checkbox — only in install mode.
                if self._install_mode:
                    if self._preselect_names is not None:
                        check_install = (
                            supported
                            and not inactive
                            and fw.name in self._preselect_names
                        )
                    else:
                        check_install = supported and not inactive and needs_install
                    item.setCheckState(
                        2,
                        Qt.CheckState.Checked
                        if check_install
                        else Qt.CheckState.Unchecked,
                    )

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
                if self._install_mode:
                    item.setCheckState(2, Qt.CheckState.Checked)

    @Slot()
    def deselectAllFirewalls(self):
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            item.setCheckState(1, Qt.CheckState.Unchecked)
            if self._install_mode:
                item.setCheckState(2, Qt.CheckState.Unchecked)

    @Slot()
    def selectChangedFirewalls(self):
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            if item.flags() & Qt.ItemFlag.ItemIsEnabled and item.data(
                0, _R_NEEDS_COMPILE
            ):
                item.setCheckState(1, Qt.CheckState.Checked)
            else:
                item.setCheckState(1, Qt.CheckState.Unchecked)
            if self._install_mode:
                if item.flags() & Qt.ItemFlag.ItemIsEnabled and item.data(
                    0, _R_NEEDS_INSTALL
                ):
                    item.setCheckState(2, Qt.CheckState.Checked)
                else:
                    item.setCheckState(2, Qt.CheckState.Unchecked)

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
        self._install_queue = []
        for i in range(self.selectTable.topLevelItemCount()):
            item = self.selectTable.topLevelItem(i)
            fw_id = item.data(0, _R_TREE_PATH)
            fw_name = item.data(0, _R_FW_NAME)
            platform = item.data(0, _R_PLATFORM)
            output_file = item.data(0, _R_OUTPUT_FILE)
            cmdline = item.data(0, _R_CMDLINE) or ''
            compiler_path = item.data(0, _R_COMPILER) or ''
            mgmt_addr = item.data(0, _R_MGMT_ADDRESS) or ''

            if item.checkState(1) == Qt.CheckState.Checked:
                self._compile_queue.append(
                    (fw_id, fw_name, platform, output_file, cmdline, compiler_path)
                )

            if self._install_mode and item.checkState(2) == Qt.CheckState.Checked:
                fw_uuid_str = item.data(0, _R_FW_UUID)
                self._install_queue.append(
                    (fw_id, fw_name, platform, fw_uuid_str, mgmt_addr)
                )

        if not self._compile_queue and not self._install_queue:
            QMessageBox.information(
                self,
                'Compile Firewalls',
                'No firewalls selected.',
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
        # Collect all unique fw_ids that appear in either queue.
        seen = set()
        for fw_id, fw_name, *_rest in self._compile_queue:
            if fw_id not in seen:
                seen.add(fw_id)
                item = QTreeWidgetItem()
                item.setText(0, fw_name)
                item.setText(1, 'Waiting')
                self.fwWorkList.addTopLevelItem(item)
                self._work_items[fw_id] = item
        for fw_id, fw_name, *_rest in self._install_queue:
            if fw_id not in seen:
                seen.add(fw_id)
                item = QTreeWidgetItem()
                item.setText(0, fw_name)
                item.setText(1, 'Waiting')
                self.fwWorkList.addTopLevelItem(item)
                self._work_items[fw_id] = item

        # Set up the overall progress bar
        total = len(self._compile_queue) + len(self._install_queue)
        self._compiled_fw_ids = []
        self._installed_fw_ids = []
        self.compFirewallProgress.setMaximum(total)
        self.compFirewallProgress.setValue(0)
        self.compProgress.setMaximum(0)  # indeterminate per-fw progress
        self.compProgress.setValue(0)
        self.procLogDisplay.clear()

        if self._compile_queue:
            self._compiling = True
            self._compile_next()
        elif self._install_queue:
            self._start_install_phase()

    @Slot()
    def _back_clicked(self):
        if not self._compiling and not self._installing:
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
        elif self._installing:
            result = QMessageBox.question(
                self,
                'Installation in Progress',
                'An installation is still running. Do you want to stop it?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if result == QMessageBox.StandardButton.No:
                return
            self._stop_installation()
        self.reject()

    @Slot()
    def _stop_clicked(self):
        """Stop button on the progress page."""
        if self._compiling:
            self._stop_compilation()
        elif self._installing:
            self._stop_installation()

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
                work_item.setText(1, 'Compiled')
        else:
            self.procLogDisplay.append(
                f'<p style="color: red;"><b>{escape(self._current_fw_name)}: '
                f'compilation failed (exit code {exit_code}).</b></p>'
            )
            if work_item is not None:
                work_item.setText(1, 'Compile Error')
            # Block install for this firewall on compile failure.
            if self._install_mode:
                self._install_queue = [
                    entry
                    for entry in self._install_queue
                    if entry[0] != self._current_fw_id
                ]

        self._process = None
        self.compFirewallProgress.setValue(self.compFirewallProgress.value() + 1)
        self._compile_next()

    def _finish_compilation(self):
        self._compiling = False

        total = self.compFirewallProgress.maximum()
        ok = len(self._compiled_fw_ids)
        # Account for the compile portion only.
        compile_total = total - len(self._install_queue)
        failed = compile_total - ok
        self.procLogDisplay.append(
            f'<p><b>Compilation done: {ok} succeeded, {failed} failed.</b></p>'
        )

        if self._compiled_fw_ids:
            now = datetime.now(tz=UTC)
            epoch = int(now.timestamp())
            display = now.strftime('%Y-%m-%d %H:%M:%S')
            fw_uuids = []
            for i in range(self.selectTable.topLevelItemCount()):
                item = self.selectTable.topLevelItem(i)
                if item.data(0, _R_TREE_PATH) in self._compiled_fw_ids:
                    fw_uuids.append(uuid.UUID(item.data(0, _R_FW_UUID)))
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

            for i in range(self.selectTable.topLevelItemCount()):
                item = self.selectTable.topLevelItem(i)
                if item.data(0, _R_TREE_PATH) in self._compiled_fw_ids:
                    item.setText(4, display)

        # If in install mode and there are firewalls to install, proceed.
        if self._install_mode and self._install_queue:
            self._start_install_phase()
            return

        # No install phase — done.
        self.infoMCLabel.setText('Done')
        self.compProgress.setMaximum(1)
        self.compProgress.setValue(1)
        self.finishButton.setEnabled(True)
        self.backButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.cancelButton.setEnabled(False)

    def _start_install_phase(self):
        """Transition from compile to install phase."""
        self._installing = True
        self._canceled_all = False
        self._batch_config = None
        self.procLogDisplay.append('<p><b>Starting installation phase...</b></p>')
        self._install_next()

    def _install_next(self):
        if not self._install_queue or self._canceled_all:
            self._finish_installation()
            return

        fw_id, fw_name, platform, fw_uuid_str, mgmt_addr = self._install_queue.pop(0)
        self._current_fw_name = fw_name
        self._current_fw_id = fw_id

        work_item = self._work_items.get(fw_id)
        if work_item is not None:
            work_item.setText(1, 'Installing...')

        self.fwMCLabel.setText(fw_name)
        self.infoMCLabel.setText('Installing...')

        self.procLogDisplay.append(
            f'<a name="install-{escape(fw_id)}"></a>'
            f'<p><b>Installing {escape(fw_name)} ...</b></p>'
        )

        config = self._get_install_options(fw_uuid_str, fw_name, platform, mgmt_addr)
        if config is None:
            # User skipped or cancelled all.
            if self._canceled_all:
                self._finish_installation()
            else:
                work_item = self._work_items.get(fw_id)
                if work_item is not None:
                    work_item.setText(1, 'Skipped')
                self.compFirewallProgress.setValue(
                    self.compFirewallProgress.value() + 1
                )
                self._install_next()
            return

        from firewallfabrik.gui.firewall_installer import FirewallInstaller

        self._installer = FirewallInstaller(config, parent=self)
        self._installer.log_message.connect(self._on_install_log)
        self._installer.job_finished.connect(self._on_install_success)
        self._installer.job_failed.connect(self._on_install_failure)
        self._installer.run_jobs()

    def _get_install_options(self, fw_uuid_str, fw_name, platform, mgmt_addr):
        """Show install options dialog and return an InstallConfig, or None."""
        from firewallfabrik.gui.firewall_installer import InstallConfig
        from firewallfabrik.gui.install_options_dialog import InstallOptionsDialog

        # Load options from the firewall object.
        with self._db_manager.session() as session:
            fw = session.get(Firewall, uuid.UUID(fw_uuid_str))
            options = (fw.options or {}) if fw else {}

        config = InstallConfig(
            user=options.get('admUser', '') or 'root',
            mgmt_address=mgmt_addr,
            firewall_dir=options.get('firewall_dir', '/etc/fw'),
            ssh_args=options.get('sshArgs', ''),
            scp_args=options.get('scpArgs', ''),
            activation_cmd=options.get('activationCmd', ''),
            install_script=options.get('installScript', ''),
            install_script_args=options.get('installScriptArgs', ''),
            firewall_name=fw_name,
            fwb_file=str(self._current_file),
            working_dir=str(self._dest_dir),
            alt_address=options.get('altAddress', ''),
        )

        # Determine the compiled script path.
        output_file = options.get('output_file', '') or options.get(
            'outputFileName', ''
        )
        if output_file:
            config.script_path = str(self._dest_dir / output_file)
        else:
            base_name = fw_name.replace(' ', '_').replace('/', '_')
            config.script_path = str(self._dest_dir / f'{base_name}.fw')

        # Determine remote script name from options.
        script_on_fw = options.get('script_name_on_firewall', '')
        if script_on_fw:
            config.remote_script = script_on_fw
        else:
            config.remote_script = (
                f'{config.firewall_dir}/{Path(config.script_path).name}'
            )

        # In batch mode, reuse the saved config (skip the dialog).
        if self._batch_config is not None:
            config.user = self._batch_config.user
            config.verbose = self._batch_config.verbose
            config.quiet = self._batch_config.quiet
            config.copy_fwb = self._batch_config.copy_fwb
            config.batch_install = True
            return config

        installing_many = len(self._install_queue) > 0
        dlg = InstallOptionsDialog(fw_name, config, installing_many, parent=self)
        result = dlg.exec()

        if result == QDialog.DialogCode.Accepted:
            config = dlg.get_config()
            if config.batch_install:
                self._batch_config = config
            return config
        elif result == -1:
            # Cancel All
            self._canceled_all = True
            return None
        else:
            # Skip this firewall
            return None

    @Slot(str)
    def _on_install_log(self, msg):
        self.procLogDisplay.append(msg)

    @Slot()
    def _on_install_success(self):
        work_item = self._work_items.get(self._current_fw_id)
        if work_item is not None:
            work_item.setText(1, 'Installed')
        self.procLogDisplay.append(
            f'<p style="color: green;"><b>{escape(self._current_fw_name)}: '
            f'installed successfully.</b></p>'
        )
        self._installed_fw_ids.append(self._current_fw_id)
        self._installer = None
        self.compFirewallProgress.setValue(self.compFirewallProgress.value() + 1)
        self._install_next()

    @Slot(str)
    def _on_install_failure(self, error):
        work_item = self._work_items.get(self._current_fw_id)
        if work_item is not None:
            work_item.setText(1, 'Install Error')
        self.procLogDisplay.append(
            f'<p style="color: red;"><b>{escape(self._current_fw_name)}: '
            f'installation failed: {escape(error)}</b></p>'
        )
        self._installer = None
        self.compFirewallProgress.setValue(self.compFirewallProgress.value() + 1)
        self._install_next()

    def _finish_installation(self):
        self._installing = False

        ok = len(self._installed_fw_ids)
        self.procLogDisplay.append(f'<p><b>Installation done: {ok} installed.</b></p>')

        if self._installed_fw_ids:
            now = datetime.now(tz=UTC)
            epoch = int(now.timestamp())
            display = now.strftime('%Y-%m-%d %H:%M:%S')
            fw_uuids = []
            for i in range(self.selectTable.topLevelItemCount()):
                item = self.selectTable.topLevelItem(i)
                if item.data(0, _R_TREE_PATH) in self._installed_fw_ids:
                    fw_uuids.append(uuid.UUID(item.data(0, _R_FW_UUID)))
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
                            '$.lastInstalled',
                            epoch,
                        )
                    )
                )
            self._db_manager.save_state('Install firewalls')

            for i in range(self.selectTable.topLevelItemCount()):
                item = self.selectTable.topLevelItem(i)
                if item.data(0, _R_TREE_PATH) in self._installed_fw_ids:
                    item.setText(5, display)

        self.infoMCLabel.setText('Done')
        self.compProgress.setMaximum(1)
        self.compProgress.setValue(1)
        self.finishButton.setEnabled(True)
        self.backButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.cancelButton.setEnabled(False)

    def _stop_installation(self):
        """Terminate the installer and clear the queue."""
        self._install_queue.clear()
        if self._installer is not None:
            self._installer.terminate()
            self._installer = None
        self._installing = False
        self.procLogDisplay.append(
            '<p style="color: orange;"><b>Installation stopped by user.</b></p>'
        )
        self._finish_installation()

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
                'Process in Progress',
                'A process is still running. Do you want to stop it?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if result == QMessageBox.StandardButton.No:
                event.ignore()
                return
            self._stop_compilation()
        if self._installing and self._installer is not None:
            self._stop_installation()
        super().closeEvent(event)
