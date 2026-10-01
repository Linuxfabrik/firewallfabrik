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

"""File > Import Firewall: build a firewall from a running ruleset.

The wizard of Firewall Builder's "Import Firewall Configuration"
(``importFirewallConfigurationWizard/``), with its four steps: where the
ruleset comes from, what of it to import, the firewall's name and whether
existing objects are used, and the log of the import.  It reads
iptables-save and ``nft -j list ruleset`` - from files, or from the
running firewall over SSH - and the work is done by
:mod:`firewallfabrik.importer`.
"""

from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QSettings, Qt, Slot
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QListWidgetItem,
    QMessageBox,
    QWizard,
    QWizardPage,
)

from firewallfabrik.core.objects import Host
from firewallfabrik.gui import ruleset_lookup, version_lookup
from firewallfabrik.gui.object_tree_data import SYSTEM_GROUP_PATHS
from firewallfabrik.gui.platform_settings import get_enabled_platforms
from firewallfabrik.gui.ui_loader import FWFUiLoader
from firewallfabrik.importer import (
    apply_plan,
    parse_ip_addr_json,
    parse_iptables_save,
    parse_nft_json,
    plan_import,
)

_UI_DIR = Path(__file__).resolve().parent / 'ui'


class _Input:
    """One parsed input and the tables of it the user picked."""

    def __init__(self, label, ruleset):
        self.label = label
        self.ruleset = ruleset


def _read_file(path):
    """Parse one file, whichever of the formats it is in."""
    text = Path(path).read_text(encoding='utf-8', errors='replace')
    if text.lstrip().startswith('{'):
        return _Input(f'nft -j list ruleset ({Path(path).name})', parse_nft_json(text))
    ruleset = parse_iptables_save(text)
    family = ruleset.tables[0].family if ruleset.tables else 4
    tool = 'ip6tables-save' if family == 6 else 'iptables-save'
    return _Input(f'{tool} ({Path(path).name})', ruleset)


def _is_iptables_nft_table(table):
    """A table of iptables-nft, whose matches nft can only list as "xt"."""
    return any(
        any('iptables-save' in reason for reason in rule.unsupported)
        for chain in table.chains.values()
        for rule in chain.rules
    )


class _SourcePage(QWizardPage):
    def __init__(self, wizard):
        super().__init__(wizard)
        FWFUiLoader(self).load(str(_UI_DIR / 'importsourcepage_q.ui'))
        self._wizard = wizard
        self.fromFile.toggled.connect(self._update_enabled)
        self.fileName.textChanged.connect(self.completeChanged)
        self.address.textChanged.connect(self.completeChanged)
        self._update_enabled()

    @Slot()
    def _update_enabled(self):
        from_file = self.fromFile.isChecked()
        for widget in (self.fileNameLabel, self.fileName, self.browse):
            widget.setEnabled(from_file)
        for widget in (
            self.addressLabel,
            self.address,
            self.userLabel,
            self.user,
            self.passwordLabel,
            self.password,
        ):
            widget.setEnabled(not from_file)
        self.completeChanged.emit()

    @Slot()
    def selectFiles(self):
        files, _filter = QFileDialog.getOpenFileNames(
            self,
            self.tr('Choose the files to import'),
            '',
            self.tr('All Files (*)'),
        )
        if files:
            self.fileName.setText(';'.join(files))

    def isComplete(self):
        if self.fromFile.isChecked():
            return bool(self.fileName.text().strip())
        return bool(self.address.text().strip())

    def validatePage(self):
        wizard = self._wizard
        wizard.inputs = []
        wizard.interface_addresses = None
        wizard.suggested_name = ''
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            if self.fromFile.isChecked():
                return self._read_files()
            return self._read_firewall()
        finally:
            QApplication.restoreOverrideCursor()

    def _read_files(self):
        wizard = self._wizard
        names = [n.strip() for n in self.fileName.text().split(';') if n.strip()]
        for name in names:
            try:
                wizard.inputs.append(_read_file(name))
            except OSError as exc:
                QMessageBox.warning(self, self.tr('Import Firewall'), str(exc))
                return False
        wizard.suggested_name = Path(names[0]).stem if names else ''
        return True

    def _read_firewall(self):
        wizard = self._wizard
        address = self.address.text().strip()
        try:
            # The SSH program and timeout of Preferences > Installer, the way
            # "Lookup Version ..." logs in (device_dialogs.py).
            settings = QSettings()
            remote = ruleset_lookup.run(
                address,
                self.user.text().strip() or 'root',
                password=self.password.text(),
                ssh_path=settings.value('SSH/SSHPath', '', type=str),
                timeout=settings.value('SSH/SSHTimeout', 10, type=int) or 10,
            )
        except version_lookup.LookupFailed as exc:
            QMessageBox.warning(
                self,
                self.tr('Import Firewall'),
                self.tr(f'The ruleset of {address} could not be read: {exc}'),
            )
            return False
        if remote.nft_json:
            wizard.inputs.append(
                _Input('nft -j list ruleset', parse_nft_json(remote.nft_json))
            )
        for label, text, family in (
            ('iptables-save', remote.iptables_save, 4),
            ('ip6tables-save', remote.ip6tables_save, 6),
        ):
            if '*' in text:
                wizard.inputs.append(_Input(label, parse_iptables_save(text, family)))
        if remote.ip_addr_json:
            try:
                wizard.interface_addresses = parse_ip_addr_json(remote.ip_addr_json)
            except ValueError:
                wizard.interface_addresses = None
        wizard.lookup = remote.lookup
        wizard.suggested_name = remote.hostname.split('.')[0]
        if not wizard.inputs:
            QMessageBox.warning(
                self,
                self.tr('Import Firewall'),
                self.tr(f'{address} has neither nftables nor iptables rules.'),
            )
            return False
        return True


class _ContentPage(QWizardPage):
    def __init__(self, wizard):
        super().__init__(wizard)
        FWFUiLoader(self).load(str(_UI_DIR / 'importcontentpage_q.ui'))
        self._wizard = wizard
        platforms = get_enabled_platforms()
        for key, display in sorted(platforms.items(), key=lambda t: t[1].casefold()):
            self.platform.addItem(display, key)
        # nftables is the default wherever it is enabled, whatever the
        # ruleset was read from - the same rule every platform list follows.
        index = self.platform.findData('nftables')
        if index >= 0:
            self.platform.setCurrentIndex(index)
        self.tables.itemChanged.connect(self.completeChanged)

    def initializePage(self):
        wizard = self._wizard
        self.tables.clear()
        has_iptables_rules = any(
            item.ruleset.source == 'iptables'
            and any(
                chain.rules for t in item.ruleset.tables for chain in t.chains.values()
            )
            for item in wizard.inputs
        )
        notes = []
        for index, item in enumerate(wizard.inputs):
            for table in item.ruleset.tables:
                rules = sum(len(chain.rules) for chain in table.chains.values())
                if item.ruleset.source == 'nftables':
                    family = getattr(table, 'nft_family', '')
                    text = f'{item.label}: table {family} {table.name} ({table.kind}, {rules} rules)'
                else:
                    text = f'{item.label}: table {table.name} ({rules} rules)'
                entry = QListWidgetItem(text)
                entry.setFlags(entry.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                checked = rules > 0 and table.kind in ('filter', 'nat')
                if item.ruleset.source == 'nftables' and _is_iptables_nft_table(table):
                    # The same rules are in the iptables-save output, with
                    # the parameters the nft listing leaves out.
                    checked = checked and not has_iptables_rules
                    entry.setText(text + ' - written by iptables-nft')
                    notes.append(table.name)
                entry.setCheckState(
                    Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
                )
                entry.setData(Qt.ItemDataRole.UserRole, (index, id(table)))
                self.tables.addItem(entry)
        text = self.tr(
            f'{len(wizard.inputs)} input(s) read. Check the tables to import.'
        )
        if notes:
            text += self.tr(
                ' Tables written by iptables-nft list their matches only as "xt"'
                ' in nftables; import them from the iptables-save output.'
            )
        self.summary.setText(text)

    def isComplete(self):
        return any(
            self.tables.item(i).checkState() == Qt.CheckState.Checked
            for i in range(self.tables.count())
        )

    def validatePage(self):
        picked = set()
        for i in range(self.tables.count()):
            entry = self.tables.item(i)
            if entry.checkState() == Qt.CheckState.Checked:
                picked.add(entry.data(Qt.ItemDataRole.UserRole)[1])
        self._wizard.picked_tables = picked
        self._wizard.platform = self.platform.currentData()
        return True


class _NamePage(QWizardPage):
    def __init__(self, wizard):
        super().__init__(wizard)
        FWFUiLoader(self).load(str(_UI_DIR / 'importfirewallnamepage_q.ui'))
        self._wizard = wizard
        self.setCommitPage(True)
        self.firewallName.textChanged.connect(self.completeChanged)

    def initializePage(self):
        if not self.firewallName.text():
            self.firewallName.setText(self._wizard.suggested_name or 'imported')

    def isComplete(self):
        return bool(self.firewallName.text().strip())

    def validatePage(self):
        wizard = self._wizard
        wizard.fw_name = self.firewallName.text().strip()
        wizard.deduplicate = self.deduplicateOnImport.isChecked()
        if wizard.fw_name in wizard.taken_firewall_names():
            QMessageBox.warning(
                self,
                self.tr('Import Firewall'),
                self.tr(
                    f'The library already has a firewall named "{wizard.fw_name}".'
                ),
            )
            return False
        return True


class _ProgressPage(QWizardPage):
    def __init__(self, wizard):
        super().__init__(wizard)
        FWFUiLoader(self).load(str(_UI_DIR / 'importprogresspage_q.ui'))
        self._wizard = wizard
        self._errors = 0
        self._warnings = 0

    def initializePage(self):
        self.importLog.clear()
        self._errors = self._warnings = 0
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._wizard.run_import(self._log)
        finally:
            QApplication.restoreOverrideCursor()

    def _log(self, severity, text):
        fmt = QTextCharFormat()
        if severity == 'error':
            fmt.setForeground(QColor('red'))
            self._errors += 1
        elif severity == 'warning':
            fmt.setForeground(QColor('#b06000'))
            self._warnings += 1
        cursor = self.importLog.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if not self.importLog.document().isEmpty():
            cursor.insertBlock()
        prefix = {'error': 'Error: ', 'warning': 'Warning: '}.get(severity, '')
        cursor.insertText(prefix + text, fmt)
        self.errors_count_display.setText(str(self._errors))
        self.warnings_count_display.setText(str(self._warnings))
        self.importLog.ensureCursorVisible()

    @Slot()
    def saveLog(self):
        name, _filter = QFileDialog.getSaveFileName(
            self,
            self.tr('Save import log'),
            'import.log',
            self.tr('Text files (*.txt *.log)'),
        )
        if name:
            Path(name).write_text(self.importLog.toPlainText() + '\n', encoding='utf-8')


class ImportFirewallWizard(QWizard):
    """The import wizard; :attr:`fw_id` holds the firewall it made."""

    def __init__(self, db_manager, library_id, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr('Import Firewall'))
        self.db_manager = db_manager
        self.library_id = library_id
        self.inputs = []
        self.interface_addresses = None
        self.lookup = None
        self.suggested_name = ''
        self.picked_tables = set()
        self.platform = 'nftables'
        self.fw_name = ''
        self.deduplicate = True
        self.fw_id = None
        for page in (_SourcePage, _ContentPage, _NamePage, _ProgressPage):
            self.addPage(page(self))
        self.resize(680, 560)

    def taken_firewall_names(self):
        with self.db_manager.session() as session:
            return set(
                session.scalars(
                    sqlalchemy.select(Host.name).where(
                        Host.library_id == self.library_id
                    )
                )
            )

    def run_import(self, log):
        version = ''
        if self.lookup is not None:
            version = self.lookup.entry(self.platform)
        rulesets = [item.ruleset for item in self.inputs]
        try:
            plan = plan_import(
                self.db_manager,
                self.library_id,
                rulesets,
                self.fw_name,
                self.platform,
                version=version,
                group_paths=SYSTEM_GROUP_PATHS,
                deduplicate=self.deduplicate,
                table_filter=lambda table: id(table) in self.picked_tables,
                interface_addresses=self.interface_addresses,
            )
            for severity, text in plan.messages:
                log(severity, text)
            fw_id, unresolved = apply_plan(
                self.db_manager, self.library_id, plan, group_paths=SYSTEM_GROUP_PATHS
            )
        except Exception as exc:  # the log is the place to say so
            log('error', f'The import failed: {type(exc).__name__}: {exc}')
            return
        for path in unresolved:
            log('warning', f'A reference could not be resolved: {path}')
        self.db_manager.save_state(f'Import firewall "{self.fw_name}"')
        self.fw_id = fw_id
        log(
            'info',
            f'Firewall "{self.fw_name}" created: {plan.imported_rules} rules imported, '
            f'{plan.unsupported_rules} imported disabled, '
            f'{plan.widened_rules} blocking more than the original, '
            f'{len(plan.objects)} new objects.',
        )
