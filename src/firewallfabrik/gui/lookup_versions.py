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

"""Tools > Lookup Versions of All Firewalls.

The "Lookup Version ..." button of the firewall panel, for every firewall
of the data file at once: each one is asked over ssh which iptables,
nftables and distribution it runs (``version_lookup``), and a dialog
lists the entry that fits each, to be applied in one step that Undo
takes back.  Firewall Builder has no such tool.

Firewalls that log in with a key or the ssh-agent are asked in parallel.
A firewall that wants a password is asked afterwards, one at a time, and
gets a password prompt of its own: a password typed for one firewall is
never sent to another.  Locked firewalls and clusters (which have no
release of their own) are left out.
"""

import concurrent.futures
import dataclasses
from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QByteArray, QSettings, Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QProgressDialog,
    QTreeWidgetItem,
)

from firewallfabrik.core._validation import is_read_only
from firewallfabrik.core.objects import Firewall
from firewallfabrik.gui import version_lookup
from firewallfabrik.gui.ui_loader import FWFUiLoader
from firewallfabrik.platforms import _versions

_SETTINGS_GEOMETRY = 'LookupVersionsDialog/geometry'
_TITLE = 'Lookup Versions of All Firewalls'

# ssh processes running at the same time; enough for a data file of a few
# dozen firewalls without opening a connection to each one at once.
_MAX_WORKERS = 8

_COL_NAME, _COL_FOUND, _COL_CURRENT, _COL_NEW = range(4)


@dataclasses.dataclass
class _Target:
    """One firewall to ask, and what came of it."""

    fw_id: object
    name: str
    platform: str
    version: str
    login: dict
    found: str = ''
    entry: str = ''
    remark: str = ''


def _found(result):
    """What the firewall runs, in one line."""
    iptables = result.iptables or 'not installed'
    if result.iptables_backend:
        iptables = f'{iptables} ({result.iptables_backend})'
    return (
        f'nftables {result.nftables or "not installed"}, iptables {iptables}, '
        f'{result.distribution or "unknown distribution"}'
    )


def _settle(target, result):
    """Fill in *target* from the *result* of its lookup."""
    target.found = _found(result)
    target.entry = result.entry(target.platform)
    if not target.entry:
        target.remark = f'{target.platform} is not installed, so no entry fits'
    elif target.entry == target.version:
        target.remark = 'fits already'


def _collect(db_manager):
    """The firewalls to ask, and the ones left out with the reason."""
    settings = QSettings()
    ssh_path = settings.value('SSH/SSHPath', '', type=str)
    timeout = settings.value('SSH/SSHTimeout', 10, type=int)
    targets, skipped = [], []
    with db_manager.session() as session:
        firewalls = session.scalars(
            sqlalchemy.select(Firewall)
            .where(Firewall.type == 'Firewall')
            .order_by(Firewall.name)
        ).all()
        for fw in firewalls:
            data = fw.data or {}
            target = _Target(
                fw_id=fw.id,
                name=fw.name,
                platform=data.get('platform', ''),
                version=data.get('version', ''),
                login=version_lookup.login(fw, ssh_path, timeout),
            )
            if is_read_only(fw):
                target.remark = 'locked, not asked'
                skipped.append(target)
            elif not _versions.versions(target.platform):
                target.remark = 'no platform with a version, not asked'
                skipped.append(target)
            else:
                targets.append(target)
    return targets, skipped


def _ask_without_password(parent, targets):
    """Ask every target that logs in without a password, in parallel.

    Return the targets that want a password.  Cancelling the progress
    dialog leaves the targets not answered yet unasked; ssh processes
    already running end on their own within their timeout.
    """
    progress = QProgressDialog(
        'Asking the firewalls ...', 'Cancel', 0, len(targets), parent
    )
    progress.setWindowTitle(_TITLE)
    progress.setWindowModality(Qt.WindowModality.WindowModal)
    progress.setMinimumDuration(0)
    progress.setValue(0)
    need_password = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS)
    futures = {
        executor.submit(version_lookup.run, **target.login): target
        for target in targets
    }
    pending = set(futures)
    try:
        while pending and not progress.wasCanceled():
            done, pending = concurrent.futures.wait(
                pending,
                timeout=0.1,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                target = futures[future]
                try:
                    _settle(target, future.result())
                except version_lookup.AuthenticationRequired:
                    need_password.append(target)
                except version_lookup.LookupFailed as exc:
                    target.remark = f'not reachable: {exc}'
            progress.setValue(len(futures) - len(pending))
            QApplication.processEvents()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        progress.close()
    if pending:
        # Cancelled: the firewalls still to be asked are not prompted for
        # a password either.
        for target in [futures[future] for future in pending] + need_password:
            target.remark = 'not asked, cancelled'
        return []
    return need_password


def _ask_with_password(parent, targets):
    """Ask each target that wants a password, prompting for it."""
    for target in targets:
        login = target.login
        password, ok = QInputDialog.getText(
            parent,
            _TITLE,
            f'{target.name}: password for {login["user"]}@{login["address"]}:',
            QLineEdit.EchoMode.Password,
        )
        if not ok or not password:
            target.remark = 'not asked, no password given'
            continue
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            _settle(target, version_lookup.run(password=password, **login))
        except version_lookup.LookupFailed as exc:
            target.remark = f'not reachable: {exc}'
        finally:
            QApplication.restoreOverrideCursor()


def _choose(parent, targets):
    """Show the results; return the targets to change, or None."""
    ui_path = Path(__file__).resolve().parent / 'ui' / 'lookupversionsdialog_q.ui'
    dlg = QDialog(parent)
    FWFUiLoader(dlg).load(str(ui_path))
    geometry = QSettings().value(_SETTINGS_GEOMETRY, type=QByteArray)
    if not (geometry and dlg.restoreGeometry(geometry)):
        geo = dlg.geometry()
        geo.moveCenter(parent.geometry().center())
        dlg.setGeometry(geo)

    items = {}
    for target in targets:
        item = QTreeWidgetItem()
        item.setText(_COL_NAME, target.name)
        item.setText(_COL_FOUND, target.found)
        item.setText(
            _COL_CURRENT,
            _versions.label(target.platform, target.version)
            if target.version
            else _versions.unset_label(target.platform),
        )
        if target.remark:
            item.setText(_COL_NEW, target.remark)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
        else:
            item.setText(_COL_NEW, _versions.label(target.platform, target.entry))
            item.setCheckState(_COL_NAME, Qt.CheckState.Checked)
            items[target.fw_id] = item
        dlg.firewallList.addTopLevelItem(item)
    for column in range(dlg.firewallList.columnCount()):
        dlg.firewallList.resizeColumnToContents(column)
    dlg.applyButton.setEnabled(bool(items))

    accepted = dlg.exec() == QDialog.DialogCode.Accepted
    QSettings().setValue(_SETTINGS_GEOMETRY, dlg.saveGeometry())
    if not accepted:
        return None
    return [
        target
        for target in targets
        if target.fw_id in items
        and items[target.fw_id].checkState(_COL_NAME) == Qt.CheckState.Checked
    ]


def _apply(db_manager, chosen):
    """Set the entries in one change, stamped like an edit in the panel."""
    now = int(datetime.now(tz=UTC).timestamp())
    entries = {target.fw_id: target.entry for target in chosen}
    with db_manager.session('Lookup versions of all firewalls') as session:
        for fw in session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.id.in_(entries))
        ):
            fw.data = {
                **(fw.data or {}),
                'version': entries[fw.id],
                'lastModified': now,
            }


def lookup_all_versions(window):
    """Run the tool for the data file open in main window *window*.

    Return True when versions were changed.
    """
    db_manager = window._db_manager
    targets, skipped = _collect(db_manager)
    if not targets:
        QMessageBox.information(
            window,
            _TITLE,
            'The data file has no firewall whose version could be looked up.',
        )
        return False
    need_password = _ask_without_password(window, targets)
    _ask_with_password(window, need_password)
    chosen = _choose(window, sorted(targets + skipped, key=lambda t: t.name))
    if not chosen:
        return False
    _apply(db_manager, chosen)
    return True
