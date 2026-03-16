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

"""File Properties dialog showing metadata about the currently loaded file."""

from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QLabel,
    QVBoxLayout,
)

from firewallfabrik.core.objects import (
    Address,
    Firewall,
    Host,
    Library,
    Network,
    Rule,
    Service,
)


def _human_file_size(size_bytes):
    """Return a human-readable file size string."""
    for unit in ('B', 'KB', 'MB', 'GB'):
        if abs(size_bytes) < 1024:
            return f'{size_bytes:.1f} {unit}' if unit != 'B' else f'{size_bytes} {unit}'
        size_bytes /= 1024
    return f'{size_bytes:.1f} TB'


class FilePropertiesDialog(QDialog):
    """Modal dialog displaying metadata for the currently loaded firewall file.

    Shows the file location, size, last-modified timestamp, and object
    counts queried from the in-memory SQLite database.
    """

    def __init__(self, db_manager, file_path, parent=None):
        super().__init__(parent)
        self.setWindowTitle('File Properties')
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        # --- File information ---
        file_form = QFormLayout()
        file_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        file_path = Path(file_path) if file_path else None
        file_form.addRow(
            'Location:', self._value_label(str(file_path) if file_path else 'N/A')
        )

        if file_path and file_path.exists():
            stat = file_path.stat()
            file_form.addRow(
                'File size:', self._value_label(_human_file_size(stat.st_size))
            )
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC).astimezone()
            file_form.addRow(
                'Last modified:', self._value_label(mtime.strftime('%Y-%m-%d %H:%M:%S'))
            )
        else:
            file_form.addRow('File size:', self._value_label('N/A'))
            file_form.addRow('Last modified:', self._value_label('N/A'))

        layout.addLayout(file_form)

        # --- Separator ---
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(line)

        # --- Object counts ---
        counts_form = QFormLayout()
        counts_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        counts = self._query_counts(db_manager)
        counts_form.addRow('Libraries:', self._value_label(str(counts['libraries'])))
        counts_form.addRow('Addresses:', self._value_label(str(counts['addresses'])))
        counts_form.addRow('Firewalls:', self._value_label(str(counts['firewalls'])))
        counts_form.addRow('Hosts:', self._value_label(str(counts['hosts'])))
        counts_form.addRow('Networks:', self._value_label(str(counts['networks'])))
        counts_form.addRow('Rules:', self._value_label(str(counts['rules'])))
        counts_form.addRow('Services:', self._value_label(str(counts['services'])))

        layout.addLayout(counts_form)

        # --- Button box ---
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)

        self.adjustSize()

        # Centre on parent window.
        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    @staticmethod
    def _value_label(text):
        """Create a QLabel suitable for a form value field."""
        lbl = QLabel(text)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lbl.setWordWrap(True)
        return lbl

    @staticmethod
    def _query_counts(db_manager):
        """Query object counts from the database."""
        session = db_manager.create_session()
        try:
            return {
                'addresses': session.query(sqlalchemy.func.count(Address.id))
                .filter(Address.type == 'Address')
                .scalar(),
                'firewalls': session.query(sqlalchemy.func.count(Firewall.id))
                .filter(Host.type == 'Firewall')
                .scalar(),
                'hosts': session.query(sqlalchemy.func.count(Host.id))
                .filter(Host.type == 'Host')
                .scalar(),
                'libraries': session.query(sqlalchemy.func.count(Library.id)).scalar(),
                'networks': session.query(sqlalchemy.func.count(Network.id))
                .filter(Address.type.in_(['Network', 'NetworkIPv6']))
                .scalar(),
                'rules': session.query(sqlalchemy.func.count(Rule.id)).scalar(),
                'services': session.query(sqlalchemy.func.count(Service.id)).scalar(),
            }
        finally:
            session.close()
