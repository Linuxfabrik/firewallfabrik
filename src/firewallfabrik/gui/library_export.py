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

"""Library Export dialog and logic.

Allows the user to select one or more libraries and export them to a
standalone ``.fwf`` file that can later be imported into another project.
This mirrors the ``LibExportDialog`` / ``ProjectPanel::fileExport()``
workflow in the original fwbuilder C++ codebase.
"""

import logging
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QVBoxLayout,
)

from firewallfabrik.core._yaml_writer import YamlWriter
from firewallfabrik.core.objects import FWObjectDatabase, Library

logger = logging.getLogger(__name__)


class LibExportDialog(QDialog):
    """Dialog that lets the user pick libraries to export.

    After ``exec()`` returns ``QDialog.Accepted``, call
    :pyattr:`selected_library_ids` and :pyattr:`make_read_only` to
    retrieve the user's choices.
    """

    def __init__(self, session, database_id, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.tr('Export Library'))
        self.setMinimumSize(460, 380)
        self.resize(500, 420)

        self._library_map: dict[int, tuple[str, object]] = {}
        # {row_index: (library_name, library_id)}

        layout = QVBoxLayout(self)

        # --- description label ---
        desc_label = QLabel(
            self.tr(
                'This will export one or more libraries to a file which '
                'can later be imported back into FirewallFabrik.'
            ),
        )
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        # --- library list ---
        list_layout = QHBoxLayout()
        choose_label = QLabel(self.tr('Choose libraries\nto be exported:'))
        choose_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        list_layout.addWidget(choose_label)

        self._libs_list = QListWidget()
        self._libs_list.setSelectionMode(
            QListWidget.SelectionMode.ExtendedSelection,
        )
        self._libs_list.setToolTip(
            self.tr(
                'Select one or more libraries to include in the exported '
                'file. The "Standard" library is excluded because it ships '
                'with every FirewallFabrik installation.'
            ),
        )
        list_layout.addWidget(self._libs_list)
        layout.addLayout(list_layout)

        # --- read-only checkbox ---
        self._export_ro = QCheckBox(
            self.tr('Make exported libraries read-only'),
        )
        self._export_ro.setChecked(True)
        self._export_ro.setToolTip(
            self.tr(
                'When checked, the exported libraries will be marked as '
                'read-only so that they cannot be accidentally modified '
                'after import.'
            ),
        )
        layout.addWidget(self._export_ro)

        # --- button box ---
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        # --- populate library list ---
        self._populate(session, database_id)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def selected_library_ids(self):
        """Return the list of selected library UUIDs."""
        ids = []
        for item in self._libs_list.selectedItems():
            row = self._libs_list.row(item)
            _, lib_id = self._library_map[row]
            ids.append(lib_id)
        return ids

    @property
    def make_read_only(self):
        """Return whether the user wants the exported libraries to be read-only."""
        return self._export_ro.isChecked()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _populate(self, session, database_id):
        """Fill the list widget with available user libraries."""
        libraries = session.scalars(
            sqlalchemy.select(Library)
            .where(Library.database_id == database_id)
            .order_by(Library.name),
        ).all()

        row = 0
        for lib in libraries:
            # Skip the Standard library — it ships with every installation
            if lib.name == 'Standard':
                continue
            item = QListWidgetItem(lib.name)
            icon = QIcon(':/Icons/Library/icon-tree')
            if not icon.isNull():
                item.setIcon(icon)
            self._libs_list.addItem(item)
            self._library_map[row] = (lib.name, lib.id)
            row += 1

    def accept(self):
        """Validate selection before accepting."""
        if not self._libs_list.selectedItems():
            QMessageBox.warning(
                self,
                self.tr('Export Library'),
                self.tr('Please select at least one library to export.'),
            )
            return
        super().accept()


def export_libraries(parent_widget, db_manager):
    """Run the full library-export workflow.

    1. Open the library-selection dialog.
    2. Ask for a destination file.
    3. Write the selected libraries to a ``.fwf`` file.

    Parameters
    ----------
    parent_widget : QWidget
        Parent widget for centering dialogs.
    db_manager : DatabaseManager
        The active database manager instance.
    """
    session = db_manager.create_session()
    try:
        db = session.scalars(sqlalchemy.select(FWObjectDatabase)).first()
        if db is None:
            QMessageBox.warning(
                parent_widget,
                parent_widget.tr('Export Library'),
                parent_widget.tr('No database is currently loaded.'),
            )
            return

        # --- Step 1: library selection ---
        dialog = LibExportDialog(session, db.id, parent=parent_widget)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        selected_ids = dialog.selected_library_ids
        make_ro = dialog.make_read_only

        if not selected_ids:
            return

        # Suggest a default filename based on the first selected library
        first_name, _ = next(
            (v for v in dialog._library_map.values() if v[1] in selected_ids),
            ('export', None),
        )

        # --- Step 2: file dialog ---
        file_path, _ = QFileDialog.getSaveFileName(
            parent_widget,
            parent_widget.tr('Export Library To File'),
            f'{first_name}.fwf',
            parent_widget.tr('FirewallFabrik files (*.fwf)'),
        )
        if not file_path:
            return

        file_path = Path(file_path)
        if file_path.suffix == '':
            file_path = file_path.with_suffix('.fwf')

        # --- Step 3: write the export file ---
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            _write_library_export(
                session,
                db,
                selected_ids,
                make_ro,
                file_path,
            )
        finally:
            QApplication.restoreOverrideCursor()

        QMessageBox.information(
            parent_widget,
            parent_widget.tr('Export Library'),
            parent_widget.tr(f'Library exported successfully to:\n{file_path}'),
        )
    finally:
        session.close()


def _write_library_export(session, db, library_ids, make_ro, output_path):
    """Serialize only the selected libraries to a .fwf file.

    Re-uses :class:`YamlWriter` internals so the output format is
    identical to a normal save.
    """
    libraries = session.scalars(
        sqlalchemy.select(Library).where(
            Library.id.in_(library_ids),
        ),
    ).all()

    writer = YamlWriter()

    # Build ref-index for ALL libraries in the database so that
    # cross-references (e.g. group members pointing to Standard objects)
    # resolve correctly.
    all_libraries = session.scalars(
        sqlalchemy.select(Library).where(
            Library.database_id == db.id,
        ),
    ).all()
    writer._build_ref_index(session, all_libraries)

    # Serialize the database envelope (metadata)
    doc = writer._serialize_database(db)

    # Serialize only the selected libraries
    serialized = []
    for lib in libraries:
        lib_dict = writer._serialize_library(session, lib)
        if make_ro:
            lib_dict['ro'] = True
        serialized.append(lib_dict)

    doc['libraries'] = sorted(serialized, key=lambda lib: lib['name'])

    writer._write_yaml(output_path, doc)
    logger.info(
        'Exported %d library/libraries to %s',
        len(libraries),
        output_path,
    )
