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
                'can later be imported back into FirewallFabrik.\n\n'
                'The Standard library is excluded because it ships with '
                'every FirewallFabrik installation.'
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
            self.tr('Select one or more libraries to include in the exported file.'),
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


def import_library(parent_widget, db_manager, reload_callback):
    """Run the library-import workflow.

    Opens a file dialog, reads the selected ``.fwf`` file, and merges
    its libraries into the current database.  Mirrors fwbuilder's
    ``ProjectPanel::fileImport()`` / ``loadLibrary()``.

    Parameters
    ----------
    parent_widget : QWidget
        Parent widget for centering dialogs.
    db_manager : DatabaseManager
        The active database manager instance.
    reload_callback : callable
        Called after a successful import to refresh the object tree.
    """
    file_path, _ = QFileDialog.getOpenFileName(
        parent_widget,
        parent_widget.tr('Import Library'),
        '',
        parent_widget.tr(
            'FirewallFabrik files (*.fwf);;'
            'Firewall Builder files (*.fwb);;'
            'All Files (*)'
        ),
    )
    if not file_path:
        return

    file_path = Path(file_path)
    if not file_path.is_file():
        QMessageBox.warning(
            parent_widget,
            parent_widget.tr('Import Library'),
            parent_widget.tr(f'File not found: {file_path}'),
        )
        return

    QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
    try:
        count, unresolved = _do_import_library(db_manager, file_path)
    except Exception as exc:
        QApplication.restoreOverrideCursor()
        logger.exception('Library import failed')
        # Naming the file alone leaves the administrator with a dialog that
        # says nothing and a traceback only in the terminal.
        QMessageBox.critical(
            parent_widget,
            parent_widget.tr('Import Library'),
            parent_widget.tr(
                f'Failed to import library from:\n{file_path}\n\n'
                f'{type(exc).__name__}: {exc}'
            ),
        )
        return
    finally:
        QApplication.restoreOverrideCursor()

    if count == 0:
        QMessageBox.information(
            parent_widget,
            parent_widget.tr('Import Library'),
            parent_widget.tr('No new libraries found in the file.'),
        )
        return

    reload_callback()

    text = f'Successfully imported {count} library/libraries from:\n{file_path}'
    if unresolved:
        shown = '\n'.join(unresolved[:15])
        if len(unresolved) > 15:
            shown += f'\n... and {len(unresolved) - 15} more'
        text += (
            f'\n\n{len(unresolved)} reference(s) could not be resolved, because '
            'the objects they name are not in this file. The rules using them '
            'match everything on that side until the objects are added:\n'
            f'{shown}'
        )
    QMessageBox.information(
        parent_widget,
        parent_widget.tr('Import Library'),
        parent_widget.tr(text),
    )


def _unique_library_name(name, taken):
    """Return *name*, or the first free ``name-1``, ``name-2``, ... .

    Same shape as ``ObjectManipulator::makeNameUnique``, which is what
    Firewall Builder applies to every library it imports.
    """
    if name not in taken:
        return name
    suffix = 1
    while f'{name}-{suffix}' in taken:
        suffix += 1
    return f'{name}-{suffix}'


def _do_import_library(db_manager, file_path):
    """Read *file_path* and merge its libraries into the current database.

    The file is opened in a database of its own and every library that is
    not already there is carried across by the same writer and reader the
    ``.fwf`` format uses, so nested objects, group memberships and rule
    elements come with it.

    Returns the number of libraries imported and the reference paths that
    named an object this database has not got - an object of the file's own
    Standard library, most of the time, which stays behind.  A rule element
    that loses its object matches everything instead, so the caller has to
    be able to say so.
    """
    from firewallfabrik.core import objects
    from firewallfabrik.core._database import DatabaseManager
    from firewallfabrik.core._yaml_reader import YamlReader

    import_mgr = DatabaseManager()
    import_mgr.load(file_path)

    imported = 0
    unresolved = []
    try:
        with import_mgr.session() as imp_session, db_manager.session() as cur_session:
            cur_db = cur_session.scalars(sqlalchemy.select(FWObjectDatabase)).first()
            if cur_db is None:
                return 0, []

            existing_names = {
                lib.name
                for lib in cur_session.scalars(
                    sqlalchemy.select(Library).where(
                        Library.database_id == cur_db.id,
                    ),
                ).all()
            }

            imp_libs = imp_session.scalars(sqlalchemy.select(Library)).all()

            # A name that is taken is renamed, not skipped: two data files
            # of the same house both call their library "User", and
            # skipping meant File > Import Library did nothing at all.
            # Firewall Builder renames too (`makeNameUnique` in
            # ProjectPanel::loadLibrary).  This has to happen before the
            # index below, or every reference inside the library still
            # carries the old name and resolves to the library that was
            # already there.
            to_import = []
            for lib in imp_libs:
                if lib.name == 'Standard':
                    continue
                lib.name = _unique_library_name(lib.name, existing_names)
                existing_names.add(lib.name)
                to_import.append(lib)
            imp_session.flush()

            # Over every library of the file, not only the ones being
            # imported: an object of the library we take may reference one
            # in Standard, and without a path for it the reference is
            # written out as a raw UUID that resolves to nothing.
            writer = YamlWriter()
            writer._build_ref_index(imp_session, imp_libs)

            for lib in to_import:
                lib_dict = writer._serialize_library(imp_session, lib)

                reader = YamlReader()
                # A reference into a library that stays behind - Standard,
                # most of the time - has to land on the object this
                # database already has, so the reader starts from the paths
                # of the current tree and adds the new library's own.
                reader._ref_index.update(db_manager.ref_index)
                new_lib = reader._parse_library(lib_dict, cur_db)
                reader._resolve_deferred()

                cur_session.add(new_lib)
                cur_session.flush()
                if reader._memberships:
                    cur_session.execute(
                        objects.group_membership.insert(),
                        reader._memberships,
                    )
                if reader._rule_element_rows:
                    cur_session.execute(
                        objects.rule_elements.insert(),
                        reader._rule_element_rows,
                    )

                # So that a later save, and a second import, can resolve a
                # reference into what was just added.
                db_manager.ref_index.update(reader._ref_index)
                unresolved.extend(reader.unresolved_refs)
                imported += 1
    finally:
        import_mgr.engine.dispose()

    return imported, sorted(set(unresolved))
