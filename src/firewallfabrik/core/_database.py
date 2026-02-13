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

import contextlib
import dataclasses
import io
import logging
import pathlib
import re
import time

import sqlalchemy
import sqlalchemy.event
import sqlalchemy.orm

from . import objects
from ._xml_reader import XmlReader
from ._yaml_reader import YamlReader
from ._yaml_writer import YamlWriter

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class HistoryEntry:
    """Internal: snapshot + metadata."""

    state: bytes
    timestamp: float
    description: str = ''


@dataclasses.dataclass(frozen=True, slots=True)
class HistorySnapshot:
    """Public: metadata for one entry, without state bytes."""

    index: int
    timestamp: float
    description: str
    is_current: bool


def duplicate_object_name(exc, library_names=None, parent_names=None):
    """Extract the duplicate object name from a UNIQUE-constraint IntegrityError.

    *library_names* is an optional ``{uuid_hex: name}`` mapping used to
    resolve a ``library_id`` column to a human-readable library name.

    *parent_names* is an optional ``{uuid_hex: context_str}`` mapping used to
    resolve any parent FK column (e.g. ``device_id``) to a human-readable
    context string when ``library_id`` is not available.

    Returns a string like ``"User > TCPService 'ssh'"`` (with library) or
    ``"TCPService 'ssh'"`` (without), or *None* when the name cannot be
    determined.
    """
    stmt = getattr(exc, 'statement', None) or ''
    params = getattr(exc, 'params', None)
    if not stmt or not params:
        return None
    m = re.search(r'\(([^)]+)\)\s*VALUES', stmt)
    if not m:
        return None
    cols = [c.strip() for c in m.group(1).split(',')]

    # Parse the constraint columns and table name from the error message
    # (e.g. "UNIQUE constraint failed: services.library_id, services.type, services.name")
    constraint_cols = set()
    constraint_table = ''
    orig_msg = str(getattr(exc, 'orig', ''))
    cm = re.search(r'UNIQUE constraint failed:\s*(.+)', orig_msg)
    if cm:
        parts = [c.strip().split('.') for c in cm.group(1).split(',')]
        constraint_cols = {p[-1] for p in parts}
        constraint_table = parts[0][0] if parts and len(parts[0]) > 1 else ''

    rows = params if isinstance(params, list) else [params]

    # Find the actual conflicting row by looking for a duplicate on the
    # constraint columns.  Fall back to the first row if we cannot tell.
    row = rows[0] if rows else None
    if constraint_cols and len(rows) > 1:
        key_idxs = [cols.index(c) for c in constraint_cols if c in cols]
        if key_idxs:
            seen = {}
            for r in rows:
                key = tuple(r[i] for i in key_idxs)
                if key in seen:
                    row = r
                    break
                seen[key] = r

    if not isinstance(row, (tuple, list)):
        return None
    name_idx = cols.index('name') if 'name' in cols else -1
    if name_idx < 0 or name_idx >= len(row):
        return None
    name = row[name_idx]
    type_idx = cols.index('type') if 'type' in cols else -1
    if 0 <= type_idx < len(row):
        obj_part = f"{row[type_idx]} '{name}'"
    elif constraint_table:
        # No STI type column — derive a label from the table name in the
        # constraint error (e.g. "interfaces.device_id" → "Interface").
        _table_labels = {
            'interfaces': 'Interface',
            'intervals': 'Interval',
            'libraries': 'Library',
        }
        label = _table_labels.get(constraint_table, constraint_table.title())
        obj_part = f"{label} '{name}'"
    else:
        obj_part = f"'{name}'"
    context = None
    if library_names:
        lib_idx = cols.index('library_id') if 'library_id' in cols else -1
        if 0 <= lib_idx < len(row):
            context = library_names.get(row[lib_idx])
    if not context and parent_names:
        # Try any FK column present in the constraint (e.g. device_id)
        for fk_col in constraint_cols - {'type', 'name'}:
            fk_idx = cols.index(fk_col) if fk_col in cols else -1
            if 0 <= fk_idx < len(row):
                context = parent_names.get(row[fk_idx])
                if context:
                    break
    if context:
        return f'{context} > {obj_part}'
    return obj_part


class DatabaseManager:
    def __init__(self, connection_string='sqlite:///:memory:'):
        self.engine = sqlalchemy.create_engine(connection_string, echo=False)
        self._session_factory = sqlalchemy.orm.sessionmaker(self.engine)
        self._history = []
        self._current_index = -1
        self._saved_index = -1
        self.on_history_changed = None
        self.ref_index = {}
        objects.enable_sqlite_fks(self.engine)
        self._reset_db(True)

    @property
    def can_undo(self):
        return self._current_index > 0

    @property
    def can_redo(self):
        return self._current_index < len(self._history) - 1

    @property
    def is_dirty(self):
        """True when the database has unsaved changes."""
        return self._current_index != self._saved_index

    def _notify_history_changed(self):
        if self.on_history_changed is not None:
            self.on_history_changed()

    @contextlib.contextmanager
    def session(self, description=''):
        """Create a new database session. This session automatically commits the transaction exits and saves changes to the undo stack (if necessary) when the contextmanager exits."""
        session = self._session_factory()
        _core_dml = False

        def _track_dml(orm_execute_state):
            nonlocal _core_dml
            if not orm_execute_state.is_select:
                _core_dml = True

        sqlalchemy.event.listen(session, 'do_orm_execute', _track_dml)
        try:
            yield session
            is_dirty = (
                len(session.new) + len(session.dirty) + len(session.deleted) > 0
                or _core_dml
            )
            session.commit()
            if is_dirty:
                logger.debug('Database state changed, saving to undo stack')
                self.save_state(description)
        except Exception:
            session.rollback()
            raise
        finally:
            sqlalchemy.event.remove(session, 'do_orm_execute', _track_dml)
            session.close()

    def create_session(self):
        """Create a new database session for manual use. Remember to call save_state() afterwards if any objects were added, changed, or updated."""
        return self._session_factory()

    def save_state(self, description=''):
        """Save the current state of the database to the history."""
        logger.debug('Saving database state to history')
        del self._history[self._current_index + 1 :]
        entry = HistoryEntry(
            state=self._dump_db(),
            timestamp=time.time(),
            description=description,
        )
        self._history.append(entry)
        self._current_index = len(self._history) - 1
        logger.debug(
            'History has %d entries, current index %d',
            len(self._history),
            self._current_index,
        )
        self._notify_history_changed()

    def undo(self):
        """Undo the last database state change."""
        new_index = self._current_index - 1
        if new_index >= 0:
            logger.debug('Undoing last database state change')
            return self.jump_to(new_index)
        return False

    def redo(self):
        """Redo the last undone database state change."""
        new_index = self._current_index + 1
        if new_index < len(self._history):
            logger.debug('Redoing last undone database state change')
            return self.jump_to(new_index)
        return False

    def clear_states(self):
        """Clear all saved states from the history."""
        logger.debug('Clearing all saved database states')
        self._history.clear()
        self._current_index = -1
        self._notify_history_changed()

    def jump_to(self, index):
        """Jump to a specific history state by index.

        Returns True if the state was changed, False otherwise.
        """
        if not 0 <= index < len(self._history):
            logger.info(
                'No history jump since index %d is out of range (0..%d)',
                index,
                len(self._history) - 1,
            )
            return False
        if index == self._current_index:
            logger.info('Already at history index %d', index)
            return False
        self._current_index = index
        self._restore_db(self._history[self._current_index].state)
        logger.debug('Jumped to history index %d', self._current_index)
        self._notify_history_changed()
        return True

    def get_history(self):
        """Return a list of history snapshots and the current index.

        Returns a list of HistorySnapshots
        """
        snapshots = [
            HistorySnapshot(
                index=i,
                timestamp=entry.timestamp,
                description=entry.description,
                is_current=(i == self._current_index),
            )
            for i, entry in enumerate(self._history)
        ]
        return snapshots

    def load(self, path):
        path = pathlib.Path(path)
        logger.debug('Loading database from %s', path)
        match path.suffix:
            case '.fwb':
                self._load_xml(path, exclude_libraries={'Deleted Objects'})
                path = path.with_suffix('.fwf')
            case '.fwf':
                self._load_yaml(path)
            case _:
                raise ValueError(f'Unsupported file extension: {path}')
        self.save_state('Load file')
        self._saved_index = self._current_index
        return path

    def save(self, path):
        path = pathlib.Path(path)
        logger.debug('Saving database to %s', path)
        match path.suffix:
            case '.fwf':
                self._save_yaml(path)
            case _:
                raise ValueError(f'Unsupported file extension: {path}')
        self._saved_index = self._current_index

    def _import(self, data):
        self.ref_index = data.ref_index
        # Build UUID-hex-to-name maps so that IntegrityError messages can
        # include context (the transaction is rolled back before callers see
        # the exception, so a DB lookup is not possible).
        self._library_names = {
            str(lib.id).replace('-', ''): lib.name for lib in data.database.libraries
        }
        # Map device UUIDs to their full tree path so that child objects
        # (e.g. interfaces) without their own library_id can still be
        # located in the tree.
        group_index = {}
        for lib in data.database.libraries:
            for grp in lib.groups:
                group_index[grp.id] = grp
        self._parent_names = {}
        for lib in data.database.libraries:
            for dev in lib.devices:
                parts = [dev.name]
                grp = group_index.get(dev.group_id)
                while grp is not None:
                    parts.append(grp.name)
                    grp = group_index.get(grp.parent_group_id)
                parts.append(lib.name)
                parts.reverse()
                self._parent_names[str(dev.id).replace('-', '')] = ' > '.join(parts)
        with self.session() as session:
            session.add(data.database)
            session.flush()
            if data.memberships:
                session.execute(
                    objects.group_membership.insert(),
                    data.memberships,
                )
            if data.rule_element_rows:
                session.execute(
                    objects.rule_elements.insert(),
                    data.rule_element_rows,
                )

    def _load_xml(self, path, exclude_libraries=None):
        reader = XmlReader()
        result = reader.parse(path, exclude_libraries=exclude_libraries)
        self._import(result)

    def _save_yaml(self, output_path):
        writer = YamlWriter()
        with self.session() as session:
            db = session.scalars(
                sqlalchemy.select(objects.FWObjectDatabase),
            ).first()
            if db is None:
                raise ValueError('No database found')
            writer.write(session, db.id, output_path)

    def _load_yaml(self, input_path):
        reader = YamlReader()
        result = reader.parse(input_path)
        self._import(result)

    def _dump_db(self):
        backup = io.BytesIO()
        for line in self.engine.raw_connection().iterdump():
            backup.write(f'{line}\n'.encode())
        return backup.getvalue()

    def _restore_db(self, state):
        self._reset_db(False)
        connection = self.engine.raw_connection()
        connection.execute('PRAGMA foreign_keys = OFF')
        connection.executescript(state.decode('utf-8'))
        connection.execute('PRAGMA foreign_keys = ON')

    def _reset_db(self, recreate_schema):
        logger.debug('Resetting database')
        objects.Base.metadata.drop_all(self.engine)
        if recreate_schema:
            logger.debug('Recreating database schema')
            objects.Base.metadata.create_all(self.engine)
