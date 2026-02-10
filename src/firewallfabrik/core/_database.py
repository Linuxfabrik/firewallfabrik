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
import time

import sqlalchemy
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


class DatabaseManager:
    def __init__(self, connection_string='sqlite:///:memory:'):
        self.engine = sqlalchemy.create_engine(connection_string, echo=False)
        self._session_factory = sqlalchemy.orm.sessionmaker(self.engine)
        self._history = []
        self._current_index = -1
        objects.enable_sqlite_fks(self.engine)
        self._reset_db(True)

    @contextlib.contextmanager
    def session(self, description=''):
        """Create a new database session. This session automatically commits the transaction exits and saves changes to the undo stack (if necessary) when the contextmanager exits."""
        session = self._session_factory()
        try:
            yield session
            is_dirty = len(session.new) + len(session.dirty) + len(session.deleted) > 0
            session.commit()
            if is_dirty:
                logger.debug('Database state changed, saving to undo stack')
                self.save_state(description)
        except Exception:
            session.rollback()
            raise
        finally:
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
        self.save_state('Loaded from file')
        return path

    def save(self, path):
        path = pathlib.Path(path)
        logger.debug('Saving database to %s', path)
        match path.suffix:
            case '.fwf':
                self._save_yaml(path)
            case _:
                raise ValueError(f'Unsupported file extension: {path}')

    def _import(self, data):
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
