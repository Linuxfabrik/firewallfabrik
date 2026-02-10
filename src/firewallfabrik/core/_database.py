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
import io
import logging
import pathlib

import sqlalchemy
import sqlalchemy.orm

from . import objects
from ._xml_reader import XmlReader
from ._yaml_reader import YamlReader
from ._yaml_writer import YamlWriter

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self, connection_string='sqlite:///:memory:'):
        self.engine = sqlalchemy.create_engine(connection_string, echo=False)
        self._session_factory = sqlalchemy.orm.sessionmaker(self.engine)
        self._undo_stack = []
        objects.enable_sqlite_fks(self.engine)
        self._reset_db(True)

    @contextlib.contextmanager
    def session(self):
        """Create a new database session. This session automatically commits the transaction exits and saves changes to the undo stack (if necessary) when the contextmanager exits."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            if len(session.new) + len(session.dirty) + len(session.deleted) > 0:
                logger.debug('Database state changed, saving to undo stack')
                self.save_state()
            session.close()

    def create_session(self):
        """Create a new database session for manual use. Remember to call save_state() afterwards if any objects were added, changed, or updated."""
        return self._session_factory()

    def save_state(self):
        """Save the current state of the database to the undo stack."""
        logger.debug('Saving database state to undo stack')
        backup = io.BytesIO()
        for line in self.engine.raw_connection().iterdump():
            backup.write(f'{line}\n'.encode())
        self._undo_stack.append(backup.getvalue())
        logger.debug('Undo stack has now a size of %d', self.nr_undo_states())

    def undo(self):
        """Undo the last database state change."""
        logger.debug('Undoing last database state change')
        if not self._undo_stack or self.nr_undo_states() == 0:
            return False
        saved_state = self._undo_stack.pop()
        self._reset_db(False)
        connection = self.engine.raw_connection()
        connection.execute('PRAGMA foreign_keys = OFF')
        connection.executescript(saved_state.decode('utf-8'))
        connection.execute('PRAGMA foreign_keys = ON')
        logger.debug('Undo stack has now a size of %d', self.nr_undo_states())
        return True

    def nr_undo_states(self):
        return len(self._undo_stack)

    def clear_states(self):
        """Clear all saved states from the undo stack."""
        logger.debug('Clearing all saved database states')
        self._undo_stack.clear()

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
        self.save_state()
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

    def _reset_db(self, recreate_schema):
        logger.debug('Resetting database')
        objects.Base.metadata.drop_all(self.engine)
        if recreate_schema:
            logger.debug('Recreating database schema')
            objects.Base.metadata.create_all(self.engine)
