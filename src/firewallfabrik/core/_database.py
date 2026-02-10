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

import sqlalchemy
import sqlalchemy.orm

from . import objects
from ._xml_reader import XmlReader
from ._yaml_reader import YamlReader
from ._yaml_writer import YamlWriter


class DatabaseManager:
    def __init__(self, connection_string='sqlite:///:memory:'):
        self.engine = sqlalchemy.create_engine(connection_string, echo=False)
        self._session_factory = sqlalchemy.orm.sessionmaker(bind=self.engine)
        objects.enable_sqlite_fks(self.engine)
        objects.Base.metadata.create_all(self.engine)

    @contextlib.contextmanager
    def session(self):
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def create_session(self):
        return self._session_factory()

    def load(self, path):
        match path.rsplit('.', 1)[-1]:
            case 'fwb':
                self._load_xml(path, exclude_libraries={'Deleted Objects'})
            case 'fwf':
                self._load_yaml(path)
            case _:
                raise ValueError(f'Unsupported file extension: {path}')

    def save(self, path):
        match path.rsplit('.', 1)[-1]:
            case 'fwf':
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
