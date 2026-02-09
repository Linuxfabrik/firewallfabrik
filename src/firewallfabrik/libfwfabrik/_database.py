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

# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.

# SPDX-License-Identifier: GPL-2.0-or-later

import contextlib

import sqlalchemy.orm
from sqlalchemy import create_engine

from ._xml_reader import XmlReader
from .models import Base, enable_sqlite_fks, group_membership, rule_elements


class DatabaseManager:
    def __init__(self, connection_string='sqlite:///:memory:'):
        self.engine = create_engine(connection_string, echo=False)
        self._session_factory = sqlalchemy.orm.sessionmaker(bind=self.engine)
        enable_sqlite_fks(self.engine)
        Base.metadata.create_all(self.engine)

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
        reader = XmlReader()
        result = reader.parse(path)
        with self.session() as session:
            session.add(result.database)
            session.flush()
            if result.memberships:
                session.execute(
                    group_membership.insert(),
                    result.memberships,
                )
            if result.rule_element_rows:
                session.execute(
                    rule_elements.insert(),
                    result.rule_element_rows,
                )
