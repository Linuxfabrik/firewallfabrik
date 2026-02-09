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

"""Declarative base and SQLite FK helper."""

from __future__ import annotations  # This is needed since SQLAlchemy does not support forward references yet

import sqlalchemy
import sqlalchemy.event
import sqlalchemy.orm


class Base(sqlalchemy.orm.DeclarativeBase):
    pass


def enable_sqlite_fks(engine: sqlalchemy.engine.Engine) -> None:
    """Enable foreign key enforcement for SQLite connections."""

    @sqlalchemy.event.listens_for(engine, 'connect')
    def _set_sqlite_pragma(
            dbapi_connection: object,
            connection_record: object,
    ) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[union-attr]
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()
