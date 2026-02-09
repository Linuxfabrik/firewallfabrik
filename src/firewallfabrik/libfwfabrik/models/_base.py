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
