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

"""FWObjectDatabase and Library models."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

import uuid
from typing import TYPE_CHECKING

import sqlalchemy
import sqlalchemy.orm

from ._base import Base

if TYPE_CHECKING:
    from ._addresses import Address
    from ._devices import Host, Interface
    from ._groups import Group
    from ._services import Interval, Service


class FWObjectDatabase(Base):
    """Root of the object tree / database."""

    __tablename__ = 'fw_databases'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    last_modified: sqlalchemy.orm.Mapped[float] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Float,
        default=0.0,
    )
    data_file: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    predictable_id_tracker: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer,
        default=0,
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )

    libraries: sqlalchemy.orm.Mapped[list[Library]] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='database',
    )


class Library(Base):
    """A library is a top-level container directly under the database."""

    __tablename__ = 'libraries'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    database_id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('fw_databases.id'),
        nullable=False,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    ro: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )

    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            'database_id', 'name', name='uq_libraries_database'
        ),
    )

    database: sqlalchemy.orm.Mapped[FWObjectDatabase] = sqlalchemy.orm.relationship(
        'FWObjectDatabase',
        back_populates='libraries',
    )
    groups: sqlalchemy.orm.Mapped[list[Group]] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='library',
    )
    devices: sqlalchemy.orm.Mapped[list[Host]] = sqlalchemy.orm.relationship(
        'Host',
        back_populates='library',
    )
    services: sqlalchemy.orm.Mapped[list[Service]] = sqlalchemy.orm.relationship(
        'Service',
        back_populates='library',
    )
    intervals: sqlalchemy.orm.Mapped[list[Interval]] = sqlalchemy.orm.relationship(
        'Interval',
        back_populates='library',
    )
    interfaces: sqlalchemy.orm.Mapped[list[Interface]] = sqlalchemy.orm.relationship(
        'Interface',
        back_populates='library',
    )
    addresses: sqlalchemy.orm.Mapped[list[Address]] = sqlalchemy.orm.relationship(
        'Address',
        back_populates='library',
        primaryjoin='Library.id == foreign(Address.library_id)',
    )
