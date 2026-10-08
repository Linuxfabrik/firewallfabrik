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


STANDARD_LIBRARY_NAME = 'Standard'

# Tables that hold the Standard library's placeholder objects: the "Any"
# network, IP service and interval, and the "Dummy" network, IP service
# and interface.
_PLACEHOLDER_TABLES = frozenset({'addresses', 'interfaces', 'intervals', 'services'})

# Columns that put an object below something other than its library.
_PARENT_COLUMNS = ('device_id', 'group_id', 'interface_id', 'parent_interface_id')


def placeholder_kind(obj) -> str:
    """Return ``'Any'`` or ``'Dummy'`` for a Standard library placeholder.

    Firewall Builder recognises its placeholders by their fixed ids:
    ``RuleElement::isAny`` compares the reference with
    ``getAnyElementId()`` and ``RuleElement*::isDummy`` with
    ``DUMMY_ADDRESS_ID`` and its siblings (fwbuilder5 RuleElement.cpp:138,
    :198).  FirewallFabrik gives every object a new id on each load, so it
    asks where the object is instead: directly in the Standard library,
    in no folder and below no device or interface, which is where both
    Firewall Builder and ``standard.fwf`` keep them.  The name alone is
    not enough - a user object called "Any" or "Dummy" is an ordinary
    object.  Returns ``''`` for every other object.
    """
    name = getattr(obj, 'name', None)
    if name not in ('Any', 'Dummy'):
        return ''
    if getattr(type(obj), '__tablename__', None) not in _PLACEHOLDER_TABLES:
        return ''
    if any(getattr(obj, column, None) is not None for column in _PARENT_COLUMNS):
        return ''
    library = getattr(obj, 'library', None)
    if library is None or library.name != STANDARD_LIBRARY_NAME:
        return ''
    return name


def _is_standard_copy(library) -> bool:
    """A library File > Import Library brought along: "Standard-1", ..."""
    prefix = f'{STANDARD_LIBRARY_NAME}-'
    name = library.name or ''
    return name.startswith(prefix) and name[len(prefix) :].isdigit()


def redirect_placeholder_copies(session) -> int:
    """Point references to a copied Standard library's placeholders at the real ones.

    File > Import Library takes the other file's Standard library along as
    an editable copy under a free name ("Standard-1"), and the rules of the
    firewalls it brings name that copy's "Any" and "Dummy".  Firewall
    Builder gives the placeholders one fixed id in every file, so there an
    imported rule names the database's own "Any".  Here the copy's objects
    are no placeholders (:func:`placeholder_kind` asks for the Standard
    library), and a rule naming one would compile "any" as the network
    0.0.0.0/0, which the IPv6 pass then drops.  This restores the Firewall
    Builder reading for every reference, rule elements and group members
    alike.  Returns how many references were moved.
    """
    from ._addresses import Address
    from ._devices import Interface
    from ._groups import group_membership
    from ._rules import rule_elements
    from ._services import Interval, Service

    libraries = session.scalars(sqlalchemy.select(Library)).all()
    standard = next(
        (lib for lib in libraries if lib.name == STANDARD_LIBRARY_NAME), None
    )
    copies = [lib for lib in libraries if _is_standard_copy(lib)]
    if standard is None or not copies:
        return 0

    moved = 0
    for cls in (Address, Interface, Interval, Service):
        real = {}
        for obj in session.scalars(
            sqlalchemy.select(cls).where(cls.library_id == standard.id)
        ):
            kind = placeholder_kind(obj)
            if kind:
                real[(getattr(obj, 'type', cls.__name__), kind)] = obj.id
        for copy in copies:
            for obj in session.scalars(
                sqlalchemy.select(cls).where(cls.library_id == copy.id)
            ):
                if obj.name not in ('Any', 'Dummy'):
                    continue
                if any(getattr(obj, c, None) is not None for c in _PARENT_COLUMNS):
                    continue
                target = real.get((getattr(obj, 'type', cls.__name__), obj.name))
                if target is None:
                    continue
                moved += _redirect(session, rule_elements, 'target_id', obj.id, target)
                moved += _redirect(
                    session, group_membership, 'member_id', obj.id, target
                )
    return moved


def _redirect(session, table, column, old_id, new_id) -> int:
    """Move every reference in *table* from *old_id* to *new_id*.

    A container that holds both keeps one reference.
    """
    owner = 'rule_id' if column == 'target_id' else 'group_id'
    rows = session.execute(
        sqlalchemy.select(table).where(table.c[column] == old_id)
    ).all()
    for row in rows:
        same = [table.c[owner] == row._mapping[owner]]
        if 'slot' in table.c:
            same.append(table.c.slot == row._mapping['slot'])
        holds_new = session.execute(
            sqlalchemy.select(table.c[column]).where(*same, table.c[column] == new_id)
        ).first()
        where = [*same, table.c[column] == old_id]
        if holds_new is not None:
            session.execute(sqlalchemy.delete(table).where(*where))
        else:
            session.execute(
                sqlalchemy.update(table).where(*where).values({column: new_id})
            )
    return len(rows)


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
