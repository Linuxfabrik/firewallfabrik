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

"""Address models (STI)."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

import uuid

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet


class Address(Base):
    """Base class for all objects that have an IP address."""

    __tablename__ = 'addresses'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    type: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String(50),
    )
    library_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('libraries.id'),
        nullable=True,
        default=None,
    )
    interface_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = (
        sqlalchemy.orm.mapped_column(
            sqlalchemy.Uuid,
            sqlalchemy.ForeignKey('interfaces.id'),
            nullable=True,
            default=None,
        )
    )
    group_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('groups.id'),
        nullable=True,
        default=None,
    )
    name: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String,
        default='',
    )
    comment: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Text,
        default='',
    )
    keywords: sqlalchemy.orm.Mapped[set[str] | None] = sqlalchemy.orm.mapped_column(
        JSONEncodedSet, default=set
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    inet_addr_mask: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    start_address: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    end_address: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    subst_type_name: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    source_name: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    run_time: sqlalchemy.orm.Mapped[bool | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean, nullable=True, default=None
    )

    library: sqlalchemy.orm.Mapped[Library | None] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='addresses',
    )
    interface: sqlalchemy.orm.Mapped[Interface | None] = sqlalchemy.orm.relationship(
        'Interface',
        back_populates='addresses',
    )
    group: sqlalchemy.orm.Mapped[Group | None] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='addresses',
        primaryjoin='Group.id == foreign(Address.group_id)',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Address',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_addresses_type', 'type'),
        sqlalchemy.Index('ix_addresses_library_id', 'library_id'),
        sqlalchemy.Index('ix_addresses_interface_id', 'interface_id'),
        sqlalchemy.Index('ix_addresses_group_id', 'group_id'),
        sqlalchemy.Index('ix_addresses_name', 'name'),
    )


class IPv4(Address):
    """IPv4 address object."""

    __mapper_args__ = {'polymorphic_identity': 'IPv4'}


class IPv6(Address):
    """IPv6 address object."""

    __mapper_args__ = {'polymorphic_identity': 'IPv6'}


class Network(Address):
    """IPv4 network object."""

    __mapper_args__ = {'polymorphic_identity': 'Network'}


class NetworkIPv6(Address):
    """IPv6 network object."""

    __mapper_args__ = {'polymorphic_identity': 'NetworkIPv6'}


class PhysAddress(Address):
    """Physical (MAC) address object."""

    __mapper_args__ = {'polymorphic_identity': 'PhysAddress'}


class AddressRange(Address):
    """An IP address range defined by start and end addresses."""

    __mapper_args__ = {'polymorphic_identity': 'AddressRange'}


class MultiAddressRunTime(Address):
    """Run-time variant of MultiAddress, used internally by compilers."""

    __mapper_args__ = {'polymorphic_identity': 'MultiAddressRunTime'}
