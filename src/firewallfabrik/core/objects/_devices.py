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

"""Device models (STI): Host, Firewall, Cluster, and Interface."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

import uuid

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet


class Host(Base):
    """Host object (a device with interfaces)."""

    __tablename__ = 'devices'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    type: sqlalchemy.orm.Mapped[str] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String(50),
    )
    library_id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('libraries.id'),
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
    keywords: sqlalchemy.orm.Mapped[set[str] | None] = sqlalchemy.orm.mapped_column(
        JSONEncodedSet, default=set
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    options: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    management: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    id_mapping_for_duplicate: sqlalchemy.orm.Mapped[dict | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )

    library: sqlalchemy.orm.Mapped[Library] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='devices',
    )
    interfaces: sqlalchemy.orm.Mapped[list[Interface]] = sqlalchemy.orm.relationship(
        'Interface',
        back_populates='device',
    )
    rule_sets: sqlalchemy.orm.Mapped[list[RuleSet]] = sqlalchemy.orm.relationship(
        'RuleSet',
        back_populates='device',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Host',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_devices_type', 'type'),
        sqlalchemy.Index('ix_devices_library_id', 'library_id'),
        sqlalchemy.Index('ix_devices_name', 'name'),
    )


class Firewall(Host):
    """Firewall object."""

    __mapper_args__ = {'polymorphic_identity': 'Firewall'}


class Cluster(Firewall):
    """High-availability cluster of firewalls."""

    __mapper_args__ = {'polymorphic_identity': 'Cluster'}


class Interface(Base):
    """Network interface object."""

    __tablename__ = 'interfaces'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
    )
    device_id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('devices.id'),
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
    keywords: sqlalchemy.orm.Mapped[set[str] | None] = sqlalchemy.orm.mapped_column(
        JSONEncodedSet, default=set
    )
    data: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    options: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    bcast_bits: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer,
        default=0,
    )
    ostatus: sqlalchemy.orm.Mapped[bool] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Boolean,
        default=False,
    )
    snmp_type: sqlalchemy.orm.Mapped[int] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer,
        default=0,
    )

    device: sqlalchemy.orm.Mapped[Host] = sqlalchemy.orm.relationship(
        'Host',
        back_populates='interfaces',
    )
    addresses: sqlalchemy.orm.Mapped[list[Address]] = sqlalchemy.orm.relationship(
        'Address',
        back_populates='interface',
        primaryjoin='Interface.id == foreign(Address.interface_id)',
    )
