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

"""Service models (STI) and Interval."""

from __future__ import annotations  # This is needed since SQLAlchemy does not support forward references yet

import typing
import uuid

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet


class Service(Base):
    """Base class for all service objects."""

    __tablename__ = 'services'

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
    keywords: sqlalchemy.orm.Mapped[typing.Optional[set[str]]] = (
        sqlalchemy.orm.mapped_column(JSONEncodedSet, default=set)
    )
    data: sqlalchemy.orm.Mapped[typing.Optional[dict]] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    src_range_start: sqlalchemy.orm.Mapped[typing.Optional[int]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, nullable=True, default=None)
    )
    src_range_end: sqlalchemy.orm.Mapped[typing.Optional[int]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, nullable=True, default=None)
    )
    dst_range_start: sqlalchemy.orm.Mapped[typing.Optional[int]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, nullable=True, default=None)
    )
    dst_range_end: sqlalchemy.orm.Mapped[typing.Optional[int]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, nullable=True, default=None)
    )
    tcp_flags: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    tcp_flags_masks: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    named_protocols: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    codes: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    protocol: sqlalchemy.orm.Mapped[typing.Optional[str]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, nullable=True, default=None)
    )
    custom_address_family: sqlalchemy.orm.Mapped[typing.Optional[int]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, nullable=True, default=None)
    )
    userid: sqlalchemy.orm.Mapped[typing.Optional[str]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, nullable=True, default=None)
    )

    library: sqlalchemy.orm.Mapped['Library'] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='services',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Service',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_services_type', 'type'),
        sqlalchemy.Index('ix_services_library_id', 'library_id'),
        sqlalchemy.Index('ix_services_name', 'name'),
    )


class TCPUDPService(Service):
    """Base for TCP and UDP services, carrying port ranges."""
    __mapper_args__ = {'polymorphic_identity': 'TCPUDPService'}


class TCPService(TCPUDPService):
    """TCP service with optional flag inspection."""
    __mapper_args__ = {'polymorphic_identity': 'TCPService'}


class UDPService(TCPUDPService):
    """UDP service."""
    __mapper_args__ = {'polymorphic_identity': 'UDPService'}


class ICMPService(Service):
    """ICMPv4 service."""
    __mapper_args__ = {'polymorphic_identity': 'ICMPService'}


class ICMP6Service(ICMPService):
    """ICMPv6 service."""
    __mapper_args__ = {'polymorphic_identity': 'ICMP6Service'}


class IPService(Service):
    """Generic IP protocol service."""
    __mapper_args__ = {'polymorphic_identity': 'IPService'}


class CustomService(Service):
    """Platform-specific custom service code."""
    __mapper_args__ = {'polymorphic_identity': 'CustomService'}


class UserService(Service):
    """Service matching a specific user identity."""
    __mapper_args__ = {'polymorphic_identity': 'UserService'}


class TagService(Service):
    """Service used for packet tagging."""
    __mapper_args__ = {'polymorphic_identity': 'TagService'}


class Interval(Base):
    """Time interval used in rule scheduling."""

    __tablename__ = 'intervals'

    id: sqlalchemy.orm.Mapped[uuid.UUID] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        primary_key=True,
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
    keywords: sqlalchemy.orm.Mapped[typing.Optional[set[str]]] = (
        sqlalchemy.orm.mapped_column(JSONEncodedSet, default=set)
    )
    data: sqlalchemy.orm.Mapped[typing.Optional[dict]] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )

    library: sqlalchemy.orm.Mapped['Library'] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='intervals',
    )
