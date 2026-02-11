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

"""Service models (STI) and Interval."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

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
    src_range_start: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    src_range_end: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    dst_range_start: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    dst_range_end: sqlalchemy.orm.Mapped[int | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Integer, nullable=True, default=None
    )
    tcp_flags: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    tcp_flags_masks: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    named_protocols: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    codes: sqlalchemy.orm.Mapped[dict | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON, nullable=True, default=None
    )
    protocol: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )
    custom_address_family: sqlalchemy.orm.Mapped[int | None] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Integer, nullable=True, default=None)
    )
    userid: sqlalchemy.orm.Mapped[str | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.String, nullable=True, default=None
    )

    library: sqlalchemy.orm.Mapped[Library] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='services',
    )
    group: sqlalchemy.orm.Mapped[Group | None] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='services',
        primaryjoin='Group.id == foreign(Service.group_id)',
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Service',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_services_type', 'type'),
        sqlalchemy.Index('ix_services_library_id', 'library_id'),
        sqlalchemy.Index('ix_services_group_id', 'group_id'),
        sqlalchemy.Index('ix_services_name', 'name'),
    )

    # -- Compiler helper methods --

    PROTOCOL_MAP = {
        'TCPService': ('tcp', 6),
        'UDPService': ('udp', 17),
        'ICMPService': ('icmp', 1),
        'ICMP6Service': ('ipv6-icmp', 58),
    }

    def get_protocol_name(self) -> str:
        """Return the protocol name string for this service type."""
        if isinstance(self, IPService) and self.protocol:
            return self.protocol
        entry = self.PROTOCOL_MAP.get(self.type)
        if entry:
            return entry[0]
        return ''

    def get_protocol_number(self) -> int:
        """Return the IP protocol number for this service type."""
        if isinstance(self, IPService) and self.protocol:
            try:
                return int(self.protocol)
            except ValueError:
                pass
        entry = self.PROTOCOL_MAP.get(self.type)
        if entry:
            return entry[1]
        return -1

    def is_any(self) -> bool:
        """True if this service matches any protocol/port."""
        if isinstance(self, IPService):
            return not self.protocol or self.protocol == '0'
        if isinstance(self, (TCPService, UDPService)):
            return (
                (self.src_range_start or 0) == 0
                and (self.src_range_end or 0) == 0
                and (self.dst_range_start or 0) == 0
                and (self.dst_range_end or 0) == 0
            )
        return False


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

    library: sqlalchemy.orm.Mapped[Library] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='intervals',
    )
    group: sqlalchemy.orm.Mapped[Group | None] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='intervals',
        primaryjoin='Group.id == foreign(Interval.group_id)',
    )

    __table_args__ = (
        sqlalchemy.Index('ix_intervals_library_id', 'library_id'),
        sqlalchemy.Index('ix_intervals_group_id', 'group_id'),
        sqlalchemy.Index('ix_intervals_name', 'name'),
    )
