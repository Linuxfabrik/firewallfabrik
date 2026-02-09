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

"""Group models (STI) and group_membership association table."""

from __future__ import annotations  # This is needed since SQLAlchemy does not support forward references yet

import typing
import uuid

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet


class Group(Base):
    """Base class for group objects (containers of references)."""

    __tablename__ = 'groups'

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
    parent_group_id: sqlalchemy.orm.Mapped[typing.Optional[uuid.UUID]] = (
        sqlalchemy.orm.mapped_column(
            sqlalchemy.Uuid,
            sqlalchemy.ForeignKey('groups.id'),
            nullable=True,
            default=None,
        )
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
    keywords: sqlalchemy.orm.Mapped[typing.Optional[set[str]]] = (
        sqlalchemy.orm.mapped_column(JSONEncodedSet, default=set)
    )
    data: sqlalchemy.orm.Mapped[typing.Optional[dict]] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )

    library: sqlalchemy.orm.Mapped['Library'] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='groups',
    )
    parent_group: sqlalchemy.orm.Mapped[typing.Optional[Group]] = (
        sqlalchemy.orm.relationship(
            'Group',
            remote_side='Group.id',
            back_populates='child_groups',
        )
    )
    child_groups: sqlalchemy.orm.Mapped[list[Group]] = (
        sqlalchemy.orm.relationship(
            'Group',
            back_populates='parent_group',
        )
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Group',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_groups_type', 'type'),
        sqlalchemy.Index('ix_groups_library_id', 'library_id'),
        sqlalchemy.Index('ix_groups_parent_group_id', 'parent_group_id'),
        sqlalchemy.Index('ix_groups_name', 'name'),
    )


class ObjectGroup(Group):
    """Group that holds references to address / host objects."""
    __mapper_args__ = {'polymorphic_identity': 'ObjectGroup'}


class ServiceGroup(Group):
    """Group that holds references to service objects."""
    __mapper_args__ = {'polymorphic_identity': 'ServiceGroup'}


class IntervalGroup(Group):
    """Group that holds references to interval (time) objects."""
    __mapper_args__ = {'polymorphic_identity': 'IntervalGroup'}


class MultiAddress(ObjectGroup):
    """Base for objects that resolve to multiple addresses at compile/run time."""
    __mapper_args__ = {'polymorphic_identity': 'MultiAddress'}


class AddressTable(MultiAddress):
    """Addresses loaded from an external table/file."""
    __mapper_args__ = {'polymorphic_identity': 'AddressTable'}


class AttachedNetworks(MultiAddress):
    """Networks attached to an interface."""
    __mapper_args__ = {'polymorphic_identity': 'AttachedNetworks'}


class DynamicGroup(MultiAddress):
    """Group whose membership is determined dynamically."""
    __mapper_args__ = {'polymorphic_identity': 'DynamicGroup'}


class DNSName(MultiAddress):
    """Object resolved via DNS at compile or run time."""
    __mapper_args__ = {'polymorphic_identity': 'DNSName'}


class ClusterGroup(ObjectGroup):
    """Base class for cluster interface groups."""
    __mapper_args__ = {'polymorphic_identity': 'ClusterGroup'}


class FailoverClusterGroup(ClusterGroup):
    """Cluster group for failover."""
    __mapper_args__ = {'polymorphic_identity': 'FailoverClusterGroup'}


class StateSyncClusterGroup(ClusterGroup):
    """Cluster group for state synchronisation."""
    __mapper_args__ = {'polymorphic_identity': 'StateSyncClusterGroup'}


group_membership = sqlalchemy.Table(
    'group_membership',
    Base.metadata,
    sqlalchemy.Column(
        'group_id',
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('groups.id'),
        primary_key=True,
    ),
    sqlalchemy.Column(
        'member_id',
        sqlalchemy.Uuid,
        primary_key=True,
    ),
    sqlalchemy.Index('ix_group_membership_group_id', 'group_id'),
)
