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

"""Group models (STI) and group_membership association table."""

from __future__ import (
    annotations,  # This is needed since SQLAlchemy does not support forward references yet
)

import uuid
from typing import TYPE_CHECKING

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet

if TYPE_CHECKING:
    from ._addresses import Address
    from ._database import Library
    from ._devices import Host
    from ._services import Interval, Service


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
    parent_group_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = (
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

    library: sqlalchemy.orm.Mapped[Library] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='groups',
    )
    parent_group: sqlalchemy.orm.Mapped[Group | None] = sqlalchemy.orm.relationship(
        'Group',
        remote_side='Group.id',
        back_populates='child_groups',
    )
    child_groups: sqlalchemy.orm.Mapped[list[Group]] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='parent_group',
    )
    addresses: sqlalchemy.orm.Mapped[list[Address]] = sqlalchemy.orm.relationship(
        'Address',
        back_populates='group',
        primaryjoin='Group.id == foreign(Address.group_id)',
    )
    services: sqlalchemy.orm.Mapped[list[Service]] = sqlalchemy.orm.relationship(
        'Service',
        back_populates='group',
        primaryjoin='Group.id == foreign(Service.group_id)',
    )
    intervals: sqlalchemy.orm.Mapped[list[Interval]] = sqlalchemy.orm.relationship(
        'Interval',
        back_populates='group',
        primaryjoin='Group.id == foreign(Interval.group_id)',
    )
    devices: sqlalchemy.orm.Mapped[list[Host]] = sqlalchemy.orm.relationship(
        'Host',
        back_populates='group',
        primaryjoin='Group.id == foreign(Host.group_id)',
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
        sqlalchemy.UniqueConstraint(
            'parent_group_id', 'type', 'name', name='uq_groups_parent'
        ),
        # No root-level partial unique index here: Group has no device_id FK,
        # so cluster-internal groups (e.g. StateSyncClusterGroup "State Sync
        # Group") end up at the library root — one per cluster — with
        # identical (library_id, type, name) tuples.  A partial unique index
        # on (library_id, type, name) WHERE parent_group_id IS NULL would
        # reject this legitimate data.  The UniqueConstraint above is safe
        # because SQLite treats NULL parent_group_id values as distinct.
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

    #: The key the object's own source is stored under.  Firewall Builder
    #: writes it as an XML attribute (``AddressTable filename=``,
    #: ``DNSName dnsrec=``) and the `.fwb` reader copies every attribute it
    #: does not know by name into ``data``, so this is what an imported
    #: file carries and what the compilers have always read.
    SOURCE_KEY = 'source_name'

    def get_source_name(self) -> str:
        """Return the file or host name this object resolves from.

        Ports ``MultiAddress::getSourceName``.  The editors wrote the value
        under ``source_name`` for a while, which no compiler reads, so an
        object created or edited in FirewallFabrik resolved its own object
        name instead; that spelling is still accepted here so those files
        keep working.
        """
        data = self.data or {}
        return str(data.get(self.SOURCE_KEY) or data.get('source_name') or '')

    def set_source_name(self, value: str) -> dict:
        """Return *data* with the source set, cleared of the old spelling."""
        data = dict(self.data or {})
        if self.SOURCE_KEY != 'source_name':
            data.pop('source_name', None)
        data[self.SOURCE_KEY] = value
        return data


class AddressTable(MultiAddress):
    """Addresses loaded from an external table/file."""

    __mapper_args__ = {'polymorphic_identity': 'AddressTable'}

    SOURCE_KEY = 'filename'


def is_run_time_address_table(obj) -> bool:
    """Report whether *obj* is an AddressTable that is read on the firewall.

    A compile-time table is replaced by its addresses before the rule
    reaches a print rule; only a run-time one still carries the file.
    """
    return isinstance(obj, AddressTable) and bool((obj.data or {}).get('run_time'))


def get_address_table_source(at: AddressTable, fw=None) -> str:
    """Return the file an AddressTable is read from, as the script sees it.

    A file name may hold the token ``%DATADIR%``, which stands for the
    directory the data files live in.  For a table read *on the firewall*
    that is the firewall's own "Data directory" setting, because the path
    goes into the generated script and is opened there - not the directory
    of the machine that compiled it, which is what the compile-time
    resolution in ``Compiler._load_address_table`` uses.  fwbuilder makes
    the same split (AddressTable::getFilename: ``options->getStr(
    "data_dir")`` when ``isRunTime()``, ``FWObject::getDataDir()``
    otherwise).

    Without *fw* the token is left as it stands, which is what a caller
    that has no firewall at hand can say about it.
    """
    filename = at.get_source_name()
    if '%DATADIR%' not in filename or fw is None:
        return filename
    data_dir = str(fw.get_option('linux24_data_dir') or '').rstrip('/')
    return filename.replace('%DATADIR%', data_dir) if data_dir else filename


class AttachedNetworks(MultiAddress):
    """Networks attached to an interface."""

    __mapper_args__ = {'polymorphic_identity': 'AttachedNetworks'}


class DynamicGroup(MultiAddress):
    """Group whose membership is determined dynamically."""

    __mapper_args__ = {'polymorphic_identity': 'DynamicGroup'}


class DNSName(MultiAddress):
    """Object resolved via DNS at compile or run time."""

    __mapper_args__ = {'polymorphic_identity': 'DNSName'}

    SOURCE_KEY = 'dnsrec'


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
    sqlalchemy.Column(
        'position',
        sqlalchemy.Integer,
        default=0,
    ),
    sqlalchemy.Index('ix_group_membership_group_id', 'group_id'),
)
