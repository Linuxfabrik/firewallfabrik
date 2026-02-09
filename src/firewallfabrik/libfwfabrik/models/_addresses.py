"""Address models (STI)."""

from __future__ import annotations  # This is needed since SQLAlchemy does not support forward references yet

import typing
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
    library_id: sqlalchemy.orm.Mapped[typing.Optional[uuid.UUID]] = (
        sqlalchemy.orm.mapped_column(
            sqlalchemy.Uuid,
            sqlalchemy.ForeignKey('libraries.id'),
            nullable=True,
            default=None,
        )
    )
    interface_id: sqlalchemy.orm.Mapped[typing.Optional[uuid.UUID]] = (
        sqlalchemy.orm.mapped_column(
            sqlalchemy.Uuid,
            sqlalchemy.ForeignKey('interfaces.id'),
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
    keywords: sqlalchemy.orm.Mapped[typing.Optional[set[str]]] = (
        sqlalchemy.orm.mapped_column(JSONEncodedSet, default=set)
    )
    data: sqlalchemy.orm.Mapped[typing.Optional[dict]] = sqlalchemy.orm.mapped_column(
        sqlalchemy.JSON,
        default=dict,
    )
    inet_addr_mask: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    start_address: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    end_address: sqlalchemy.orm.Mapped[typing.Optional[dict]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.JSON, nullable=True, default=None)
    )
    subst_type_name: sqlalchemy.orm.Mapped[typing.Optional[str]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, nullable=True, default=None)
    )
    source_name: sqlalchemy.orm.Mapped[typing.Optional[str]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.String, nullable=True, default=None)
    )
    run_time: sqlalchemy.orm.Mapped[typing.Optional[bool]] = (
        sqlalchemy.orm.mapped_column(sqlalchemy.Boolean, nullable=True, default=None)
    )

    library: sqlalchemy.orm.Mapped[typing.Optional['Library']] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='addresses',
    )
    interface: sqlalchemy.orm.Mapped[typing.Optional['Interface']] = (
        sqlalchemy.orm.relationship(
            'Interface',
            back_populates='addresses',
        )
    )

    __mapper_args__ = {
        'polymorphic_on': 'type',
        'polymorphic_identity': 'Address',
    }

    __table_args__ = (
        sqlalchemy.Index('ix_addresses_type', 'type'),
        sqlalchemy.Index('ix_addresses_library_id', 'library_id'),
        sqlalchemy.Index('ix_addresses_interface_id', 'interface_id'),
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
