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
from typing import TYPE_CHECKING, Any

import sqlalchemy
import sqlalchemy.orm

from firewallfabrik.core._options import option_bool, option_is_true

from ._base import Base
from ._types import JSONEncodedSet

if TYPE_CHECKING:
    from ._addresses import Address
    from ._database import Library
    from ._groups import Group
    from ._rules import RuleSet


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
    group: sqlalchemy.orm.Mapped[Group | None] = sqlalchemy.orm.relationship(
        'Group',
        back_populates='devices',
        primaryjoin='Group.id == foreign(Host.group_id)',
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
        sqlalchemy.Index('ix_devices_group_id', 'group_id'),
        sqlalchemy.Index('ix_devices_name', 'name'),
        sqlalchemy.UniqueConstraint(
            'group_id', 'type', 'name', name='uq_devices_group'
        ),
        sqlalchemy.Index(
            'uq_devices_orphan_lib',
            'library_id',
            'type',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('group_id IS NULL'),
        ),
    )

    # -- Compiler helper methods --

    _GET_OPTION_SENTINEL = object()

    def get_option(self, key: str, platform: str | None = None) -> Any:
        """Look up a value in the device options dict.

        Resolution order:

        1. Explicit value in ``self.options[key]`` (if present).
        2. YAML default from ``platforms/<platform>/defaults.yaml``
           or ``platforms/<os>/defaults.yaml``.

        *platform* names the schema to fall back to when it is not the
        one the object stores.  A firewall imported from a ``.fwb`` file
        says ``iptables``, because Firewall Builder has no other Linux
        platform, and compiling it with ``fwf-nft`` is an ordinary thing
        to do - so the driver names the platform it is compiling for and
        the nftables-only keys resolve.

        Raises ``KeyError`` if the key is unknown in both the stored
        options and all YAML schemas.  This catches typos in compiler
        code at the earliest possible moment.

        String ``"True"``/``"False"`` values are coerced to Python
        bools so that values loaded from XML work correctly, in the
        line-wrapped spelling a data file may carry as well
        (:func:`firewallfabrik.core._options.option_bool`).
        """
        _S = self._GET_OPTION_SENTINEL
        if self.options:
            val = self.options.get(key, _S)
            if val is not _S:
                coerced = option_bool(val, _S)
                return val if coerced is _S else coerced
        # Fall back to YAML platform / OS defaults.
        from firewallfabrik.platforms._defaults import get_option_default

        # get_option_default raises KeyError when the key is unknown.
        return get_option_default(platform or self.platform, self.host_os, key)

    # The key Firewall Builder stores the "MAC address matching" checkbox
    # under (`HostDialog.cpp:161`, read in `Compiler.cpp:485`).  It is not
    # part of any platform schema, so it does not go through
    # :meth:`get_option`, which would raise ``KeyError`` for it.
    _MAC_FILTER_KEY = 'use_mac_addr_filter'
    # The key the FirewallFabrik host editor wrote before it learnt the
    # one above.  Read so a file written by an older release keeps its
    # setting; never written.
    _LEGACY_MAC_FILTER_KEY = 'mac_filter_enabled'

    def matches_by_mac(self) -> bool:
        """Are this host's addresses matched together with its MAC address?"""
        for source, key in (
            (self.options, self._MAC_FILTER_KEY),
            (self.data, self._LEGACY_MAC_FILTER_KEY),
        ):
            value = (source or {}).get(key)
            if value is None:
                continue
            return option_is_true(value)
        return False

    def set_matches_by_mac(self, value: bool) -> None:
        """Store the "MAC address matching" setting where the compiler reads it."""
        options = dict(self.options or {})
        options[self._MAC_FILTER_KEY] = bool(value)
        self.options = options
        if (self.data or {}).get(self._LEGACY_MAC_FILTER_KEY) is not None:
            data = dict(self.data)
            del data[self._LEGACY_MAC_FILTER_KEY]
            self.data = data

    @property
    def platform(self) -> str:
        if self.data:
            return self.data.get('platform', '')
        return ''

    @property
    def host_os(self) -> str:
        if self.data:
            return self.data.get('host_OS', '')
        return ''

    @property
    def version(self) -> str:
        if self.data:
            return self.data.get('version', '')
        return ''


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
    device_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('devices.id'),
        nullable=True,
        default=None,
    )
    library_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = sqlalchemy.orm.mapped_column(
        sqlalchemy.Uuid,
        sqlalchemy.ForeignKey('libraries.id'),
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

    parent_interface_id: sqlalchemy.orm.Mapped[uuid.UUID | None] = (
        sqlalchemy.orm.mapped_column(
            sqlalchemy.Uuid,
            sqlalchemy.ForeignKey('interfaces.id'),
            nullable=True,
            default=None,
        )
    )

    device: sqlalchemy.orm.Mapped[Host | None] = sqlalchemy.orm.relationship(
        'Host',
        back_populates='interfaces',
    )
    library: sqlalchemy.orm.Mapped[Library | None] = sqlalchemy.orm.relationship(
        'Library',
        back_populates='interfaces',
    )
    parent_interface: sqlalchemy.orm.Mapped[Interface | None] = (
        sqlalchemy.orm.relationship(
            'Interface',
            remote_side='Interface.id',
            back_populates='sub_interfaces',
        )
    )
    sub_interfaces: sqlalchemy.orm.Mapped[list[Interface]] = (
        sqlalchemy.orm.relationship(
            'Interface',
            back_populates='parent_interface',
        )
    )
    addresses: sqlalchemy.orm.Mapped[list[Address]] = sqlalchemy.orm.relationship(
        'Address',
        back_populates='interface',
        primaryjoin='Interface.id == foreign(Address.interface_id)',
    )

    __table_args__ = (
        # Sub-interfaces: unique name within the same parent interface.
        # SQLite treats NULL parent_interface_id as distinct, so this only
        # constrains actual sub-interfaces.
        sqlalchemy.UniqueConstraint(
            'parent_interface_id', 'name', name='uq_interfaces_parent'
        ),
        # Top-level interfaces: unique (device_id, name) where no parent.
        sqlalchemy.Index(
            'uq_interfaces_device',
            'device_id',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('parent_interface_id IS NULL'),
        ),
        sqlalchemy.Index(
            'uq_interfaces_standalone_lib',
            'library_id',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('device_id IS NULL'),
        ),
    )

    # -- Compiler helper methods --

    def get_option(self, key: str, default: Any = None) -> Any:
        """Look up a value in the interface options dict."""
        if self.options:
            val = self.options.get(key, default)
            return option_bool(val, val)
        return default

    def is_loopback(self) -> bool:
        return self.name == 'lo'

    def is_dynamic(self) -> bool:
        return bool((self.data or {}).get('dyn', False))

    def is_unnumbered(self) -> bool:
        return bool((self.data or {}).get('unnum', False))

    def is_unprotected(self) -> bool:
        """Is this interface marked "unprotected"?

        Mirrors C++ ``Interface::isUnprotected()``.  The administrator
        says with it that no rules are to be generated for this
        interface, so anything that answers "every interface of the
        firewall" has to leave it out.
        """
        return bool((self.data or {}).get('unprotected', False))

    def is_regular(self) -> bool:
        return (
            not self.is_dynamic()
            and not self.is_unnumbered()
            and not self.is_bridge_port()
        )

    def _is_port_of(self, parent_type: str) -> bool:
        """Is this a plain port of a parent interface of *parent_type*?

        Mirrors C++ ``Interface::isBridgePort()`` / ``isSlave()``: neither
        Firewall Builder nor FirewallFabrik stores a flag on the port, the
        answer follows from the port's own type and its parent's.
        """
        if (self.get_option('type', '') or '') not in ('', 'ethernet'):
            return False
        parent = self.parent_interface
        return (
            parent is not None and (parent.get_option('type', '') or '') == parent_type
        )

    def is_bridge_port(self) -> bool:
        # An explicit option still wins, so a file that carries one keeps
        # working.
        if self.get_option('bridge_port', False):
            return True
        return self._is_port_of('bridge')

    def is_slave(self) -> bool:
        if self.get_option('slave', False):
            return True
        return self._is_port_of('bonding')
