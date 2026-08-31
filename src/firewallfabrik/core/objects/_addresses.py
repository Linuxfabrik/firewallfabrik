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

import ipaddress
import re
import uuid
from typing import TYPE_CHECKING

import sqlalchemy
import sqlalchemy.orm

from ._base import Base
from ._types import JSONEncodedSet

if TYPE_CHECKING:
    from ._database import Library
    from ._devices import Interface
    from ._groups import Group


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
        sqlalchemy.UniqueConstraint(
            'group_id', 'type', 'name', name='uq_addresses_group'
        ),
        sqlalchemy.UniqueConstraint(
            'interface_id', 'type', 'name', name='uq_addresses_interface'
        ),
        sqlalchemy.Index(
            'uq_addresses_orphan_lib',
            'library_id',
            'type',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('group_id IS NULL AND interface_id IS NULL'),
        ),
    )

    # -- Compiler helper methods --

    def get_address(self) -> str:
        """Return the address string from inet_addr_mask JSON."""
        if self.inet_addr_mask:
            return self.inet_addr_mask.get('address', '')
        return ''

    def get_netmask(self) -> str:
        """Return the netmask string from inet_addr_mask JSON."""
        if self.inet_addr_mask:
            return self.inet_addr_mask.get('netmask', '')
        return ''

    def get_start_address(self) -> str:
        """Return start address string (for AddressRange)."""
        if self.start_address:
            return self.start_address.get('address', '')
        return ''

    def get_end_address(self) -> str:
        """Return end address string (for AddressRange)."""
        if self.end_address:
            return self.end_address.get('address', '')
        return ''

    def _family_address(self) -> str:
        """Return a representative address string for family detection.

        AddressRange stores its endpoints in ``start_address`` /
        ``end_address`` rather than ``inet_addr_mask``, so ``get_address()``
        is empty for ranges.  Fall back to the range start so family
        predicates work for every address subtype.
        """
        return self.get_address() or self.get_start_address()

    def is_v4(self) -> bool:
        """True if this address is an IPv4-family address."""
        if isinstance(self, (IPv4, Network)):
            return True
        # For base Address type, check actual address value
        addr_str = self._family_address()
        if addr_str:
            try:
                return isinstance(ipaddress.ip_address(addr_str), ipaddress.IPv4Address)
            except ValueError:
                pass
        return False

    def is_v6(self) -> bool:
        """True if this address is an IPv6-family address."""
        if isinstance(self, (IPv6, NetworkIPv6)):
            return True
        # For base Address type, check actual address value
        addr_str = self._family_address()
        if addr_str:
            try:
                return isinstance(ipaddress.ip_address(addr_str), ipaddress.IPv6Address)
            except ValueError:
                pass
        return False

    def is_any(self) -> bool:
        """True if this represents the 'any' address (0.0.0.0/0 or ::/0).

        The netmask goes through :func:`netmask_prefix_length`, not through
        ``ipaddress.ip_address``: Firewall Builder writes an IPv6 netmask as
        a bit length (``NetworkIPv6::toXML``), and reading ``"0"`` as an
        address raises, which answered "not any" for every ``::/0`` there
        is.
        """
        addr = self.get_address()
        mask = self.get_netmask()
        if not addr:
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if int(ip) != 0:
            return False
        if not mask:
            return True
        return netmask_prefix_length(addr, mask) == 0

    def is_broadcast(self) -> bool:
        """True if this is a broadcast address (255.255.255.255)."""
        return self.get_address() == '255.255.255.255'

    def is_multicast(self) -> bool:
        """True if this is a multicast address (224.0.0.0/4 or ff00::/8).

        Returns ``False`` for objects without a single address (e.g. an
        AddressRange whose address lives in ``start_address``/
        ``end_address`` rather than in ``inet_addr_mask``).
        """
        addr = self.get_address()
        if not addr:
            return False
        try:
            return ipaddress.ip_address(addr).is_multicast
        except ValueError:
            return False

    def count_inet_addresses(self, skip_loopback: bool = True) -> int:
        """Return how many ``-s`` / ``-d`` arguments this object stands for.

        Ports ``Address::countInetAddresses``, which answers **0** by
        default and is overridden to 1 by IPv4, IPv6, Network and
        NetworkIPv6 alone.  An address range, a DNS name, an address
        table and a MAC address therefore answer 0 here, which is what
        keeps them out of the single-``!`` negation: each of them is
        written out as several arguments, and one ``!`` per argument
        negates each of them separately rather than the object.
        """
        return 0


class IPv4(Address):
    """IPv4 address object."""

    __mapper_args__ = {'polymorphic_identity': 'IPv4'}

    def count_inet_addresses(self, skip_loopback: bool = True) -> int:
        return 1


class IPv6(Address):
    """IPv6 address object."""

    __mapper_args__ = {'polymorphic_identity': 'IPv6'}

    def count_inet_addresses(self, skip_loopback: bool = True) -> int:
        return 1


class Network(Address):
    """IPv4 network object."""

    __mapper_args__ = {'polymorphic_identity': 'Network'}

    def count_inet_addresses(self, skip_loopback: bool = True) -> int:
        return 1


class NetworkIPv6(Address):
    """IPv6 network object."""

    __mapper_args__ = {'polymorphic_identity': 'NetworkIPv6'}

    def count_inet_addresses(self, skip_loopback: bool = True) -> int:
        return 1


class PhysAddress(Address):
    """Physical (MAC) address object."""

    __mapper_args__ = {'polymorphic_identity': 'PhysAddress'}


class AddressRange(Address):
    """An IP address range defined by start and end addresses."""

    __mapper_args__ = {'polymorphic_identity': 'AddressRange'}


class MultiAddressRunTime(Address):
    """Run-time variant of MultiAddress, used internally by compilers."""

    __mapper_args__ = {'polymorphic_identity': 'MultiAddressRunTime'}


# Six groups of one or two hex digits, separated by a colon or by a dash.
def max_prefix_length(address: str) -> int | None:
    """Return the host-mask length of *address*'s family, or ``None``.

    ``InetAddr::addressLengthBits()``: 32 for IPv4, 128 for IPv6.  What a
    host mask is depends on the family, and testing a prefix against 32
    alone strips the prefix off an IPv6 /32 - the size of a provider
    allocation - and turns the match into a single host.
    """
    try:
        return ipaddress.ip_address(address.strip()).max_prefixlen
    except (AttributeError, ValueError):
        return None


def netmask_prefix_length(address: str, netmask: str) -> int | None:
    """Return the prefix length *netmask* stands for, or ``None``.

    A netmask reaches the compilers in three spellings and they all mean
    the same thing.  Firewall Builder writes a bit length for IPv6
    (``NetworkIPv6::toXML``) and a dotted mask for IPv4
    (``Network::setNetmask``); a data file older than either, or written
    by another tool, carries a bit length for IPv4 as well; and the
    compilers themselves build an all-ones IPv6 mask in address form
    where ``InetAddr::getAllOnes()`` is what fwbuilder uses.

    ``ipaddress.ip_network()`` takes only two of the three, which is why
    this exists: it is the reader that answers what the netmask *means*,
    next to the print rules, which answer what the compilers currently
    *do* with it.  Where the two disagree, a rule matches something other
    than what it names, and that is what the verify pass reports.

    ``None`` means the value is no netmask at all.
    """
    if netmask is None:
        return None
    text = str(netmask).strip()
    if not text:
        return None
    try:
        family = ipaddress.ip_address(address.strip())
    except (AttributeError, ValueError):
        return None
    max_prefix = family.max_prefixlen

    if text.isascii() and text.isdigit():
        prefix = int(text)
        return prefix if prefix <= max_prefix else None

    # The address form, for either family.  Only a mask of ones followed
    # by zeros is one: InetAddr::isValidV4Netmask() refuses the rest, and
    # the inverted spelling 0.255.255.255 is a host mask to ip_network()
    # while fwbuilder calls it zeroes in the middle.
    try:
        bits = int(ipaddress.ip_address(text))
    except ValueError:
        return None
    if len(ipaddress.ip_address(text).packed) * 8 != max_prefix:
        return None
    prefix = 0
    top = 1 << (max_prefix - 1)
    while bits & top:
        prefix += 1
        bits = (bits << 1) & ((1 << max_prefix) - 1)
    return prefix if bits == 0 else None


# The colon form is what both packet filters take.  The dash form is the
# other common spelling of the same address and only nftables reads it,
# which is why it is recognised here and written back out as colons.
_MAC_ADDRESS_RE = re.compile(
    r'[0-9A-Fa-f]{1,2}([:-])(?:[0-9A-Fa-f]{1,2}\1){4}[0-9A-Fa-f]{1,2}'
)


def normalize_mac_address(value: str) -> str:
    """Return *value* as a MAC both back ends take, or an empty string.

    A physAddress carries its MAC as free text from its editor - Firewall
    Builder does not check it either - and the value reaches both back ends
    unchecked: ``-m mac --mac-source`` on iptables, ``ether saddr`` /
    ``ether daddr`` on nftables.  Neither takes a word.  iptables answers
    "Invalid MAC address specified." and stops the activation script with
    every built-in policy already set to DROP; nftables answers a syntax
    error and refuses the **whole** ruleset, so the firewall keeps whatever
    it was running.  And on iptables the value goes into the generated
    script as a bare shell word, where a semicolon starts a second command
    - as root, at exactly that moment.  The ToS value, the packet mark and
    the rate-limit table name next door are guarded for the same reason.

    The two tools also disagree on one spelling, which makes a data file
    carrying it compile on one platform and cost the whole ruleset on the
    other: nftables reads ``aa-bb-cc-dd-ee-ff`` and prints it back with
    colons, iptables refuses it (``xtopt_parse_ethermac`` in
    libxtables/xtoptions.c splits on ``:`` alone).  Both spellings mean the
    same address, so this answers with the colon form for either.

    Everything else is refused.  iptables is the more permissive of the two
    - ``strtoul`` accepts an empty group and a leading sign, so ``:::::``
    and ``-1:2:3:4:5:6`` load there - but nftables' scanner does not
    (src/scanner.l, ``macaddr``), and a value only one platform takes is
    the portability bug this is here to stop.  Verified against iptables
    1.8.11 and nft 1.1.6.
    """
    if not value:
        return ''
    text = value.strip()
    match = _MAC_ADDRESS_RE.fullmatch(text)
    if match is None:
        return ''
    return ':'.join(f'{int(part, 16):02x}' for part in text.split(match.group(1)))


def range_to_cidr(start: str, end: str) -> str | None:
    """Return the ``addr/prefixlen`` CIDR string when *start*..*end* is
    an exact CIDR block, else ``None``.

    Example: ``range_to_cidr('192.168.4.0', '192.168.4.255')`` returns
    ``'192.168.4.0/24'``; ``range_to_cidr('192.168.4.10',
    '192.168.4.50')`` returns ``None``.  Both addresses must share the
    same IP version.  Invalid input returns ``None``.
    """
    if not start or not end:
        return None
    try:
        start_addr = ipaddress.ip_address(start)
        end_addr = ipaddress.ip_address(end)
    except ValueError:
        return None
    if start_addr.version != end_addr.version:
        return None
    if int(start_addr) > int(end_addr):
        return None
    networks = list(ipaddress.summarize_address_range(start_addr, end_addr))
    if len(networks) != 1:
        return None
    return str(networks[0])
