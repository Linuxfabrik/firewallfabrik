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

import re
import uuid
from typing import TYPE_CHECKING, ClassVar

import sqlalchemy
import sqlalchemy.orm

from firewallfabrik.core._options import option_is_true

from ._base import Base
from ._types import JSONEncodedSet

if TYPE_CHECKING:
    from ._database import Library
    from ._groups import Group


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
        sqlalchemy.UniqueConstraint(
            'group_id', 'type', 'name', name='uq_services_group'
        ),
        sqlalchemy.Index(
            'uq_services_orphan_lib',
            'library_id',
            'type',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('group_id IS NULL'),
        ),
    )

    # -- Compiler helper methods --

    PROTOCOL_MAP = {
        'TCPService': ('tcp', 6),
        'UDPService': ('udp', 17),
        'ICMPService': ('icmp', 1),
        'ICMP6Service': ('ipv6-icmp', 58),
    }

    def get_protocol_name(self) -> str:
        """Return the protocol name string for this service type.

        A CustomService carries its protocol in the same attribute as an
        IPService, so both are resolved the same way.
        """
        if isinstance(self, (CustomService, IPService)):
            proto = self._ipservice_protocol_str()
            if proto:
                return proto
        entry = self.PROTOCOL_MAP.get(self.type)
        if entry:
            return entry[0]
        return ''

    def _ipservice_protocol_str(self) -> str:
        """Return the protocol string for an IPService.

        Checks ``self.protocol`` first (set for CustomService and explicit
        YAML ``protocol:`` fields), then falls back to
        ``named_protocols['protocol_num']`` which is the standard storage
        for IPService objects imported from both .fwb and .fwf files.
        """
        if self.protocol:
            return self.protocol
        if self.named_protocols:
            pnum = self.named_protocols.get('protocol_num')
            if pnum is not None:
                return str(pnum)
        return ''

    def get_protocol_number(self) -> int:
        """Return the IP protocol number for this service type."""
        if isinstance(self, IPService):
            proto = self._ipservice_protocol_str()
            if proto:
                try:
                    return int(proto)
                except ValueError:
                    pass
        entry = self.PROTOCOL_MAP.get(self.type)
        if entry:
            return entry[1]
        return -1

    def is_any(self) -> bool:
        """True if this service matches any protocol/port."""
        if isinstance(self, IPService):
            proto = self._ipservice_protocol_str()
            return not proto or proto == '0'
        if isinstance(self, (TCPService, UDPService)):
            if (
                (self.src_range_start or 0) != 0
                or (self.src_range_end or 0) != 0
                or (self.dst_range_start or 0) != 0
                or (self.dst_range_end or 0) != 0
            ):
                return False
            # A TCP service that inspects flags or requires the "established"
            # option is no longer "any TCP" — it matches a specific subset.
            if isinstance(self, TCPService):
                masks = self.tcp_flags_masks or {}
                if any(masks.values()):
                    return False
                established = (self.data or {}).get('established', False)
                if option_is_true(established):
                    return False
            return True
        return False


class TCPUDPService(Service):
    """Base for TCP and UDP services, carrying port ranges."""

    __mapper_args__ = {'polymorphic_identity': 'TCPUDPService'}


class TCPService(TCPUDPService):
    """TCP service with optional flag inspection."""

    __mapper_args__ = {'polymorphic_identity': 'TCPService'}

    # The order fwbuilder writes the flags in
    # (PolicyCompiler_PrintRule::_printTCPFlags).
    TCP_FLAG_ORDER: ClassVar[tuple[str, ...]] = (
        'urg',
        'ack',
        'psh',
        'rst',
        'syn',
        'fin',
    )

    def tcp_flag_match(self) -> tuple[list[str], list[str]]:
        """Return the flags to inspect and the ones that must be set.

        Ports fwbuilder's ``PolicyCompiler_ipt::PrintRule::_printTCPFlags``,
        including its one special case: a service that inspects all six
        flags and wants only SYN is a connection request, and fwbuilder
        narrows the inspected set to SYN, RST and ACK for it.  Inspecting
        all six instead would also require FIN, PSH and URG to be clear,
        which is a different match.  Both back ends have to agree on this,
        so the decision lives here rather than in one of the print rules.

        Returns ``([], [])`` for a service that inspects nothing.
        """
        masks = self.tcp_flags_masks or {}
        flags = self.tcp_flags or {}
        mask_names = [f for f in self.TCP_FLAG_ORDER if masks.get(f)]
        if not mask_names:
            return ([], [])
        comp_names = [f for f in self.TCP_FLAG_ORDER if flags.get(f)]
        if len(mask_names) == len(self.TCP_FLAG_ORDER) and comp_names == ['syn']:
            # fwbuilder spells this one out in its own order.
            return (['syn', 'rst', 'ack'], comp_names)
        return (mask_names, comp_names)


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


# Symbolic DiffServ code-point class names understood by both the iptables
# `--dscp-class` option and nftables' `dscp` matcher (RFC 2474 / RFC 2597).
# Names outside this set are not valid classes; both back ends reject them.
VALID_DSCP_CLASSES = frozenset(
    {
        'af11', 'af12', 'af13',
        'af21', 'af22', 'af23',
        'af31', 'af32', 'af33',
        'af41', 'af42', 'af43',
        'be',
        'cs0', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7',
        'ef',
    }
)  # fmt: skip

# A DiffServ code point occupies the upper six bits of the traffic class
# byte, so it counts from 0 to 63.  iptables bounds its --dscp argument by
# XT_DSCP_MAX (netfilter include/linux/netfilter/xt_dscp.h) and nftables
# rejects anything above 63 as well.
MAX_DSCP = 0x3F


def is_valid_dscp(value: str) -> bool:
    """Return True if ``value`` is a usable DSCP match value.

    Accepts a code point in range (decimal or ``0x`` hex) or one of the
    symbolic DiffServ class names both back ends understand.  An unknown
    class name (for example ``AF4``, which is missing its drop-precedence
    digit) is rejected, and so is a number outside 0-63 -- the common way
    to write EF as the whole traffic class byte, ``184`` or ``0xb8``,
    lands there.  The compiler can then report the value instead of
    emitting an unloadable rule.
    """
    if not value:
        return False
    normalized = value.strip().lower()
    if normalized in VALID_DSCP_CLASSES:
        return True
    code_point = _strtoul(normalized)
    return code_point is not None and code_point <= MAX_DSCP


def _strtoul(text: str) -> int | None:
    """Read a number the way C's ``strtoul(s, NULL, 0)`` reads it.

    netfilter parses these values with base 0, so ``0x`` is hex and a
    leading zero is octal.  Python's ``int(s, 0)`` agrees about hex and
    refuses the octal spelling outright ("invalid literal"), so ``020``
    would be reported as unusable although both tools take it as 16.
    """
    value = text.strip()
    if not value or value.startswith(('-', '+')):
        # netfilter's callers all bound the value at zero from below, and a
        # sign is not part of any spelling they accept.
        return None
    try:
        if value.lower().startswith('0x'):
            return int(value, 16)
        if value.startswith('0') and len(value) > 1:
            return int(value, 8)
        return int(value, 10)
    except ValueError:
        return None


# The five names the ToS match takes instead of a number, spelled the way
# netfilter spells them (extensions/tos_values.c, tos_symbol_names).  The
# comparison is case insensitive there (strcasecmp in xtopt_parse_tosmask).
VALID_TOS_NAMES = frozenset(
    {
        'maximize-reliability',
        'maximize-throughput',
        'minimize-cost',
        'minimize-delay',
        'normal-service',
    }
)

# The whole traffic class byte, which is what --tos reads: xtopt_parse_tosmask
# hands the argument to tos_parse_numeric with UINT8_MAX as the ceiling.
MAX_TOS = 0xFF


def is_valid_tos(value: str) -> bool:
    """Return True if ``value`` is a usable ToS match value.

    ``--tos`` takes either a number, optionally followed by ``/`` and a
    mask, each from 0 to 255 and in any base C reads (decimal, ``0x`` hex,
    leading-zero octal), or one of five symbolic names.  Anything else is
    answered with "Symbolic name is unknown" or "Illegal value", which
    stops the activation script with every built-in policy already set to
    DROP (netfilter libxtables/xtoptions.c, xtopt_parse_tosmask and
    tos_parse_numeric).

    Checking it is worth more than the message it saves: the value is free
    text from the service editor and goes into the generated script
    unquoted, so a space ends the argument and a dollar sign, a backtick or
    a semicolon start something else entirely - as root, at the moment
    every chain is already at DROP.  The rate-limit table name next door is
    guarded for exactly that reason.
    """
    if not value:
        return False
    normalized = value.strip().lower()
    if normalized in VALID_TOS_NAMES:
        return True
    parts = normalized.split('/')
    if len(parts) > 2:
        return False
    for part in parts:
        number = _strtoul(part)
        if number is None or number > MAX_TOS:
            return False
    return True


# A packet mark is a 32 bit word on both back ends: iptables bounds each
# half of `value[/mask]` at UINT32_MAX (netfilter libxtables/xtables.c,
# xtables_parse_val_mask) and nftables answers a larger one with "Value
# ... exceeds valid range 0-4294967295".
MAX_PACKET_MARK = 0xFFFFFFFF


def is_valid_packet_mark(value: str) -> bool:
    """Return True if ``value`` is a usable packet mark.

    A Tag Service carries the mark as free text from its editor, and the
    mark reaches both back ends unchecked: ``-j MARK --set-mark`` and
    ``-m mark --mark`` on iptables, ``meta mark set`` and ``meta mark`` on
    nftables.  Neither takes a word.  iptables answers "bad integer value
    for option" or "trailing garbage after value", which stops the
    activation script with every built-in policy already set to DROP;
    nftables answers a syntax error and refuses the **whole** ruleset, so
    the firewall keeps whatever it was running.

    The grammar is ``value[/mask]``, each half read the way C reads a
    number with base 0 - decimal, ``0x`` hex, leading-zero octal - and
    bounded at 0 and 4294967295.  Both tools agree on all three bases and
    on the ceiling; verified against iptables 1.8.11 and nft 1.1.6, which
    both store ``020`` as 16.

    Checking it is worth more than the message it saves: the value goes
    into the generated script as a bare shell word, so a space ends the
    argument and a dollar sign, a backtick or a semicolon start something
    else entirely - as root, at the moment every chain is already at DROP.
    The ToS value and the rate-limit table name next door are guarded for
    exactly that reason.
    """
    if not value:
        return False
    parts = value.strip().split('/')
    if len(parts) > 2:
        return False
    for part in parts:
        number = _strtoul(part)
        if number is None or number > MAX_PACKET_MARK:
            return False
    return True


def packet_mark_clear_mask(value: str) -> int | None:
    """Return the bits ``--set-mark value/mask`` clears, ``None`` if none.

    ``--set-mark`` is ``--set-xmark`` with the clear mask computed as
    ``value | mask`` (netfilter extensions/libxt_MARK.c, ``mark_tg_parse``:
    ``O_SET_MARK`` assigns ``info->mask = cb->val.mark | cb->val.mask``),
    and nftables has no such shorthand - it has to be written out as a
    bitwise expression, which needs the number rather than the text.

    Both halves are read the way C reads a number with base 0, which is
    what :func:`is_valid_packet_mark` accepts: ``Python int(s, 0)`` agrees
    about hex and refuses the leading-zero octal spelling both tools take,
    so reading them here rather than at the call site keeps the two
    answers from disagreeing.  ``None`` means the value carries no mask,
    or none that can be read.
    """
    head, sep, tail = value.strip().partition('/')
    if not sep:
        return None
    left = _strtoul(head)
    right = _strtoul(tail)
    if left is None or right is None:
        return None
    return left | right


# A user name both packet filters hand to getpwnam, or a numeric id, or a
# range of them.  The alphabet is the portable one plus the dot and the
# dash a range needs; it deliberately leaves out everything the shell
# reads as syntax, the same way the ToS value and the rate-limit table
# name do.  A leading dash would look like an option to iptables.
_USER_ID_RE = re.compile(r'[0-9A-Za-z_.][0-9A-Za-z._-]{0,254}')


def is_valid_user_id(value: str) -> bool:
    """Return True if ``value`` is a user both packet filters can look up.

    A User Service carries the user as free text from its editor, and the
    value reaches both back ends unchecked: ``-m owner --uid-owner`` on
    iptables, ``meta skuid`` on nftables.  Both look the name up with
    ``getpwnam`` and fall back to a numeric id (netfilter
    extensions/libxt_owner.c and nftables src/meta.c, ``uid_type_parse``),
    so a name that does not exist on the firewall is the admin's business
    and is passed on.  What is not is a value holding characters neither
    tool can carry: nftables answers a syntax error and refuses the
    **whole** ruleset, and on iptables the value goes into the generated
    script as a bare shell word, where a dollar sign, a backtick or a
    semicolon starts something else entirely - as root, at the moment
    every chain is already at DROP.
    """
    return bool(_USER_ID_RE.fullmatch(str(value).strip()))


class CustomService(Service):
    """Platform-specific custom service code."""

    __mapper_args__ = {'polymorphic_identity': 'CustomService'}


class UserService(Service):
    """Service matching a specific user identity."""

    __mapper_args__ = {'polymorphic_identity': 'UserService'}


class TagService(Service):
    """Service used for packet tagging."""

    __mapper_args__ = {'polymorphic_identity': 'TagService'}

    def get_code(self) -> str:
        """Return the packet mark this service matches.

        The value is stored under the ``tagcode`` key, the attribute name
        the ``.fwb`` XML and the tag service dialog both use.  Mirrors
        fwbuilder's ``TagService::getCode()``.
        """
        return str((self.data or {}).get('tagcode', '') or '')


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
        sqlalchemy.UniqueConstraint('group_id', 'name', name='uq_intervals_group'),
        sqlalchemy.Index(
            'uq_intervals_orphan_lib',
            'library_id',
            'name',
            unique=True,
            sqlite_where=sqlalchemy.text('group_id IS NULL'),
        ),
    )
