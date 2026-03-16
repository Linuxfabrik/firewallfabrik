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

"""Import address/network objects from a text file.

Supported line formats (one entry per line):

- ``10.0.0.1``                   -- single IPv4 host
- ``10.0.0.0/24``                -- IPv4 network in CIDR notation
- ``10.0.0.0/255.255.255.0``     -- IPv4 network with dotted netmask
- ``2001:db8::1``                -- single IPv6 host
- ``2001:db8::/32``              -- IPv6 network in CIDR notation
- Lines starting with ``#`` are treated as comments.
- Empty / whitespace-only lines are silently skipped.

Each entry may optionally be followed by whitespace and a name::

    10.0.0.1  webserver01
    192.168.0.0/24  office-network

When no name is given the address/network string itself is used as the
object name.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from firewallfabrik.core.objects import Address

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------


@dataclass
class ParsedEntry:
    """A single address or network parsed from one line of the input file."""

    name: str
    address: str
    netmask: str
    obj_type: str  # 'IPv4', 'IPv6', 'Network', or 'NetworkIPv6'
    line_number: int


@dataclass
class ImportResult:
    """Summary returned after importing addresses."""

    created: int = 0
    skipped: int = 0
    errors: list[str] | None = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


# ------------------------------------------------------------------
# Parsing
# ------------------------------------------------------------------


def _parse_line(line: str, line_number: int) -> ParsedEntry | None:
    """Parse a single non-comment, non-empty line.

    Returns a :class:`ParsedEntry` or *None* when the line cannot be
    interpreted.

    Raises :class:`ValueError` with a human-readable message on
    malformed input.
    """
    # Split into at most two parts: address-part and optional name.
    parts = line.split(None, 1)
    addr_part = parts[0]
    name = parts[1].strip() if len(parts) > 1 else addr_part

    # Try to interpret as a network first (contains '/').
    if '/' in addr_part:
        pieces = addr_part.split('/', 1)
        network_addr = pieces[0]
        mask_part = pieces[1]

        # Determine if the network address is IPv4 or IPv6.
        try:
            ip_obj = ipaddress.ip_address(network_addr)
        except ValueError as exc:
            msg = f'Line {line_number}: invalid address "{network_addr}" -- {exc}'
            raise ValueError(msg) from exc

        if isinstance(ip_obj, ipaddress.IPv4Address):
            # mask_part could be CIDR prefix length or dotted netmask.
            if '.' in mask_part:
                # Dotted netmask -- validate it.
                try:
                    ipaddress.IPv4Network(f'{network_addr}/{mask_part}', strict=False)
                except ValueError as exc:
                    msg = f'Line {line_number}: invalid netmask "{mask_part}" -- {exc}'
                    raise ValueError(msg) from exc
                netmask = mask_part
            else:
                # CIDR prefix length -- convert to dotted netmask.
                try:
                    prefix_len = int(mask_part)
                    net = ipaddress.IPv4Network(
                        f'{network_addr}/{prefix_len}', strict=False
                    )
                except ValueError as exc:
                    msg = (
                        f'Line {line_number}: invalid CIDR prefix '
                        f'"{mask_part}" -- {exc}'
                    )
                    raise ValueError(msg) from exc
                netmask = str(net.netmask)

            # Host with /32 -> IPv4 object; otherwise Network.
            if netmask == '255.255.255.255':
                return ParsedEntry(
                    name=name,
                    address=network_addr,
                    netmask=netmask,
                    obj_type='IPv4',
                    line_number=line_number,
                )
            return ParsedEntry(
                name=name,
                address=str(
                    ipaddress.IPv4Network(
                        f'{network_addr}/{netmask}',
                        strict=False,
                    ).network_address
                ),
                netmask=netmask,
                obj_type='Network',
                line_number=line_number,
            )

        # IPv6 network.
        try:
            prefix_len = int(mask_part)
            ipaddress.IPv6Network(f'{network_addr}/{prefix_len}', strict=False)
        except ValueError as exc:
            msg = f'Line {line_number}: invalid IPv6 prefix "{mask_part}" -- {exc}'
            raise ValueError(msg) from exc

        if prefix_len == 128:
            return ParsedEntry(
                name=name,
                address=str(ip_obj),
                netmask='128',
                obj_type='IPv6',
                line_number=line_number,
            )
        return ParsedEntry(
            name=name,
            address=str(
                ipaddress.IPv6Network(
                    f'{network_addr}/{prefix_len}',
                    strict=False,
                ).network_address
            ),
            netmask=str(prefix_len),
            obj_type='NetworkIPv6',
            line_number=line_number,
        )

    # No slash -- plain host address.
    try:
        ip_obj = ipaddress.ip_address(addr_part)
    except ValueError as exc:
        msg = f'Line {line_number}: invalid address "{addr_part}" -- {exc}'
        raise ValueError(msg) from exc

    if isinstance(ip_obj, ipaddress.IPv4Address):
        return ParsedEntry(
            name=name,
            address=str(ip_obj),
            netmask='255.255.255.255',
            obj_type='IPv4',
            line_number=line_number,
        )
    return ParsedEntry(
        name=name,
        address=str(ip_obj),
        netmask='128',
        obj_type='IPv6',
        line_number=line_number,
    )


def parse_address_file(file_path: str | Path) -> tuple[list[ParsedEntry], list[str]]:
    """Parse a text file and return ``(entries, errors)``.

    *entries* contains one :class:`ParsedEntry` per valid line.
    *errors* contains human-readable messages for lines that could not
    be parsed (parsing continues past errors).
    """
    entries: list[ParsedEntry] = []
    errors: list[str] = []

    path = Path(file_path)
    text = path.read_text(encoding='utf-8', errors='replace')

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            entry = _parse_line(line, line_number)
            if entry is not None:
                entries.append(entry)
        except ValueError as exc:
            errors.append(str(exc))

    return entries, errors


# ------------------------------------------------------------------
# Database import
# ------------------------------------------------------------------


def import_entries(session, lib_id, group_id, entries):
    """Create Address / Network objects in the database.

    Parameters
    ----------
    session : sqlalchemy.orm.Session
        An open (uncommitted) database session.
    lib_id : uuid.UUID
        The target library's ID.
    group_id : uuid.UUID | None
        The target group's ID (e.g. ``Objects/Addresses`` or
        ``Objects/Networks``).  When *None* the objects are placed
        directly in the library without a parent group.
    entries : list[ParsedEntry]
        Parsed entries to import.

    Returns
    -------
    ImportResult
        A summary of created / skipped objects and any errors.
    """
    result = ImportResult()

    for entry in entries:
        try:
            new_obj = Address(
                id=uuid.uuid4(),
                type=entry.obj_type,
                library_id=lib_id,
                group_id=group_id,
                name=entry.name,
                inet_addr_mask={
                    'address': entry.address,
                    'netmask': entry.netmask,
                },
            )
            session.add(new_obj)
            session.flush()
            result.created += 1
        except Exception as exc:
            session.rollback()
            logger.warning(
                'Failed to import "%s" (line %d): %s',
                entry.name,
                entry.line_number,
                exc,
            )
            result.skipped += 1
            result.errors.append(f'"{entry.name}" (line {entry.line_number}): {exc}')

    return result
