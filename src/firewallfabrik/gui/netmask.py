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

"""Netmask validation for the address editors, the way fwbuilder does it.

Every editor that takes a netmask refuses the same values Firewall
Builder refuses, with the message Firewall Builder shows, and hands back
the value in the spelling that goes into the data file: dotted for IPv4
and a bit length for IPv6 (``NetworkIPv6::toXML`` writes the length,
``Network::setNetmask`` writes ``InetAddr::toString``).

Normalising here is what keeps a mask the compilers can read out of the
file.  fwbuilder stores the result of ``InetAddr(...)``, so a mask typed
as ``8`` is written as ``255.0.0.0``; storing the raw text instead let a
value through that passed validation and that nothing downstream could
parse, and the compilers then dropped the netmask and matched a single
address where a whole network was meant.
"""

import ipaddress

# fwbuilder's InetAddr::addressLengthBits() for the two families.
IPV4_MAX_PREFIX = 32
IPV6_MAX_PREFIX = 128

ILLEGAL_NETMASK = "Illegal netmask '%1'"
ZEROES_IN_THE_MIDDLE = 'Netmasks with zeroes in the middle are not supported'
NETWORK_WITH_ZERO_NETMASK = "Network object should not have netmask '0.0.0.0'"
EMPTY_ADDRESS_OR_NETMASK = 'Empty address or netmask field'


class NetmaskRejected(ValueError):
    """A netmask an editor refuses, carrying the message fwbuilder shows."""

    def __init__(self, message: str, value: str = ''):
        super().__init__(message.replace('%1', value))
        self.message = message.replace('%1', value)


def _bit_length(text: str) -> int | None:
    """Read *text* as a plain bit length, or return ``None``.

    Deliberately stricter than ``int()``, which takes a leading sign and
    any Unicode decimal digit: ``'+8'`` and ``'٨'`` passed as the length
    8 and were then stored verbatim, where ``ipaddress`` could not read
    them back and every compiler path silently dropped the netmask.  Only
    ASCII digits are a length.  Surrounding whitespace is dropped, the
    way ``IPv4Dialog::validate()`` trims the field first.
    """
    stripped = text.strip()
    if stripped.isascii() and stripped.isdigit():
        return int(stripped)
    return None


def _dotted(text: str) -> str | None:
    """Read *text* as a dotted IPv4 mask, or return ``None``."""
    try:
        return str(ipaddress.IPv4Address(text.strip()))
    except ValueError:
        return None


def _is_contiguous(dotted: str) -> bool:
    """``InetAddr::isValidV4Netmask()``: ones first, then zeros only.

    Written out rather than left to ``IPv4Network``, which also takes the
    inverted spelling: 0.255.255.255 is a host mask there and passes,
    while fwbuilder refuses it as a mask with zeroes in the middle.
    """
    bits = int(ipaddress.IPv4Address(dotted))
    while bits & 0x80000000:
        bits = (bits << 1) & 0xFFFFFFFF
    return bits == 0


def _mask_of_length(prefix: int) -> str:
    """The dotted IPv4 mask of *prefix* bits."""
    return str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)


def is_any_address(text: str) -> bool:
    """``InetAddr::isAny()`` for the address field of an editor."""
    try:
        return int(ipaddress.ip_address(text.strip())) == 0
    except ValueError:
        return False


def netmask_for_ipv4_address(text: str) -> str:
    """Validate the netmask of an IPv4 address object.

    ``IPv4Dialog::validate()``: the value has to parse as an ``InetAddr``
    and has to be a contiguous mask.  A value without a dot is a bit
    length (``InetAddr::init_from_string``), so ``8`` and ``255.0.0.0``
    are the same mask and both are accepted.
    """
    prefix = _bit_length(text)
    if prefix is not None:
        if prefix > IPV4_MAX_PREFIX:
            raise NetmaskRejected(ILLEGAL_NETMASK, text)
        return _mask_of_length(prefix)

    dotted = _dotted(text)
    if dotted is None:
        raise NetmaskRejected(ILLEGAL_NETMASK, text)
    if not _is_contiguous(dotted):
        raise NetmaskRejected(ZEROES_IN_THE_MIDDLE)
    return dotted


def netmask_for_network(text: str, *, address_is_any: bool) -> str:
    """Validate the netmask of a Network object.

    ``NetworkDialog::validate()`` keeps two branches apart.  A bit length
    has to sit inside ``0 < len < 32``, with 0 allowed only when the
    address is 0.0.0.0 as well, while a dotted mask only has to be
    contiguous and other than 0.0.0.0 (fwbuilder #251: a network object
    with a /0 netmask matches every address, which is never what the
    admin meant).  The asymmetry is fwbuilder's - a length of 32 is
    refused where 255.255.255.255 is taken - and is kept so that the same
    value passes in both programs.
    """
    prefix = _bit_length(text)
    if prefix is not None:
        if address_is_any and prefix == 0:
            return _mask_of_length(0)
        if 0 < prefix < IPV4_MAX_PREFIX:
            return _mask_of_length(prefix)
        raise NetmaskRejected(ILLEGAL_NETMASK, text)

    dotted = _dotted(text)
    if dotted is None:
        # An empty field reaches InetAddr as the length 0 and comes out
        # as 0.0.0.0, which is the case below - so fwbuilder answers an
        # empty netmask with the /0 message rather than "illegal".
        if not text.strip() and not address_is_any:
            raise NetmaskRejected(NETWORK_WITH_ZERO_NETMASK)
        raise NetmaskRejected(ILLEGAL_NETMASK, text)
    if dotted == '0.0.0.0':  # nosec B104
        if address_is_any:
            return dotted
        raise NetmaskRejected(NETWORK_WITH_ZERO_NETMASK)
    if not _is_contiguous(dotted):
        raise NetmaskRejected(ZEROES_IN_THE_MIDDLE)
    return dotted


def netmask_for_ipv6_address(text: str) -> str:
    """Validate the netmask of an IPv6 address object.

    ``IPv6Dialog::validate()``: a bit length, and ``InetAddr(AF_INET6,
    int)`` throws above 128.
    """
    prefix = _bit_length(text)
    if prefix is None or prefix > IPV6_MAX_PREFIX:
        raise NetmaskRejected(ILLEGAL_NETMASK, text)
    return str(prefix)


def netmask_for_network_ipv6(text: str) -> str:
    """Validate the netmask of a NetworkIPv6 object.

    ``NetworkDialogIPv6::validate()``: ``0 < len < 128``.  Both ends are
    refused on purpose, /0 for fwbuilder #251 and /128 because a network
    object holding a single address is a host.
    """
    prefix = _bit_length(text)
    if prefix is None or not 0 < prefix < IPV6_MAX_PREFIX:
        raise NetmaskRejected(ILLEGAL_NETMASK, text)
    return str(prefix)


def netmask_for_interface_address(text: str, *, is_v4: bool) -> str:
    """Validate the netmask of an interface address in the new-host wizard.

    ``InterfaceEditorWidget::validateAddress()`` takes a bit length
    inside the family's range, or an address-shaped mask.  It stops
    there, so a mask with zeroes in the middle passes in fwbuilder's own
    wizard while the very same value is refused in the editor of the
    address it creates; the contiguity check of ``IPv4Dialog`` is applied
    here as well rather than carrying the value to a dialog that will
    refuse it.
    """
    prefix = _bit_length(text)
    if prefix is not None:
        if prefix > (IPV4_MAX_PREFIX if is_v4 else IPV6_MAX_PREFIX):
            raise NetmaskRejected(ILLEGAL_NETMASK, text)
        return _mask_of_length(prefix) if is_v4 else str(prefix)

    if not is_v4:
        raise NetmaskRejected(ILLEGAL_NETMASK, text)

    dotted = _dotted(text)
    if dotted is None:
        raise NetmaskRejected(ILLEGAL_NETMASK, text)
    if not _is_contiguous(dotted):
        raise NetmaskRejected(ZEROES_IN_THE_MIDDLE)
    return dotted
