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

"""Which addresses count as "the firewall" when a chain is decided.

``Compiler::complexMatch`` answers that question for every processor that
splits a rule between the input, output and forward chains, and
``ObjectMatcher`` supplies the answer.  Three things about it are easy to
get wrong in a port and all three were:

* both of its flags default to *on* (``Compiler.h:955``), so a broadcast
  and a multicast address count unless a caller says otherwise;
* ``InetAddr::isAny()`` looks at the address alone, so 0.0.0.0 - the "old
  broadcast" - counts as well, whatever netmask sits next to it;
* the address is compared against every address of the firewall's
  interfaces, not only against the ones that hang under one in the object
  tree.

A packet to a broadcast or multicast address is delivered locally and can
be sent by the firewall itself, and it is never routed, so a rule naming
one belongs in INPUT and OUTPUT.  Putting it in FORWARD gives a rule no
packet can match: an Accept that permits nothing, a Deny that stops
nothing.
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import AddressRange, Firewall, IPv4, IPv6, Network

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def firewall():
    """The `fw-nat` firewall of the hand-written fixture.

    Its eth1 carries 192.168.1.1/24, which is what the subnet cases below
    are about.
    """
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    with db.session() as session:
        yield session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-nat'),
        ).scalar_one()


def _address(cls, address, netmask):
    obj = cls(id=uuid.uuid4(), name='probe')
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


@pytest.mark.parametrize(
    ('address', 'netmask'),
    [
        # An address of the firewall, as a standalone object rather than
        # as a child of the interface that carries it.
        ('198.51.100.1', '255.255.255.255'),
        ('192.168.1.1', '255.255.255.255'),
        # The network and the broadcast address of an interface's subnet.
        # A packet to either travels in a broadcast frame and is
        # delivered locally (fwbuilder bug #1040773).
        ('192.168.1.0', '255.255.255.255'),
        ('192.168.1.255', '255.255.255.255'),
        # The broadcast, the old broadcast and a multicast group.
        ('255.255.255.255', '255.255.255.255'),
        ('0.0.0.0', '255.255.255.255'),  # nosec B104
        ('224.0.0.18', '255.255.255.255'),
    ],
)
def test_the_firewall_recognises_its_own_traffic(firewall, address, netmask):
    compiler = Compiler.__new__(Compiler)
    assert compiler.complex_match(_address(IPv4, address, netmask), firewall)


@pytest.mark.parametrize(
    ('address', 'netmask'),
    [
        ('203.0.113.9', '255.255.255.255'),
        ('192.168.1.7', '255.255.255.255'),
    ],
)
def test_an_ordinary_host_is_not_the_firewall(firewall, address, netmask):
    compiler = Compiler.__new__(Compiler)
    assert not compiler.complex_match(_address(IPv4, address, netmask), firewall)


@pytest.mark.parametrize(
    ('address', 'netmask'),
    [
        ('255.255.255.255', '255.255.255.255'),
        ('0.0.0.0', '255.255.255.255'),  # nosec B104
        ('224.0.0.18', '255.255.255.255'),
    ],
)
def test_a_bridging_firewall_forwards_such_a_frame(firewall, address, netmask):
    """The two flags off is what a bridging firewall's chain decision asks.

    A bridge really does forward a broadcast, so there the question is
    the plain one and the answer has to be no.  fwbuilder writes it as
    ``b=m= !bridging_fw``.
    """
    compiler = Compiler.__new__(Compiler)
    assert not compiler.complex_match(
        _address(IPv4, address, netmask),
        firewall,
        recognize_broadcasts=False,
        recognize_multicasts=False,
    )


def test_a_network_the_firewall_merely_sits_in_is_not_the_firewall(firewall):
    """``ObjectMatcher::dispatch(Network*)`` stops at a non-host mask.

    Whether a network counts is the "assume firewall is part of any and
    networks" question, which the callers ask for themselves.
    """
    compiler = Compiler.__new__(Compiler)
    assert not compiler.complex_match(
        _address(Network, '192.168.1.0', '255.255.255.0'),
        firewall,
    )


def test_a_network_of_one_address_is_that_address(firewall):
    """The address-range expansion produces exactly such an object."""
    compiler = Compiler.__new__(Compiler)
    assert compiler.complex_match(
        _address(Network, '192.168.1.1', '255.255.255.255'),
        firewall,
    )


def test_link_local_multicast_is_the_ipv6_broadcast(firewall):
    """``InetAddr::isBroadcast()`` answers ff02::/16 for IPv6.

    IPv6 has no broadcast; link-local multicast carries the traffic the
    IPv4 broadcast carries, and it is not routed either.
    """
    compiler = Compiler.__new__(Compiler)
    assert compiler.complex_match(_address(IPv6, 'ff02::1', '128'), firewall)
    assert not compiler.complex_match(
        _address(IPv6, 'ff02::1', '128'),
        firewall,
        recognize_broadcasts=False,
        recognize_multicasts=False,
    )


def _range(start, end):
    obj = AddressRange(id=uuid.uuid4(), name='probe')
    obj.start_address = {'address': start}
    obj.end_address = {'address': end}
    return obj


@pytest.mark.parametrize(
    ('start', 'end'),
    [
        # One end being a broadcast is enough
        # (``ObjectMatcher::dispatch(AddressRange*)``).
        ('255.255.255.255', '255.255.255.255'),
        ('203.0.113.1', '255.255.255.255'),
        # The old broadcast of the standard library.
        ('0.0.0.0', '0.0.0.0'),  # nosec B104
        # A range that covers one of the firewall's own addresses.
        ('192.168.1.0', '192.168.1.9'),
    ],
)
def test_a_range_reaching_the_firewall(firewall, start, end):
    compiler = Compiler.__new__(Compiler)
    assert compiler.complex_match(_range(start, end), firewall)


def test_a_range_that_reaches_nothing_of_the_firewall(firewall):
    compiler = Compiler.__new__(Compiler)
    assert not compiler.complex_match(_range('203.0.113.1', '203.0.113.9'), firewall)
