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

"""Tests for address containment logic used by shadowing detection.

Ports the address-related parts of fwbuilder's InetAddrMaskTest
(overlap detection) and ObjectMatcherTest (address matching).
"""

import uuid

import pytest
import sqlalchemy
import sqlalchemy.orm

from firewallfabrik.compiler.processors._generic import _addr_contains, _addr_range
from firewallfabrik.core.objects import Address, AddressRange, Network, NetworkIPv6
from firewallfabrik.core.objects._base import Base


@pytest.fixture()
def session():
    """Create an in-memory SQLite session with the ORM schema."""
    engine = sqlalchemy.create_engine('sqlite://')
    Base.metadata.create_all(engine)
    Session = sqlalchemy.orm.sessionmaker(bind=engine)
    s = Session()
    yield s
    s.close()


def _add_address(session, addr_str, name='test'):
    obj = Address(
        id=uuid.uuid4(),
        name=name,
        inet_addr_mask={'address': addr_str, 'netmask': '255.255.255.255'},
    )
    session.add(obj)
    session.flush()
    return obj


def _add_network(session, addr_str, mask_str, name='test-net'):
    obj = Network(
        id=uuid.uuid4(),
        name=name,
        inet_addr_mask={'address': addr_str, 'netmask': mask_str},
    )
    session.add(obj)
    session.flush()
    return obj


def _add_network_ipv6(session, addr_str, prefix_len, name='test-net6'):
    obj = NetworkIPv6(
        id=uuid.uuid4(),
        name=name,
        inet_addr_mask={'address': addr_str, 'netmask': str(prefix_len)},
    )
    session.add(obj)
    session.flush()
    return obj


def _add_range(session, start, end, name='test-range'):
    obj = AddressRange(
        id=uuid.uuid4(),
        name=name,
        start_address={'address': start},
        end_address={'address': end},
    )
    session.add(obj)
    session.flush()
    return obj


class TestAddrRange:
    def test_single_host(self, session):
        a = _add_address(session, '192.168.1.1')
        r = _addr_range(a)
        assert r is not None
        assert str(r[0]) == '192.168.1.1'
        assert str(r[1]) == '192.168.1.1'

    def test_network(self, session):
        n = _add_network(session, '192.168.1.0', '255.255.255.0')
        r = _addr_range(n)
        assert str(r[0]) == '192.168.1.0'
        assert str(r[1]) == '192.168.1.255'

    def test_network_cidr(self, session):
        n = _add_network(session, '10.0.0.0', '255.255.0.0')
        r = _addr_range(n)
        assert str(r[0]) == '10.0.0.0'
        assert str(r[1]) == '10.0.255.255'

    def test_address_range(self, session):
        ar = _add_range(session, '192.168.1.10', '192.168.1.20')
        r = _addr_range(ar)
        assert str(r[0]) == '192.168.1.10'
        assert str(r[1]) == '192.168.1.20'

    def test_ipv6_network(self, session):
        n = _add_network_ipv6(session, 'fe80::', 64)
        r = _addr_range(n)
        assert r is not None
        assert str(r[0]) == 'fe80::'
        assert str(r[1]) == 'fe80::ffff:ffff:ffff:ffff'

    def test_empty_address(self, session):
        a = _add_address(session, '')
        r = _addr_range(a)
        assert r is None


class TestAddrContains:
    def test_same_object(self, session):
        a = _add_address(session, '192.168.1.1')
        assert _addr_contains(a, a) is True

    def test_host_contains_itself(self, session):
        a1 = _add_address(session, '192.168.1.1', name='a1')
        a2 = _add_address(session, '192.168.1.1', name='a2')
        assert _addr_contains(a1, a2) is True

    def test_host_does_not_contain_different_host(self, session):
        a1 = _add_address(session, '192.168.1.1', name='a1')
        a2 = _add_address(session, '192.168.1.2', name='a2')
        assert _addr_contains(a1, a2) is False

    def test_network_contains_host(self, session):
        net = _add_network(session, '192.168.1.0', '255.255.255.0')
        host = _add_address(session, '192.168.1.42')
        assert _addr_contains(net, host) is True

    def test_network_does_not_contain_outside_host(self, session):
        net = _add_network(session, '192.168.1.0', '255.255.255.0')
        host = _add_address(session, '192.168.2.1')
        assert _addr_contains(net, host) is False

    def test_larger_network_contains_smaller(self, session):
        big = _add_network(session, '10.0.0.0', '255.0.0.0', name='big')
        small = _add_network(session, '10.1.0.0', '255.255.0.0', name='small')
        assert _addr_contains(big, small) is True
        assert _addr_contains(small, big) is False

    def test_network_contains_range_inside(self, session):
        net = _add_network(session, '192.168.1.0', '255.255.255.0')
        rng = _add_range(session, '192.168.1.10', '192.168.1.20')
        assert _addr_contains(net, rng) is True

    def test_network_does_not_contain_range_crossing_boundary(self, session):
        net = _add_network(session, '192.168.1.0', '255.255.255.0')
        rng = _add_range(session, '192.168.1.200', '192.168.2.10')
        assert _addr_contains(net, rng) is False

    def test_range_contains_host_inside(self, session):
        rng = _add_range(session, '10.0.0.1', '10.0.0.100')
        host = _add_address(session, '10.0.0.50')
        assert _addr_contains(rng, host) is True

    def test_range_does_not_contain_host_outside(self, session):
        rng = _add_range(session, '10.0.0.1', '10.0.0.100')
        host = _add_address(session, '10.0.0.200')
        assert _addr_contains(rng, host) is False

    def test_ipv6_network_contains_host(self, session):
        net = _add_network_ipv6(session, 'fe80::', 64)
        host = _add_address(session, 'fe80::1')
        assert _addr_contains(net, host) is True

    def test_ipv6_network_does_not_contain_different_prefix(self, session):
        net = _add_network_ipv6(session, 'fe80::', 64)
        host = _add_address(session, '2001:db8::1')
        assert _addr_contains(net, host) is False
