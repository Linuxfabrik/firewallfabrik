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

"""Which network the firewall is on, as `Compiler::checkIfAddressesMatch` asks it.

``SplitIf{Src,Dst}FWNetwork`` uses this to decide whether a rule naming a
network needs a copy in the output or input chain: the firewall sits on
that network, so it can send and receive traffic that looks like it comes
from there.

The C++ asks the question from both sides, and counts two shapes as
standing for a subnet - a Network object, and an address that hangs under
an interface, because the netmask an interface carries describes the
network the interface is on.  The port only counted the first, so the
answer was one-sided: a network *inside* the firewall's own subnet, which
is the ordinary case of a segment carved out of a LAN, was not
recognised.
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import Firewall, Network

from .conftest import FIXTURES_DIR


@pytest.fixture(scope='module')
def firewall():
    """`fw-nat`: eth0 198.51.100.1/24, eth1 192.168.1.1/24, eth2 10.0.0.1/24."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    with db.session() as session:
        yield session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-nat'),
        ).scalar_one()


def _network(address, netmask):
    obj = Network(id=uuid.uuid4(), name='probe')
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


@pytest.mark.parametrize(
    ('address', 'netmask'),
    [
        # The subnet of an interface, which contains its address.
        ('192.168.1.0', '255.255.255.0'),
        ('10.0.0.0', '255.255.255.0'),
        # A subnet carved out of one, which does not contain it.  The
        # interface's own netmask is what answers here.
        ('198.51.100.128', '255.255.255.192'),
        ('192.168.1.64', '255.255.255.192'),
        # A supernet of it.
        ('192.168.0.0', '255.255.0.0'),
    ],
)
def test_a_network_the_firewall_is_on(firewall, address, netmask):
    compiler = Compiler.__new__(Compiler)
    assert compiler.find_address_for(_network(address, netmask), firewall) is not None


@pytest.mark.parametrize(
    ('address', 'netmask'),
    [
        ('203.0.113.0', '255.255.255.0'),
        ('192.168.2.0', '255.255.255.0'),
        ('172.16.0.0', '255.240.0.0'),
    ],
)
def test_a_network_the_firewall_is_not_on(firewall, address, netmask):
    compiler = Compiler.__new__(Compiler)
    assert compiler.find_address_for(_network(address, netmask), firewall) is None


def test_the_answer_is_the_address_that_matched(firewall):
    """The caller substitutes it for the network, so it has to be the right one."""
    compiler = Compiler.__new__(Compiler)
    found = compiler.find_address_for(
        _network('192.168.1.64', '255.255.255.192'),
        firewall,
    )
    assert found is not None
    assert found.get_address() == '192.168.1.1'
