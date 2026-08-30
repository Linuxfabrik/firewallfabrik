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

"""Which object iptables can negate with a single "!".

``Compiler::singleObjectNegation`` asks the object itself:
``countInetAddresses(true) == 1``.  Every model class answers that
question for itself - 0 by default, 1 for IPv4, IPv6, Network and
NetworkIPv6, the sum of its addresses for an Interface, and the sum over
its interfaces for a Host, a Firewall and a Cluster.

Answering it by class instead ("only these four types") sends a host with
one address down the temporary-chain path.  That is not wrong on its own,
but the chain empties the rule element, and the virtual address a NAT
rule needs is read off that element - so the firewall never configured
the address it was translating to.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import (
    AddressRange,
    Firewall,
    Host,
    Interface,
    IPv4,
    IPv6,
    Network,
)

FIXTURE = (
    pathlib.Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
)


@pytest.fixture(scope='module')
def tree():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    return dm


def _count(dm, cls, name):
    with dm.session() as session:
        obj = session.scalars(sqlalchemy.select(cls).where(cls.name == name)).one()
        return obj.count_inet_addresses()


def test_an_address_object_stands_for_one_argument():
    for cls in (IPv4, IPv6, Network):
        assert cls().count_inet_addresses() == 1


def test_an_address_range_stands_for_none():
    """It is written out as the networks covering it, one "!" each."""
    assert AddressRange().count_inet_addresses() == 0


def test_the_loopback_is_skipped_when_asked():
    lo = Interface()
    lo.name = 'lo'
    lo.addresses = [IPv4()]
    assert lo.count_inet_addresses(skip_loopback=True) == 0
    assert lo.count_inet_addresses(skip_loopback=False) == 1


def test_a_host_sums_the_addresses_below_it(tree):
    assert _count(tree, Host, 'hostA') == 1


def test_a_firewall_answers_the_same_way(tree):
    """Firewall and Cluster inherit Host::countInetAddresses in the C++ too."""
    assert _count(tree, Firewall, 'firewall2') > 1


def test_a_negated_host_is_written_with_one_bang(tmp_path, tree):
    """And the address the rule translates to reaches the interface.

    firewall2's NAT rule 37 redirects http to a proxy and excludes the
    proxy itself, which is a Host object with one address.  The reference
    output writes `-d ! 192.168.1.50` and configures 192.168.1.50/24 on
    eth0.
    """
    from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

    with tree.session() as session:
        fw_id = str(
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == 'firewall2'),
            )
            .one()
            .id
        )

    driver = CompilerDriver_ipt(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')

    script = (tmp_path / 'fw.fw').read_text()
    assert '!  -d 192.168.1.50  --dport 80' in script
    assert (
        'update_addresses_of_interface "eth0 192.168.1.1/24 192.168.1.10/24 192.168.1.50/24"'
        in script
    )
