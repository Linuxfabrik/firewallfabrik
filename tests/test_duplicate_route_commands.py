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

"""One route may only be installed once.

`ip route add` for a destination that is already routed answers
"RTNETLINK answers: File exists" and returns non-zero, and since the
routing rollback that puts the previous routing table back and stops the
activation.  Every check in the routing pipeline compares object ids, the
way fwbuilder does - except the last one, which compares the command
itself (`RoutingCompiler_ipt::eliminateDuplicateRules` reads
`RoutingRuleToString(rule)`).  The difference is the whole point of that
processor: two objects holding one address, or two interface objects of
one name, are one route on the wire and two different ids.

A cluster member has exactly that pair, because the copy of a cluster
interface shares its name with the member's own interface.
"""

import uuid
from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Firewall,
    FWObjectDatabase,
    Interface,
    IPv4,
    Library,
    Network,
    Routing,
    RoutingRule,
    rule_elements,
)
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

FIXTURES = Path(__file__).parent / 'fixtures'


def _element(session, rule, slot, target_id):
    """Put one object into a rule element slot."""
    session.execute(
        rule_elements.insert().values(
            rule_id=rule.id, slot=slot, target_id=target_id, position=0
        )
    )


def _network(session, library, name, address):
    net = Network(
        id=uuid.uuid4(),
        type='Network',
        name=name,
        library=library,
        inet_addr_mask={'address': address, 'netmask': '255.255.255.0'},
    )
    session.add(net)
    return net


@pytest.fixture
def firewall_with_two_equal_routes():
    """A firewall routing the same network twice, through two objects.

    Both destinations say 192.168.50.0/24 and both routes leave through
    eth0, so the two rules compile into the same ``ip route add``.
    """
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        session.flush()

        fw = Firewall(
            id=uuid.uuid4(),
            type='Firewall',
            name='fw-test',
            library=library,
            data={'platform': 'iptables', 'host_OS': 'linux24'},
        )
        session.add(fw)
        iface = Interface(id=uuid.uuid4(), name='eth0', device=fw, library=library)
        session.add(iface)
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='fw-test:eth0:ip',
                interface=iface,
                inet_addr_mask={'address': '192.0.2.1', 'netmask': '255.255.255.0'},
            )
        )

        rule_set = Routing(
            id=uuid.uuid4(), type='Routing', name='Routing', device=fw, top=True
        )
        session.add(rule_set)

        # Two Network objects for one and the same network, the shape the
        # object tree arrives at when a network is entered twice.
        for position, obj_name in enumerate(('net-a', 'net-b')):
            net = _network(session, library, obj_name, '192.168.50.0')
            rule = RoutingRule(
                id=uuid.uuid4(),
                type='RoutingRule',
                rule_set=rule_set,
                position=position,
            )
            session.add(rule)
            session.flush()
            _element(session, rule, 'rdst', net.id)
            _element(session, rule, 'ritf', iface.id)
        session.flush()
        fw_id = str(fw.id)
    return dm, fw_id


def _routes(dm, fw_id, tmp_path):
    driver = CompilerDriver_ipt(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    script = (tmp_path / 'fw-test.fw').read_text()
    return [
        line.strip()
        for line in script.splitlines()
        if line.strip().startswith('$IP') and 'route add' in line
    ]


def test_two_objects_for_one_network_install_one_route(
    firewall_with_two_equal_routes, tmp_path
):
    dm, fw_id = firewall_with_two_equal_routes

    routes = _routes(dm, fw_id, tmp_path)

    assert len(routes) == 1, routes
    assert '192.168.50.0/24' in routes[0]
    assert 'dev eth0' in routes[0]


def test_two_interface_objects_of_one_name_install_one_route(
    firewall_with_two_equal_routes, tmp_path
):
    """The cluster shape: one name, two interface objects, one route.

    ``populate_cluster_elements`` gives the member a copy of the cluster's
    interface that carries the same name, because the failover protocol
    runs on the member's own NIC.  A route of the cluster and a route of
    the member then both say ``dev eth0``.
    """
    dm, fw_id = firewall_with_two_equal_routes
    with dm.session() as session:
        fw = session.get(Firewall, uuid.UUID(fw_id))
        copy_iface = Interface(
            id=uuid.uuid4(),
            name='eth0',
            device=fw,
            library=fw.library,
            cluster_interface=True,
        )
        session.add(copy_iface)
        session.flush()
        # `_copy_cluster_interface` copies the addresses of the cluster's
        # interface onto the member's copy, so the copy carries one - and
        # a regular interface without an address stops the compile.
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='cluster:eth0:ip',
                interface=copy_iface,
                inet_addr_mask={
                    'address': '192.0.2.9',
                    'netmask': '255.255.255.0',
                },
            )
        )
        session.flush()
        # The second rule leaves through the copy rather than through the
        # member's own interface.  Same name, different object.
        second = session.scalars(
            sqlalchemy.select(RoutingRule).where(RoutingRule.position == 1),
        ).one()
        session.execute(
            rule_elements.update()
            .where(
                rule_elements.c.rule_id == second.id,
                rule_elements.c.slot == 'ritf',
            )
            .values(target_id=copy_iface.id)
        )

    routes = _routes(dm, fw_id, tmp_path)

    assert len(routes) == 1, routes
