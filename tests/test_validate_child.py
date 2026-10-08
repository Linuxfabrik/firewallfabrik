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

"""What may go where, against Firewall Builder's ``validateChild`` (#189).

The editor once answered this per insertion path with a list of allowed
types taken from the "New object" menu, and so refused an interface as a
member of an object group.  Firewall Builder's ``ObjectGroup::validateChild``
refuses services, time intervals and rule sets and takes everything else.
Each test names the function it holds the port to.
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core._validation import (
    group_accepts,
    interface_belongs_to,
    is_gateway,
    rule_element_accepts,
    rule_element_refusal,
    rule_set_refusal,
    tree_child_refusal,
)
from firewallfabrik.core.objects import (
    AddressRange,
    AttachedNetworks,
    Cluster,
    DNSName,
    DynamicGroup,
    FailoverClusterGroup,
    Firewall,
    Host,
    Interface,
    Interval,
    IntervalGroup,
    IPv4,
    IPv6,
    Library,
    Network,
    ObjectGroup,
    PhysAddress,
    Policy,
    Routing,
    ServiceGroup,
    StateSyncClusterGroup,
    TagService,
    TCPService,
    group_membership,
)

from .conftest import FIXTURES_DIR


def _new(cls, **kw):
    return cls(id=uuid.uuid4(), name=kw.pop('name', cls.__name__), **kw)


ADDRESS_LIKE = [
    AddressRange,
    AttachedNetworks,
    Cluster,
    DNSName,
    DynamicGroup,
    FailoverClusterGroup,
    Firewall,
    Host,
    Interface,
    IPv4,
    IPv6,
    Network,
    ObjectGroup,
    PhysAddress,
]
NOT_ADDRESS_LIKE = [Interval, IntervalGroup, Library, Policy, ServiceGroup, TCPService]


@pytest.mark.parametrize('cls', ADDRESS_LIKE, ids=lambda c: c.__name__)
def test_an_object_group_takes_every_address_like_object(cls):
    """ObjectGroup::validateChild (ObjectGroup.cpp:59)."""
    assert group_accepts(_new(ObjectGroup), _new(cls))


@pytest.mark.parametrize('cls', NOT_ADDRESS_LIKE, ids=lambda c: c.__name__)
def test_an_object_group_refuses_services_intervals_and_structure(cls):
    assert not group_accepts(_new(ObjectGroup), _new(cls))


def test_a_service_group_takes_services_only():
    """ServiceGroup::validateChild (ServiceGroup.cpp:60)."""
    group = _new(ServiceGroup)
    assert group_accepts(group, _new(TCPService))
    assert group_accepts(group, _new(TagService))
    assert group_accepts(group, _new(ServiceGroup))
    for cls in (Interface, IPv4, ObjectGroup, Interval, IntervalGroup, Host):
        assert not group_accepts(group, _new(cls)), cls.__name__


def test_a_cluster_group_takes_interfaces_only():
    """ClusterGroup::validateChild (ClusterGroup.cpp:45)."""
    group = _new(FailoverClusterGroup)
    assert group_accepts(group, _new(Interface))
    assert not group_accepts(group, _new(IPv4))


def test_a_group_never_contains_itself():
    group = _new(ObjectGroup)
    assert not group_accepts(group, group)


def _interface_group(db):
    """An object group whose members are two interfaces of one firewall."""
    with db.session() as session:
        fw = session.scalars(sqlalchemy.select(Firewall)).first()
        ifaces = [i for i in fw.interfaces if i.parent_interface_id is None][:2]
        group = ObjectGroup(
            id=uuid.uuid4(),
            name='itf-group',
            library_id=fw.library_id,
        )
        session.add(group)
        session.flush()
        for pos, iface in enumerate(ifaces):
            session.execute(
                group_membership.insert().values(
                    group_id=group.id, member_id=iface.id, position=pos
                )
            )
        return fw.id, group.id


def test_a_group_of_interfaces_goes_into_the_interface_element():
    """RuleElementItf::validateChild (RuleElement.cpp:315) and #189."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    fw_id, group_id = _interface_group(db)
    with db.session() as session:
        fw = session.get(Firewall, fw_id)
        group = session.get(ObjectGroup, group_id)
        for slot in ('itf', 'itf_inb', 'itf_outb'):
            assert rule_element_accepts(slot, group), slot
            assert rule_element_refusal(slot, group, fw, []) == ''
        other = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.id != fw_id)
        ).first()
        assert not interface_belongs_to(other, group), (
            'checkItfChildOfThisFw: the interfaces are not the other firewall ones'
        )
        assert rule_element_refusal('itf', group, other, [])


def test_an_empty_group_or_one_with_an_address_is_no_interface_group():
    assert not rule_element_accepts('itf', _new(ObjectGroup))
    assert not rule_element_accepts('itf', _new(IPv4))


def test_the_translated_service_refuses_a_tag_service():
    """RuleElementTSrv::validateChild (RuleElement.cpp:563)."""
    assert not rule_element_accepts('tsrv', _new(TagService))
    assert rule_element_accepts('tsrv', _new(TCPService))
    assert rule_element_accepts('srv', _new(TagService))


def test_the_route_elements_take_one_object():
    """RuleElementRGtw / RuleElementRItf::validateChild (RuleElement.cpp:658, :695)."""
    gw = _new(IPv4, inet_addr_mask={'address': '192.0.2.1', 'netmask': '32'})
    assert is_gateway(gw)
    assert not is_gateway(
        _new(Network, inet_addr_mask={'address': '192.0.2.0', 'netmask': '24'})
    )
    assert rule_element_refusal('rgtw', gw, None, [_new(IPv4)])
    assert rule_element_refusal('ritf', _new(Interface), None, [_new(Interface)])


def test_a_rule_set_is_refused_everywhere_in_a_rule():
    for slot in ('src', 'dst', 'srv', 'itf', 'when', 'rgtw', 'ritf', 'tsrv'):
        assert not rule_element_accepts(slot, _new(Policy)), slot


def test_a_firewall_has_one_routing_rule_set():
    """Firewall::validateChild (Firewall.cpp:205)."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'objects-for-regression-tests.fwb'))
    with db.session() as session:
        fw = next(
            f
            for f in session.scalars(sqlalchemy.select(Firewall))
            if any(rs.type == 'Routing' for rs in f.rule_sets)
        )
        assert rule_set_refusal(fw, _new(Routing))
        assert rule_set_refusal(fw, _new(Policy)) == ''


def test_an_interface_takes_one_level_of_sub_interfaces():
    """Interface::validateChild (Interface.cpp:351)."""
    parent = _new(Interface, name='br0', options={'type': 'bridge'})
    sub = _new(Interface, name='br0.1', parent_interface_id=parent.id)
    assert tree_child_refusal(parent, _new(Interface, name='eth1')) == ''
    assert tree_child_refusal(sub, _new(Interface, name='eth1')), 'no third level'
    assert tree_child_refusal(parent, _new(PhysAddress)) == ''
    assert tree_child_refusal(parent, _new(TCPService))


def test_a_cluster_takes_state_sync_groups_and_a_firewall_does_not():
    assert tree_child_refusal(_new(Cluster), _new(StateSyncClusterGroup)) == ''
    assert tree_child_refusal(_new(Firewall), _new(StateSyncClusterGroup))
