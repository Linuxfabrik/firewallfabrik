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

"""A rule naming a cluster interface is compiled against the member's own.

A cluster interface exists on no machine: the two members may call theirs
`eth0` and `eth3`, and the address it carries is the one the cluster
shares, held by whichever member is master right now.  Firewall Builder
therefore answers every question about it with the interface the member
firewall actually has - `Compiler::replaceClusterInterfaceInItfRE`
(Compiler.cpp:1102) in the interface rule element, and
`Compiler::correctForCluster` (Compiler.cpp:1800) wherever a chain
decision asks "is this the firewall".

`ReplaceClusterInterfaceInItfRE` was a no-op here: it looked for a
`subinterfaces` attribute the model does not have and for a
`get_interface_for_member` method that did not exist, so both tests were
always false and the element came out unchanged - `-i <cluster interface
name>` in the generated rule, matching nothing.
"""

import pathlib
import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import ReplaceClusterInterfaceInItfRE
from firewallfabrik.core.objects import Cluster, Direction, Firewall, PolicyAction

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    """Carries the one thing the substitution reads: which firewall it is."""

    def __init__(self, fw):
        self.fw = fw

    correct_for_cluster = Compiler.correct_for_cluster


def _rule(slot, objects):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
        direction=Direction.Both,
    )
    setattr(rule, slot, list(objects))
    return rule


@pytest.fixture(scope='module')
def tree():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    return dm


def _objects(session):
    cluster = session.scalars(
        sqlalchemy.select(Cluster).where(Cluster.name == 'vrrp_cluster_1'),
    ).one()
    member = session.scalars(
        sqlalchemy.select(Firewall).where(Firewall.name == 'linux-2'),
    ).one()
    cluster_iface = next(i for i in cluster.interfaces if i.name == 'eth1')
    return cluster, member, cluster_iface


def test_the_interface_element_names_the_member_interface(tree):
    with tree.session() as session:
        _, member, cluster_iface = _objects(session)
        rule = _rule('itf', [cluster_iface])

        proc = ReplaceClusterInterfaceInItfRE('replace', 'itf')
        proc.set_context(_Compiler(member))
        proc.set_data_source(_Feeder([rule]))
        assert proc.process_next() is True

        (out,) = proc.tmp_queue
        (iface,) = out.itf
        assert iface.id != cluster_iface.id
        assert iface.device_id == member.id


def test_an_interface_of_a_cluster_this_firewall_is_not_in_is_left_alone(tree):
    with tree.session() as session:
        _, _, cluster_iface = _objects(session)
        outsider = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == 'linux-3'),
        ).one()
        rule = _rule('itf', [cluster_iface])

        proc = ReplaceClusterInterfaceInItfRE('replace', 'itf')
        proc.set_context(_Compiler(outsider))
        proc.set_data_source(_Feeder([rule]))
        proc.process_next()

        (out,) = proc.tmp_queue
        assert [o.id for o in out.itf] == [cluster_iface.id]


def test_correct_for_cluster_answers_with_the_member_interface(tree):
    with tree.session() as session:
        _, member, cluster_iface = _objects(session)

        answer = _Compiler(member).correct_for_cluster(cluster_iface)

        assert answer.device_id == member.id


def test_correct_for_cluster_leaves_an_ordinary_interface_alone(tree):
    with tree.session() as session:
        _, member, _ = _objects(session)
        own = member.interfaces[0]

        assert _Compiler(member).correct_for_cluster(own) is own
