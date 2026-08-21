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

"""The four guards in front of "outbound, and the firewall is the destination".

A packet that is not from the firewall and is addressed to it goes into
the input chain and is never forwarded, so it cannot cross an interface
outbound: a rule written that way would never see it and
``PolicyCompiler_ipt::specialCaseWithFWInDstAndOutbound`` drops it.

It drops it *silently*, which is why the guards matter more than the
rule. The nftables copy had three of the four missing while its docstring
described them, and rule 1 of ``test_fw``'s OSPF branch - "outbound to
ff00::/8", the multicast group OSPF talks to - disappeared from the
nftables ruleset while staying in the iptables one, with nothing said
anywhere.
"""

import uuid

import pytest

from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.compiler.processors._policy import (
    SpecialCaseWithFWInDstAndOutbound,
)
from firewallfabrik.core.objects import (
    Direction,
    Firewall,
    Interface,
    IPv4,
    Network,
)


def _address(cls, address, netmask, name='probe'):
    obj = cls(id=uuid.uuid4(), name=name)
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


@pytest.fixture
def firewall():
    fw = Firewall(id=uuid.uuid4(), name='fw-test')
    eth0 = Interface(id=uuid.uuid4(), name='eth0')
    addr = _address(IPv4, '192.168.1.1', '255.255.255.0', 'fw-test:eth0:ip')
    addr.interface_id = eth0.id
    eth0.addresses = [addr]
    eth0.device_id = fw.id
    fw.interfaces = [eth0]
    # `get_option` resolves an absent key against the platform's
    # defaults.yaml, so the firewall has to name a platform.
    fw.data = {'platform': 'iptables', 'host_OS': 'linux24'}
    fw.options = {}
    return fw


class _Rule:
    type = 'PolicyRule'

    def __init__(self, itf, src, dst, chain='FORWARD') -> None:
        self.direction = Direction.Outbound
        self.itf = [itf] if itf is not None else []
        self.src = [src] if src is not None else []
        self.dst = [dst] if dst is not None else []
        self.ipt_chain = chain
        self.src_single_object_negation = False
        self.options: dict = {}
        self._neg: dict = {}

    def get_neg(self, slot):
        return self._neg.get(slot, False)

    def get_option(self, key, default=None):
        return self.options.get(key, default)

    def is_src_any(self):
        return not self.src

    def is_dst_any(self):
        return not self.dst


class _Feeder(PolicyRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _kept(firewall, rule):
    compiler = Compiler.__new__(Compiler)
    compiler.fw = firewall
    proc = SpecialCaseWithFWInDstAndOutbound('drop outbound with fw in dst')
    proc.compiler = compiler
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    return bool(proc.tmp_queue)


def test_the_case_it_exists_for(firewall):
    """Outbound, to the firewall's own address, from somebody else."""
    rule = _Rule(
        firewall.interfaces[0],
        _address(IPv4, '192.168.1.7', '255.255.255.255'),
        _address(IPv4, '192.168.1.1', '255.255.255.255'),
    )
    assert not _kept(firewall, rule)


def test_a_network_is_not_the_firewall_unless_it_is_asked_to_be(firewall):
    """The guard that keeps ``test_fw``'s OSPF rule.

    With "assume firewall is part of any and networks" off - the default -
    a network object is not the firewall unless its mask covers a single
    address, whatever the multicast shortcut of ``complexMatch`` answers.
    """
    rule = _Rule(
        firewall.interfaces[0],
        _address(IPv4, '198.51.100.0', '255.255.255.0'),
        _address(Network, '224.0.0.0', '240.0.0.0', 'all-multicasts'),
    )
    assert _kept(firewall, rule)

    rule.options['firewall_is_part_of_any_and_networks'] = True
    assert not _kept(firewall, rule)


def test_a_bridging_firewall_forwards_a_broadcast(firewall):
    rule = _Rule(
        firewall.interfaces[0],
        _address(IPv4, '192.168.1.7', '255.255.255.255'),
        _address(IPv4, '255.255.255.255', '255.255.255.255'),
    )
    assert not _kept(firewall, rule)

    firewall.options = {'bridging_fw': True}
    assert _kept(firewall, rule)


def test_a_negated_source_may_be_the_firewall(firewall):
    rule = _Rule(
        firewall.interfaces[0],
        _address(IPv4, '192.168.1.7', '255.255.255.255'),
        _address(IPv4, '192.168.1.1', '255.255.255.255'),
    )
    rule._neg['src'] = True
    assert _kept(firewall, rule)


def test_an_interface_of_another_device_is_not_this_firewall_s(firewall):
    """``itf->isChildOf(compiler->fw)``, which the nftables copy left out."""
    foreign = Interface(id=uuid.uuid4(), name='eth0')
    foreign.device_id = uuid.uuid4()
    rule = _Rule(
        foreign,
        _address(IPv4, '192.168.1.7', '255.255.255.255'),
        _address(IPv4, '192.168.1.1', '255.255.255.255'),
    )
    assert _kept(firewall, rule)


@pytest.mark.parametrize('chain', ['OUTPUT', 'output'])
def test_the_output_chain_is_where_such_a_rule_belongs(firewall, chain):
    """iptables spells it OUTPUT and nftables output; both mean the same."""
    rule = _Rule(
        firewall.interfaces[0],
        _address(IPv4, '192.168.1.7', '255.255.255.255'),
        _address(IPv4, '192.168.1.1', '255.255.255.255'),
        chain=chain,
    )
    assert _kept(firewall, rule)
