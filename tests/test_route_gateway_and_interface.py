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

"""A route has one gateway and leaves through one interface.

Firewall Builder's editor takes one object into each element
(``RuleElementRGtw::validateChild``, ``RuleElementRItf::validateChild``) and
its compiler refuses a gateway that is not one address
(``singleAdressInRGtw``).  The print rule here writes the first object of
each element, so a second gateway or interface vanished from the route, and
a network as the gateway compiled into ``via 192.0.2.0/24``, which iproute2
refuses when the script runs.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import (
    AddressRange,
    Interface,
    IPv4,
    IPv6,
    Network,
    ObjectGroup,
    RoutingRuleType,
)
from firewallfabrik.platforms.linux._routing_compiler import (
    RItfChildOfFw,
    SingleAddressInRGtw,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    fw = None

    def __init__(self):
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(**slots):
    return CompRule(
        id=uuid.uuid4(),
        type='RoutingRule',
        position=0,
        label='0',
        comment='',
        options={},
        negations={},
        routing_rule_type=RoutingRuleType.SinglePath,
        **slots,
    )


def _run(processor_cls, rule):
    compiler = _Compiler()
    proc = processor_cls(name='under test')
    proc.set_context(compiler)
    proc.prev_processor = _Feeder([rule])
    while proc.process_next():
        pass
    return list(proc.tmp_queue), compiler.messages


def _addr(cls, address, netmask):
    return cls(
        id=uuid.uuid4(),
        name=f'{cls.__name__}-{address}',
        inet_addr_mask={'address': address, 'netmask': netmask},
    )


@pytest.mark.parametrize(
    'gateway',
    [
        _addr(IPv4, '192.0.2.1', '255.255.255.255'),
        _addr(IPv6, '2001:db8::1', '128'),
        _addr(Network, '192.0.2.1', '255.255.255.255'),
    ],
    ids=['IPv4', 'IPv6', 'host network'],
)
def test_one_address_is_a_gateway(gateway):
    passed, messages = _run(SingleAddressInRGtw, _rule(rgtw=[gateway]))
    assert len(passed) == 1
    assert messages == []


def test_two_gateways_are_refused():
    rule = _rule(
        rgtw=[
            _addr(IPv4, '192.0.2.1', '255.255.255.255'),
            _addr(IPv4, '192.0.2.2', '255.255.255.255'),
        ]
    )
    passed, messages = _run(SingleAddressInRGtw, rule)
    assert passed == []
    assert 'A route has one gateway, but the rule names 2' in messages[0]


@pytest.mark.parametrize(
    'gateway',
    [
        _addr(Network, '192.0.2.0', '255.255.255.0'),
        AddressRange(id=uuid.uuid4(), name='range'),
        ObjectGroup(id=uuid.uuid4(), name='group'),
    ],
    ids=['network', 'range', 'group'],
)
def test_anything_but_one_address_is_refused_as_a_gateway(gateway):
    passed, messages = _run(SingleAddressInRGtw, _rule(rgtw=[gateway]))
    assert passed == []
    assert 'is not a single address, host or interface' in messages[0]


def test_two_route_interfaces_are_refused():
    rule = _rule(
        ritf=[
            Interface(id=uuid.uuid4(), name='eth1'),
            Interface(id=uuid.uuid4(), name='eth2'),
        ]
    )
    passed, messages = _run(RItfChildOfFw, rule)
    assert passed == []
    assert 'leaves through one interface, but the rule names 2' in messages[0]
