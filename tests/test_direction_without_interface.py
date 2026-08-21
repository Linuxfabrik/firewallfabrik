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

"""How a rule says "inbound" when it names no interface.

The built-in input and output chains answer the question with their hook.
A branch rule set does not: its chain is reached from input *and* output,
so a rule marked "Outbound" there applies to incoming traffic as well
unless the rule says which direction it means.  Firewall Builder says it
by putting a group named ``*`` into the Itf element
(``PolicyCompiler_ipt::InterfaceAndDirection``), which the print rule
writes as ``-i +`` / ``-o +``.  nftables refuses ``iifname "*"``
outright, so it asks ``meta iif`` for a device index instead.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Direction, Interface, PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import (
    InterfaceAndDirection as InterfaceAndDirection_ipt,
)
from firewallfabrik.platforms.linux._netfilter import ANY_INTERFACE
from firewallfabrik.platforms.nftables._policy_compiler import (
    InterfaceAndDirection as InterfaceAndDirection_nft,
)


class _Source:
    def __init__(self, rules):
        self._rules = list(rules)

    def get_next_rule(self):
        return self._rules.pop(0) if self._rules else None


def _rule(direction, itf=None, chain=''):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
        direction=direction,
    )
    rule.itf = [itf] if itf is not None else []
    rule.ipt_chain = chain
    return rule


def _interface(name='eth0'):
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = name
    iface.data = {}
    iface.options = {}
    return iface


def _run(cls, rule):
    processor = cls(name='fill in interface and direction')
    processor.prev_processor = _Source([rule])
    assert processor.process_next() is True
    return processor.tmp_queue[0]


PROCESSORS = [InterfaceAndDirection_ipt, InterfaceAndDirection_nft]
IDS = ['ipt', 'nft']


@pytest.mark.parametrize('cls', PROCESSORS, ids=IDS)
@pytest.mark.parametrize('direction', [Direction.Inbound, Direction.Outbound])
def test_a_direction_without_an_interface_names_every_interface(cls, direction):
    assert _run(cls, _rule(direction)).itf == [ANY_INTERFACE]


@pytest.mark.parametrize('cls', PROCESSORS, ids=IDS)
def test_a_rule_in_both_directions_names_none(cls):
    rule = _run(cls, _rule(Direction.Both))
    assert rule.itf == []
    assert rule.iface_label == 'nil'


@pytest.mark.parametrize('cls', PROCESSORS, ids=IDS)
def test_a_rule_that_names_an_interface_keeps_it(cls):
    iface = _interface()
    rule = _run(cls, _rule(Direction.Inbound, iface))
    assert rule.itf == [iface]
    assert rule.iface_label == 'eth0'


def test_every_interface_is_not_an_interface():
    """Every ``Interface::cast`` in the C++ answers null for the group."""
    assert not isinstance(ANY_INTERFACE, Interface)
    assert ANY_INTERFACE.name == '*'


def test_the_iptables_printer_writes_the_wildcard():
    from firewallfabrik.platforms.iptables._print_rule import PrintRule

    printer = PrintRule()
    rule = _rule(Direction.Inbound, ANY_INTERFACE, chain='mail_in')
    assert printer._print_direction_and_interface(rule).strip() == '-i +'

    rule = _rule(Direction.Outbound, ANY_INTERFACE, chain='mail_in')
    assert printer._print_direction_and_interface(rule).strip() == '-o +'


def test_the_nftables_printer_asks_for_a_device_index():
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    printer = PrintRule_nft()
    rule = _rule(Direction.Inbound, ANY_INTERFACE, chain='mail_in')
    assert printer._print_interface(rule) == 'meta iif != 0'

    rule = _rule(Direction.Outbound, ANY_INTERFACE, chain='mail_in')
    assert printer._print_interface(rule) == 'meta oif != 0'


@pytest.mark.parametrize(
    ('direction', 'chain'),
    [
        (Direction.Inbound, 'input'),
        (Direction.Inbound, 'forward'),
        (Direction.Inbound, 'prerouting'),
        (Direction.Outbound, 'output'),
        (Direction.Outbound, 'forward'),
        (Direction.Outbound, 'postrouting'),
    ],
)
def test_the_nftables_printer_leaves_out_what_the_hook_answers(direction, chain):
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    printer = PrintRule_nft()
    rule = _rule(direction, ANY_INTERFACE, chain=chain)
    assert printer._print_interface(rule) == ''


def test_the_nftables_printer_keeps_it_where_the_hook_does_not():
    """A locally generated packet reaches postrouting with no incoming device."""
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    printer = PrintRule_nft()
    rule = _rule(Direction.Inbound, ANY_INTERFACE, chain='postrouting')
    assert printer._print_interface(rule) == 'meta iif != 0'
