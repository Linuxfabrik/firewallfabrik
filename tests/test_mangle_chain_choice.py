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

"""Which mangle chain a rule ends up in when nothing has claimed it.

The direction decides it - inbound traffic is seen in prerouting, outbound
in postrouting - except for an accepting rule, which fwbuilder puts in
prerouting whatever its direction says
(PolicyCompiler_ipt::finalizeChain).  Prerouting is the first mangle hook
a packet crosses, so an accept there covers every path through the box.

No firewall in the test corpus reaches this, because
`ClearActionInTagClassifyIfMangle` turns the action into Continue for
every rule that tags or classifies; it is reachable from a mangle-only
rule set.  Hence the unit test.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import (
    FinalizeChain as FinalizeChainIpt,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    FinalizeChain as FinalizeChainNft,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Firewall:
    id = uuid.uuid4()

    def get_option(self, key, default=None):
        # "no change", i.e. the firewall forwards.
        return ''


class _Compiler:
    my_table = 'mangle'
    ipv6_policy = False

    def __init__(self) -> None:
        self.fw = _Firewall()

    @staticmethod
    def set_chain(rule, chain):
        rule.ipt_chain = chain

    @staticmethod
    def complex_match(*_args, **_kwargs):
        return False

    def warning(self, _rule, msg: str = '') -> None:
        pass


def _chain(processor_cls, action, direction):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=action,
    )
    rule.direction = direction
    proc = processor_cls(name='FinalizeChain')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return rule.ipt_chain


@pytest.mark.parametrize(
    ('direction', 'expected'),
    [
        (Direction.Inbound, 'PREROUTING'),
        (Direction.Outbound, 'POSTROUTING'),
        (Direction.Both, 'FORWARD'),
    ],
)
def test_direction_decides_for_a_non_accepting_rule(direction, expected):
    assert _chain(FinalizeChainIpt, PolicyAction.Deny, direction) == expected


@pytest.mark.parametrize(
    'direction', [Direction.Inbound, Direction.Outbound, Direction.Both]
)
def test_an_accepting_rule_goes_to_prerouting_whatever_its_direction(direction):
    assert _chain(FinalizeChainIpt, PolicyAction.Accept, direction) == 'PREROUTING'


@pytest.mark.parametrize(
    'direction', [Direction.Inbound, Direction.Outbound, Direction.Both]
)
def test_nftables_says_the_same(direction):
    assert _chain(FinalizeChainNft, PolicyAction.Accept, direction) == 'prerouting'
