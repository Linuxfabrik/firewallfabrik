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

"""Optimize1 counts the time interval as a fourth rule element.

``PolicyCompiler_ipt::optimize1`` reads four elements, not three, and its
own regression output shows both halves of that: a rule with one interval
carries ``-m time`` on the jump rule alone (``optitest`` test 13), and a
rule with two intervals gets a chain of its own reached by one jump per
interval (``$IPTABLES -A Cid41453516.0 -m time ... -j Cid41453516.1``,
twice).  Repeating the interval on every level of the cascade is what
``ConvertToAtomicForIntervals`` then multiplies, so the level count grows
with the number of intervals.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import Optimize1


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self):
        self.chains = []
        self._n = 0

    def get_new_tmp_chain_name(self, rule):
        self._n += 1
        return f'Ctest.{self._n - 1}'

    def register_chain(self, chain):
        self.chains.append(chain)

    def insert_upstream_chain(self, this_chain, new_chain):
        pass


def _rule(src=(), dst=(), srv=(), when=()):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    rule.src = list(src)
    rule.dst = list(dst)
    rule.srv = list(srv)
    rule.when = list(when)
    rule.ipt_chain = 'FORWARD'
    return rule


def _optimize(rule):
    proc = Optimize1(name='Optimize1')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return list(proc.tmp_queue)


def test_a_single_interval_stays_on_the_jump_rule():
    out = _optimize(_rule(dst=['10.0.0.1', '10.0.0.2', '10.0.0.3'], when=['office']))
    assert len(out) == 2
    jump, detail = out
    assert jump.when == ['office']
    assert detail.when == []


def test_several_intervals_are_factored_into_one_chain():
    """Two intervals against three destinations and four services.

    The interval is then the cheapest element to split on, which is the
    branch fwbuilder has and the port did not.
    """
    out = _optimize(
        _rule(
            dst=['10.0.0.1', '10.0.0.2', '10.0.0.3'],
            srv=['http', 'https', 'ssh', 'smtp'],
            when=['morning', 'evening'],
        )
    )
    jump, detail = out
    assert jump.when == ['morning', 'evening']
    assert detail.when == []
    assert jump.dst == []
    assert detail.dst == ['10.0.0.1', '10.0.0.2', '10.0.0.3']


def test_an_interval_that_is_not_the_split_leaves_the_jump_rule():
    """Two intervals, one destination: the destination is the cheaper split.

    The interval then belongs to the rule in the temporary chain, so that a
    later pass can still factor it out there.
    """
    out = _optimize(
        _rule(
            dst=['10.0.0.1'],
            srv=['http', 'https', 'ssh'],
            when=['morning', 'evening'],
        )
    )
    jump, detail = out
    assert jump.when == []
    assert detail.when == ['morning', 'evening']


def test_an_interval_not_being_split_on_leaves_the_detail_rule():
    """Otherwise every level of the cascade repeats the same -m time."""
    out = _optimize(
        _rule(
            src=['10.0.0.1', '10.0.0.2'], dst=['10.0.1.1', '10.0.1.2'], when=['office']
        )
    )
    jump, detail = out
    assert jump.when == ['office']
    assert detail.when == []


def test_a_rule_without_a_time_restriction_is_unchanged():
    """An "any" interval must not make a one-object rule look splittable."""
    out = _optimize(_rule(src=['10.0.0.1'], dst=['10.0.1.1'], srv=['http']))
    assert len(out) == 1
