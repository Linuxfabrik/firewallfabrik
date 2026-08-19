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

"""What Logging2 leaves on the two rules it puts in the log chain.

A logged rule becomes a jump rule plus a log rule and an action rule in a
chain of their own, and a packet crosses all three.  Every rate limit is a
token bucket, so a limit left on more than one of them is paid more than
once: with "20 per second" only ten packets reach the action, and packets
eleven to twenty match nothing at all.  fwbuilder clears all three limit
options on both rules inside the chain and leaves them on the jump rule
(PolicyCompiler_ipt::Logging2).  The same reasoning as
`test_ipt_optimize1_limits`, one processor further along.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import Logging2


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Firewall:
    name = 'fw-test'

    @staticmethod
    def get_option(key):
        return False


class _Compiler:
    """The bit of PolicyCompiler_ipt that Logging2 reaches for."""

    version = '1.8.11'
    fw = _Firewall()

    def get_new_chain_name(self, rule, iface):
        return 'In_RULE_1'

    def insert_upstream_chain(self, this_chain, new_chain):
        pass


def _logged(chain='INPUT', **elements):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options={
            'log': True,
            'limit_value': 20,
            'connlimit_value': 2,
            'hashlimit_value': 30,
        },
        negations={},
        action=PolicyAction.Deny,
    )
    rule.ipt_chain = chain
    for slot, value in elements.items():
        setattr(rule, slot, value)

    proc = Logging2(name='Logging2')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return list(proc.tmp_queue)


def test_the_limits_stay_on_the_jump_rule():
    jump, _log, _action = _logged(src=['10.0.0.1'])
    assert jump.get_option('limit_value') == 20
    assert jump.get_option('connlimit_value') == 2
    assert jump.get_option('hashlimit_value') == 30


def test_the_limits_are_cleared_inside_the_log_chain():
    _jump, log, action = _logged(src=['10.0.0.1'])
    for rule in (log, action):
        assert rule.get_option('limit_value') == -1
        assert rule.get_option('connlimit_value') == -1
        assert rule.get_option('hashlimit_value') == -1


def test_a_rule_already_in_that_chain_gets_no_jump_to_itself():
    """`-A X -j X` is a loop the kernel refuses, and the activation stops."""
    out = _logged(chain='In_RULE_1')
    assert len(out) == 2
    assert all(rule.ipt_chain == 'In_RULE_1' for rule in out)
    assert all(rule.ipt_target != 'In_RULE_1' for rule in out)
