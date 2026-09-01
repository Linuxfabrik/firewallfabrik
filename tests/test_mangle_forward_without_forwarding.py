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

"""A mangle rule that lands in the forward chain of a box that forwards nothing.

``PolicyCompiler_ipt::finalizeChain`` writes the "unnecessary FORWARD
rules" check (its bug #1040599) *below* both of its branches, so it
applies to the mangle pass as well: a rule whose direction is "both" keeps
the forward chain it was given at the top, and on a firewall whose IP
forwarding is switched off there is no traffic for it to see.

The nftables port returned from the mangle branch before reaching the
check, so the two platforms disagreed about that one rule.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import (
    FinalizeChain as FinalizeChain_ipt,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    FinalizeChain as FinalizeChain_nft,
)


class _Firewall:
    id = uuid.uuid4()
    name = 'fw'
    interfaces: list = []

    def __init__(self, forwards: bool) -> None:
        self._forwards = forwards

    def get_option(self, key, default=None):
        if key == 'bridging_fw':
            return False
        if key in ('linux24_ip_forward', 'linux24_ipv6_forward'):
            return '1' if self._forwards else '0'
        return default


class _Compiler:
    def __init__(self, forwards: bool, table: str) -> None:
        self.fw = _Firewall(forwards)
        self.my_table = table
        self.ipv6_policy = False
        self.messages: list[str] = []

    def correct_for_cluster(self, obj):
        return obj

    def complex_match(self, *_args, **_kwargs) -> bool:
        return False

    def set_chain(self, rule, chain) -> None:
        rule.ipt_chain = chain

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    error = warning
    abort = warning


class _Feeder(BasicRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _rule() -> CompRule:
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={'tagging': True},
        negations={},
        action=PolicyAction.Deny,
        direction=Direction.Both,
    )


def _run(processor_class, forwards: bool, table: str):
    compiler = _Compiler(forwards, table)
    proc = processor_class(name='finalize chain')
    proc.compiler = compiler
    proc.set_data_source(_Feeder(_rule()))
    proc.process_next()
    return list(proc.tmp_queue), compiler.messages


@pytest.mark.parametrize(
    'processor', [FinalizeChain_ipt, FinalizeChain_nft], ids=['ipt', 'nft']
)
@pytest.mark.parametrize('table', ['filter', 'mangle'])
def test_a_forward_rule_goes_when_the_box_does_not_forward(processor, table):
    emitted, messages = _run(processor, forwards=False, table=table)

    assert emitted == []
    assert messages and 'not to forward packets' in messages[0]


@pytest.mark.parametrize(
    'processor', [FinalizeChain_ipt, FinalizeChain_nft], ids=['ipt', 'nft']
)
@pytest.mark.parametrize('table', ['filter', 'mangle'])
def test_a_forwarding_firewall_keeps_the_rule(processor, table):
    emitted, messages = _run(processor, forwards=True, table=table)

    assert len(emitted) == 1
    assert emitted[0].ipt_chain.lower() == 'forward'
    assert messages == []
