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

"""A bridging firewall needs the forward copy of a rule about itself.

Traffic to an address of a bridging firewall reaches it through the
forward chain whenever it arrives over a bridged path, and through the
input chain when it arrives over a routing interface.  A rule that names
no interface cannot tell the two apart, so
`PolicyCompiler_ipt::decideOnChainIfDstFW` emits both copies (fwbuilder
bugs #811860, #934949 and #1231); its own reference output carries them
(`firewall23.fw.orig:426` and `:434`).  Without the forward copy a rule
written to permit SSH to the firewall drops it on every bridged path.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import Direction, Interface, PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import (
    DecideOnChainIfDstFW,
    DecideOnChainIfSrcFW,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    DecideOnChainIfDstFW as DecideOnChainIfDstFWNft,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Firewall:
    name = 'fw-test'

    def __init__(self, bridging):
        self._bridging = bridging

    def get_option(self, key):
        if key == 'bridging_fw':
            return self._bridging
        return False


class _Compiler:
    def __init__(self, bridging=True, matches=True):
        self.fw = _Firewall(bridging)
        self._matches = matches

    def complex_match(self, obj, fw, recognize_broadcasts=False, **kwargs):
        return self._matches

    @staticmethod
    def set_chain(rule, chain):
        rule.ipt_chain = chain


class _Address:
    id = uuid.uuid4()
    name = 'fw-address'


def _Interface(bridge_port):
    """A real Interface: the compilers ask ``Interface::cast``, not duck typing."""
    iface = Interface()
    iface.id = uuid.uuid4()
    iface.name = 'eth0'
    iface.data = {}
    iface.options = {'bridge_port': bridge_port}
    return iface


def _run(cls, compiler, slot, itf=None):
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
    setattr(rule, slot, [_Address()])
    rule.itf = [itf] if itf is not None else []
    proc = cls(name='decide')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return [r.ipt_chain for r in proc.tmp_queue]


def test_a_bridging_firewall_gets_both_chains():
    assert _run(DecideOnChainIfDstFW, _Compiler(), 'dst') == ['FORWARD', 'INPUT']
    assert _run(DecideOnChainIfSrcFW, _Compiler(), 'src') == ['FORWARD', 'OUTPUT']


def test_a_routing_firewall_gets_the_input_chain_alone():
    assert _run(DecideOnChainIfDstFW, _Compiler(bridging=False), 'dst') == ['INPUT']


def test_a_rule_on_a_routing_interface_is_not_duplicated():
    """Only a rule with no interface or one on a bridge port is split."""
    compiler = _Compiler()
    assert _run(DecideOnChainIfDstFW, compiler, 'dst', _Interface(False)) == ['INPUT']
    assert _run(DecideOnChainIfDstFW, compiler, 'dst', _Interface(True)) == [
        'FORWARD',
        'INPUT',
    ]


@pytest.mark.parametrize('bridging', [True, False])
def test_nftables_does_the_same(bridging):
    expected = ['forward', 'input'] if bridging else ['input']
    assert (
        _run(DecideOnChainIfDstFWNft, _Compiler(bridging=bridging), 'dst') == expected
    )
