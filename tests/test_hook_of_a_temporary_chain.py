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

"""What a match is allowed to do is decided by the hook, not by the chain.

Three passes of ``Optimize1`` run in front of the checks that ask which
chain a rule ended up in, and each of them may have moved the rule into a
temporary chain that a built-in one jumps to.  The kernel decides by the
hook the chain hangs off, so a match that is refused in POSTROUTING is
refused in every chain POSTROUTING can reach - and one that is allowed in
OUTPUT is allowed there too.

``xt_mac`` registers for PREROUTING, INPUT and FORWARD
(netfilter ``net/netfilter/xt_mac.c``) and ``xt_owner`` for OUTPUT and
POSTROUTING (``net/netfilter/xt_owner.c``).  Firewall Builder asks the
chain name in both places and has the same blind spot.

The nftables compiler grew temporary chains of its own with the negated
time interval and the log split, so the two checks there ask the same
question and get it wrong the same way.  Its chain names are lowercase
and ``ether saddr`` is refused in the output chain alone - a forwarded
packet still carries the header it arrived with.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PhysAddress, UserService
from firewallfabrik.platforms.iptables._nat_compiler import (
    CheckUserServiceInWrongChains as CheckUserServiceInWrongChains_nat,
)
from firewallfabrik.platforms.iptables._nat_compiler import (
    VerifyRuleWithMAC as VerifyRuleWithMAC_nat,
)
from firewallfabrik.platforms.iptables._policy_compiler import (
    CheckMACInOUTPUTChain,
    CheckUserServiceInWrongChains,
    PolicyCompiler_ipt,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    CheckMACInOUTPUTChain as CheckMACInOUTPUTChain_nft,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    CheckUserServiceInWrongChains as CheckUserServiceInWrongChains_nft,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    """Only the chain bookkeeping the two checks read."""

    is_chain_descendant_of = PolicyCompiler_ipt.is_chain_descendant_of
    is_chain_descendant_of_output = PolicyCompiler_ipt.is_chain_descendant_of_output

    def __init__(self, jumps=()):
        self.upstream_chains: dict[str, list[str]] = {}
        for parent, child in jumps:
            self.upstream_chains.setdefault(parent, []).append(child)
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    abort = error
    warning = error


def _nat_rule(chain, osrv=()):
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0 (NAT)',
        comment='',
        options={},
        negations={},
    )
    rule.ipt_chain = chain
    rule.osrv = list(osrv)
    rule.osrc = []
    return rule


def _rule(chain, src=(), srv=()):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
    )
    rule.ipt_chain = chain
    rule.src = list(src)
    rule.srv = list(srv)
    return rule


def _run(processor_class, rule, compiler):
    proc = processor_class(name=processor_class.__name__)
    proc.set_context(compiler)
    proc.prev_processor = _Feeder([rule])
    emitted = []
    while proc.process_next():
        while proc.tmp_queue:
            emitted.append(proc.tmp_queue.popleft())
    return emitted


def test_a_chain_is_found_through_several_jumps():
    compiler = _Compiler([('POSTROUTING', 'C1.0'), ('C1.0', 'C2.0')])

    assert compiler.is_chain_descendant_of('C2.0', 'POSTROUTING')
    assert not compiler.is_chain_descendant_of('C2.0', 'OUTPUT')


def test_every_parent_is_followed_not_only_the_first():
    """A chain can be reached from more than one place."""
    compiler = _Compiler([('FORWARD', 'C1.0'), ('OUTPUT', 'C1.0')])

    assert compiler.is_chain_descendant_of('C1.0', 'OUTPUT')
    assert compiler.is_chain_descendant_of('C1.0', 'FORWARD')


def test_a_jump_graph_that_leads_back_on_itself_does_not_loop():
    compiler = _Compiler([('C1.0', 'C2.0'), ('C2.0', 'C1.0')])

    assert not compiler.is_chain_descendant_of('C1.0', 'INPUT')


@pytest.mark.parametrize('chain', ['POSTROUTING', 'C1.0'])
def test_a_mac_below_postrouting_is_reported(chain):
    """The temporary chain is what `Optimize1` leaves the rule in."""
    compiler = _Compiler([('POSTROUTING', 'C1.0')])
    mac = PhysAddress(name='host-with-mac:1-pa')
    emitted = _run(CheckMACInOUTPUTChain, _rule(chain, src=[mac]), compiler)

    assert emitted == []
    assert compiler.messages
    assert 'POSTROUTING' in compiler.messages[0]


def test_a_mac_below_prerouting_is_left_alone():
    compiler = _Compiler([('PREROUTING', 'C1.0')])
    mac = PhysAddress(name='host-with-mac:1-pa')
    emitted = _run(CheckMACInOUTPUTChain, _rule('C1.0', src=[mac]), compiler)

    assert len(emitted) == 1
    assert compiler.messages == []


def test_a_user_service_below_postrouting_is_kept():
    """`xt_owner` allows POSTROUTING, so the rule must not be dropped."""
    compiler = _Compiler([('POSTROUTING', 'C1.0')])
    srv = UserService(name='some-user')
    emitted = _run(CheckUserServiceInWrongChains, _rule('C1.0', srv=[srv]), compiler)

    assert len(emitted) == 1
    assert compiler.messages == []


def test_a_user_service_below_forward_is_reported():
    compiler = _Compiler([('FORWARD', 'C1.0')])
    srv = UserService(name='some-user')
    emitted = _run(CheckUserServiceInWrongChains, _rule('C1.0', srv=[srv]), compiler)

    assert emitted == []
    assert compiler.messages


def test_the_nftables_mac_check_asks_the_hook_too():
    """`TimeNegation` there moves the rule into a chain of its own."""
    compiler = _Compiler([('output', 'C1.0')])
    mac = PhysAddress(name='host-with-mac:1-pa')
    emitted = _run(CheckMACInOUTPUTChain_nft, _rule('C1.0', src=[mac]), compiler)

    assert emitted == []
    assert compiler.messages
    assert 'output' in compiler.messages[0]


def test_the_nftables_mac_check_leaves_a_forwarded_packet_alone():
    compiler = _Compiler([('forward', 'C1.0')])
    mac = PhysAddress(name='host-with-mac:1-pa')
    emitted = _run(CheckMACInOUTPUTChain_nft, _rule('C1.0', src=[mac]), compiler)

    assert len(emitted) == 1
    assert compiler.messages == []


def test_the_nftables_user_service_below_output_is_kept():
    """Dropping it takes away a rule the hook can carry."""
    compiler = _Compiler([('output', 'C1.0')])
    srv = UserService(name='some-user')
    emitted = _run(
        CheckUserServiceInWrongChains_nft, _rule('C1.0', srv=[srv]), compiler
    )

    assert len(emitted) == 1
    assert compiler.messages == []


def test_the_nftables_user_service_below_input_is_reported():
    compiler = _Compiler([('input', 'C1.0')])
    srv = UserService(name='some-user')
    emitted = _run(
        CheckUserServiceInWrongChains_nft, _rule('C1.0', srv=[srv]), compiler
    )

    assert emitted == []
    assert compiler.messages


def test_the_nat_owner_check_asks_the_hook_too():
    """`DoOSrcNegation` moves the rule into a chain before one is decided.

    `-m owner` in a chain the nat prerouting hook reaches is refused by
    the kernel with -EINVAL, and the command iptables then reports stops
    the activation script with the policies already at DROP.
    """
    compiler = _Compiler([('PREROUTING', 'C1.0')])
    srv = UserService(name='some-user')
    emitted = _run(
        CheckUserServiceInWrongChains_nat, _nat_rule('C1.0', osrv=[srv]), compiler
    )

    assert emitted == []
    assert compiler.messages


def test_the_nat_owner_check_keeps_a_rule_below_postrouting():
    compiler = _Compiler([('POSTROUTING', 'C1.0')])
    srv = UserService(name='some-user')
    emitted = _run(
        CheckUserServiceInWrongChains_nat, _nat_rule('C1.0', osrv=[srv]), compiler
    )

    assert len(emitted) == 1
    assert compiler.messages == []


def test_the_nat_mac_check_asks_the_hook_too():
    compiler = _Compiler([('PREROUTING', 'C1.0')])
    rule = _nat_rule('C1.0')
    rule.osrc = [PhysAddress(name='host-with-mac:1-pa')]
    emitted = _run(VerifyRuleWithMAC_nat, rule, compiler)

    assert len(emitted) == 1
    assert compiler.messages == []
