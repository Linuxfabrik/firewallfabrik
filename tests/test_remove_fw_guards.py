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

"""When the firewall object may be dropped from a rule, and when not.

`removeFW` exists to turn "to the firewall, port 22" in the input chain
into a rule with no destination at all, which is shorter and means the
same - but only while the firewall object really stands for every address
the firewall answers on.  `PolicyCompiler_ipt::removeFW` names the two
cases where it does not, citing fwbuilder bug #685947: a script that adds
virtual addresses for NAT, and a rule that came out of a negation
expansion.  Dropping the object in the first case opens the NAT addresses
to everything the rule permits.
"""

import uuid
from collections import defaultdict

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import RemoveFW
from firewallfabrik.platforms.nftables._policy_compiler import RemoveFW as RemoveFWNft


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Firewall:
    id = uuid.uuid4()
    name = 'fw-test'


class _OSConfigurator:
    def __init__(self, virtual_addresses=()):
        self.virtual_addresses = list(virtual_addresses)


class _Compiler:
    fw = _Firewall()

    def __init__(self, virtual_addresses=()):
        self.oscnf = _OSConfigurator(virtual_addresses)
        self.upstream_chains: dict[str, list[str]] = defaultdict(list)

    def is_chain_descendant_of_input(self, chain):
        return chain.startswith('In_')

    def is_chain_descendant_of_output(self, chain):
        return chain.startswith('Out_')

    # Both compilers ask which hook a chain hangs off, not what it is
    # called, so the stub answers with the real implementation.
    is_chain_descendant_of = Compiler.is_chain_descendant_of
    insert_upstream_chain = Compiler.insert_upstream_chain

    # The real one, not a stub: what counts as the firewall is the whole
    # question this processor asks, and a cluster counts too.
    is_firewall_or_cluster = Compiler.is_firewall_or_cluster


class _FwObject:
    id = _Firewall.id
    name = 'fw-test'


def _run(cls, compiler, chain, **kwargs):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=kwargs.pop('options', {}),
        negations={},
        action=PolicyAction.Accept,
    )
    rule.ipt_chain = chain
    rule.dst = [_FwObject()]
    for key, value in kwargs.items():
        setattr(rule, key, value)
    proc = cls(name='removeFW')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return proc.tmp_queue[0]


def test_the_firewall_object_goes_when_nothing_speaks_against_it():
    out = _run(RemoveFW, _Compiler(), 'INPUT')
    assert out.dst == []


def test_a_temporary_chain_below_input_counts_as_input():
    out = _run(RemoveFW, _Compiler(), 'In_RULE_0')
    assert out.dst == []


def test_a_virtual_address_for_nat_keeps_the_firewall_object():
    """Otherwise the rule permits the whole world to the NAT addresses."""
    out = _run(RemoveFW, _Compiler(virtual_addresses=['192.168.1.10']), 'INPUT')
    assert len(out.dst) == 1


def test_a_rule_built_by_a_negation_expansion_keeps_it():
    out = _run(RemoveFW, _Compiler(), 'INPUT', options={'upstream_rule_neg': True})
    assert len(out.dst) == 1


def test_nftables_keeps_it_for_a_virtual_address_too():
    out = _run(RemoveFWNft, _Compiler(virtual_addresses=['192.168.1.10']), 'input')
    assert len(out.dst) == 1
    assert _run(RemoveFWNft, _Compiler(), 'input').dst == []


def test_a_temporary_chain_below_input_counts_as_input_on_nftables():
    """`TimeNegation` and the log split leave the rule in a chain of their own.

    The chain is named after neither hook, so asking for the name kept the
    firewall object in the destination of a rule the input hook reaches -
    a longer rule than the one the iptables compiler writes for the same
    policy.
    """
    compiler = _Compiler()
    compiler.insert_upstream_chain('input', 'C0123456789ab.0')
    assert _run(RemoveFWNft, compiler, 'C0123456789ab.0').dst == []


def test_a_temporary_chain_below_forward_keeps_the_firewall_object():
    compiler = _Compiler()
    compiler.insert_upstream_chain('forward', 'C0123456789ab.0')
    assert len(_run(RemoveFWNft, compiler, 'C0123456789ab.0').dst) == 1
