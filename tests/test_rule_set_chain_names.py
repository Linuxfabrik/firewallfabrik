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

"""Two rule sets of one script may carry one name, and their chains may not.

Almost every firewall object owns a rule set called "Policy", and a Branch
rule may point at another firewall's, which is compiled into this script
beside our own.  Every chain name is derived from the rule set name, the
rule position and the subrule suffix, so without a further distinction the
chains the imported rule set builds are the chains the top rule set builds:
the two rule sets share a chain, and whichever rule is appended first
decides for both.  ``firewall33-1`` of the reference corpus is that case -
its Branch rule points at ``firewall33:Policy``.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import Direction
from firewallfabrik.platforms.iptables._nat_compiler import NATCompiler_ipt
from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.nftables._policy_compiler import PolicyCompiler_nft


class _RuleSet:
    def __init__(self, name):
        self.name = name


class _Namer:
    """The three naming methods, with only the state they read."""

    get_rule_set_name = Compiler.get_rule_set_name
    rule_set_key = Compiler.rule_set_key
    get_new_chain_name = PolicyCompiler_ipt.get_new_chain_name
    ipt_tmp_chain_name = PolicyCompiler_ipt.get_new_tmp_chain_name
    nat_tmp_chain_name = NATCompiler_ipt.get_new_tmp_chain_name
    nft_tmp_chain_name = PolicyCompiler_nft.get_new_tmp_chain_name

    def __init__(self, name, chain=''):
        self.source_ruleset = _RuleSet(name)
        self.rule_set_chain = chain
        self.tmp_chain_counters = {}
        self.temp_chains = set()
        self.chain_rules = {}


def _rule(position=13):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=position,
        label=f'{position} (global)',
        comment='',
        options={},
        negations={},
        direction=Direction.Both,
    )


def test_the_top_rule_set_keeps_the_short_spelling():
    """``getNewChainName`` writes RULE_<n> for the firewall's own policy."""
    top = _Namer('Policy')
    assert top.get_new_chain_name(_rule(), None) == 'RULE_13'


def test_a_rule_set_of_another_name_is_named_after_itself():
    branch = _Namer('web_server_outbound', chain='web_server_outbound')
    assert branch.get_new_chain_name(_rule(), None) == 'web_server_outbound_13'


def test_an_imported_rule_set_called_policy_does_not_take_rule_n():
    """The case ``firewall33-1`` is: a branch into another firewall's Policy.

    Firewall Builder asks whether the name is "Policy" and answers
    "RULE_" for both rule sets, so the imported set's Deny rule and the
    top set's rule build one chain.
    """
    top = _Namer('Policy')
    imported = _Namer('Policy', chain='Policy')
    assert imported.get_new_chain_name(_rule(), None) == 'Policy_13'
    assert imported.get_new_chain_name(_rule(), None) != top.get_new_chain_name(
        _rule(), None
    )


def test_the_temporary_chains_of_two_rule_sets_of_one_name_differ():
    """The negation and the SDNAT expansions hash the same three values."""
    for method in ('ipt_tmp_chain_name', 'nat_tmp_chain_name', 'nft_tmp_chain_name'):
        top = _Namer('Policy')
        imported = _Namer('Policy', chain='Policy')
        assert getattr(top, method)(_rule()) != getattr(imported, method)(_rule()), (
            method
        )


def test_the_temporary_chain_name_is_stable_for_one_rule_set():
    """It has to be, or a recompile of an unchanged policy differs."""
    first = _Namer('Policy', chain='Policy')
    second = _Namer('Policy', chain='Policy')
    assert first.ipt_tmp_chain_name(_rule()) == second.ipt_tmp_chain_name(_rule())
