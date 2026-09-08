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

"""A Custom action on nftables.

The action carries one statement per packet filter, the way a Custom
Service carries one code per platform, and a rule imported from a `.fwb`
file carries the platform-less one Firewall Builder wrote.  The nftables
statement is written out verbatim, exactly as the iptables printer writes
its custom target; an iptables target is translated where netfilter's own
translator has a translation (`test_custom_action_translation.py`) and
reported where it has none, because nft answers text it cannot parse with
a syntax error and refuses the whole ruleset over it rather than the rule.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.nftables._policy_compiler import DecideOnTarget
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Firewall:
    def __init__(self, platform: str) -> None:
        self.platform = platform


class _Compiler:
    def __init__(self, platform: str = 'nftables') -> None:
        self.ipv6_policy = False
        self.branch_chains: set[str] = set()
        self.fw = _Firewall(platform)
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


class _Source:
    def __init__(self, rules) -> None:
        self._rules = list(rules)

    def get_next_rule(self):
        return self._rules.pop(0) if self._rules else None


def _rule(custom_str: str = ''):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={'custom_str': custom_str} if custom_str else {},
        negations={},
        action=PolicyAction.Custom,
    )


def _decide(platform: str, custom_str: str):
    rule = _rule(custom_str)
    processor = DecideOnTarget('decide on target')
    processor.compiler = _Compiler(platform)
    processor.prev_processor = _Source([rule])
    processor.process_next()
    return processor.compiler, rule


def _verdict(rule, platform: str = 'nftables'):
    printer = PrintRule_nft()
    printer.compiler = _Compiler(platform)
    return printer, printer._print_verdict(rule)


def test_the_statement_of_an_nftables_firewall_is_written_out():
    compiler, rule = _decide('nftables', 'tcp option maxseg size set 1400')
    assert compiler.messages == []
    assert rule.ipt_target == '.CUSTOM'

    _printer, verdict = _verdict(rule)
    assert verdict == 'tcp option maxseg size set 1400'


@pytest.mark.parametrize('platform', ['iptables', 'pf', '', 'nftables'])
def test_a_translatable_iptables_target_is_written_whatever_the_platform_says(
    platform,
):
    """A `.fwb` firewall says iptables whatever it is compiled with."""
    compiler, rule = _decide(platform, '-j TCPMSS --set-mss 1400')

    assert compiler.messages == []
    assert rule.ipt_target == '.CUSTOM'
    _printer, verdict = _verdict(rule, platform)
    assert verdict == 'tcp option maxseg size set 1400'


@pytest.mark.parametrize('platform', ['iptables', 'pf', '', 'nftables'])
def test_an_iptables_target_with_no_translation_is_reported(platform):
    """TARPIT never was in mainline netfilter, so nothing translates it."""
    compiler, rule = _decide(platform, '-j TARPIT')

    assert compiler.messages == []
    assert rule.ipt_target == '.CUSTOM'
    printer, verdict = _verdict(rule, platform)
    assert verdict is None
    assert len(printer.compiler.messages) == 1
    assert 'no nftables statement' in printer.compiler.messages[0]


def test_an_empty_statement_is_reported_by_the_printer():
    _compiler, rule = _decide('nftables', '')
    printer, verdict = _verdict(rule)

    assert verdict is None
    assert printer.compiler.messages
