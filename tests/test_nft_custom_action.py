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

The action carries one string and no platform beside it, so the firewall's
own platform says what the administrator wrote it in - the way a Custom
Service carries one code per platform.  A firewall that names nftables gets
the statement written out verbatim, exactly as the iptables printer writes
its custom target; one that names another platform holds text nft cannot
parse, and nft refuses the whole ruleset over it rather than the rule, so
the rule is reported and left out.
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


@pytest.mark.parametrize('platform', ['iptables', 'pf', ''])
def test_a_statement_written_for_another_platform_is_reported(platform):
    compiler, rule = _decide(platform, '-j TCPMSS --set-mss 1400')

    assert len(compiler.messages) == 1
    assert 'Custom action' in compiler.messages[0]
    # Without a target the print rule finds no verdict for the action and
    # answers None, which is what leaves the rule out.
    assert rule.ipt_target == ''
    _printer, verdict = _verdict(rule)
    assert verdict is None


def test_an_empty_statement_is_reported_by_the_printer():
    _compiler, rule = _decide('nftables', '')
    printer, verdict = _verdict(rule)

    assert verdict is None
    assert printer.compiler.messages
