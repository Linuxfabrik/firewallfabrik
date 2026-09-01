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

"""A Custom action written for the other platform.

The text is one string with no platform beside it, so nothing keeps it in
step when a firewall is switched from iptables to nftables in the editor -
and both printers append it to the rule verbatim.  Appending it costs more
than the rule: iptables answers an nftables statement with "unknown
option" and the activation script stops with every policy already at DROP,
nftables answers an iptables target with a syntax error and refuses the
whole ruleset, so the firewall keeps the rules it had.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._print_rule import PrintRule as PrintRuleIpt
from firewallfabrik.platforms.linux._netfilter import custom_action_is_iptables_syntax
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

IPTABLES_TARGETS = [
    '-j TCPMSS --set-mss 1400',
    '-j TARPIT',
    '  -j ROUTE --gw 192.0.2.1',
]

NFTABLES_STATEMENTS = [
    'tcp option maxseg size set 1400',
    'meta mark set 0x10',
    'counter accept',
]


class _Firewall:
    platform = 'nftables'
    version = ''


class _Compiler:
    def __init__(self) -> None:
        self.ipv6_policy = False
        self.shared_inet_table = False
        self.fw = _Firewall()
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(custom_str: str) -> CompRule:
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={'custom_str': custom_str},
        negations={},
        action=PolicyAction.Custom,
    )
    rule.ipt_target = '.CUSTOM'
    return rule


def _ipt(custom_str: str):
    printer = PrintRuleIpt()
    printer.compiler = _Compiler()
    return printer, printer._print_target(_rule(custom_str))


def _nft(custom_str: str):
    printer = PrintRule_nft()
    printer.compiler = _Compiler()
    return printer, printer._print_verdict(_rule(custom_str))


@pytest.mark.parametrize('text', IPTABLES_TARGETS)
def test_the_helper_reads_a_target_as_iptables(text):
    assert custom_action_is_iptables_syntax(text)


@pytest.mark.parametrize('text', NFTABLES_STATEMENTS)
def test_the_helper_reads_a_statement_as_nftables(text):
    assert not custom_action_is_iptables_syntax(text)


@pytest.mark.parametrize('text', IPTABLES_TARGETS)
def test_iptables_writes_its_own_target(text):
    printer, result = _ipt(text)
    assert result == f' {text}'
    assert not printer.compiler.messages


@pytest.mark.parametrize('text', NFTABLES_STATEMENTS)
def test_iptables_leaves_out_an_nftables_statement(text):
    """`$IPTABLES ... meta mark set 0x10` stops the activation."""
    printer, result = _ipt(text)
    assert result is None
    assert printer.compiler.messages


@pytest.mark.parametrize('text', NFTABLES_STATEMENTS)
def test_nftables_writes_its_own_statement(text):
    printer, result = _nft(text)
    assert result == text
    assert not printer.compiler.messages


@pytest.mark.parametrize('text', IPTABLES_TARGETS)
def test_nftables_leaves_out_an_iptables_target(text):
    """Writing it out would cost the whole ruleset, not the one rule."""
    printer, result = _nft(text)
    assert result is None
    assert printer.compiler.messages
