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

"""The release a per-source connection limit needs on nftables.

``-m connlimit --connlimit-above N`` becomes
``add @<set> { ip saddr ct count over N }``, and the set it counts in has
to be declared ``flags dynamic``: the rule creates one element per address
as it sees them, and the flag is what tells the kernel to pick a set
backend that allows it.

``dynamic`` entered the scanner in nftables v0.9.1 ("src: add dynamic flag
and use it", 2018-06-11).  On v0.9.0 the declaration is a syntax error, and
nftables loads a ruleset in one transaction - so the rule would not only
lose its limit, it would take the whole ruleset with it and leave the
firewall on the rules it had.  ``ct count`` and the ``add @set`` statement
themselves are both older than that and need no gate of their own.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft
from firewallfabrik.platforms.nftables._utils import (
    NFT_DYNAMIC_SET_FIRST_RELEASE,
    nft_feature_available,
)


class _Firewall:
    platform = 'nftables'

    def __init__(self, version: str) -> None:
        self.version = version


class _Compiler:
    def __init__(self, version: str) -> None:
        self.ipv6_policy = False
        self.shared_inet_table = False
        self.fw = _Firewall(version)
        self.messages: list[str] = []
        self.dynamic_sets: dict[str, str] = {}

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def get_rule_set_name(self) -> str:
        return 'Policy'

    def register_dynamic_set(self, name: str, addr_type: str) -> None:
        self.dynamic_sets[name] = addr_type


def _print(version: str, **options):
    printer = PrintRule_nft()
    printer.compiler = _Compiler(version)
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=3,
        label='3 (global)',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )
    return printer, printer._print_connlimit(rule)


@pytest.mark.parametrize(
    ('version', 'available'),
    [
        ('', True),
        ('0.9.0', False),
        ('0.9.1', True),
        ('0.9.5', True),
        ('1.1.6', True),
    ],
)
def test_the_dynamic_set_needs_0_9_1(version, available):
    compiler = _Compiler(version)
    assert nft_feature_available(compiler, NFT_DYNAMIC_SET_FIRST_RELEASE) is available


@pytest.mark.parametrize('version', ['', '0.9.1', '0.9.5'])
def test_a_release_that_knows_the_flag_writes_the_limit(version):
    printer, result = _print(version, connlimit_value=10)
    assert result == 'add @connlimit_Policy_3 { ip saddr ct count over 10 }'
    assert printer.compiler.dynamic_sets == {'connlimit_Policy_3': 'ipv4_addr'}
    assert not printer.compiler.messages


def test_an_older_release_leaves_the_rule_out():
    """Emitting it would cost the whole ruleset, not the one rule."""
    printer, result = _print('0.9.0', connlimit_value=10)
    assert result is None
    assert not printer.compiler.dynamic_sets
    assert any(
        NFT_DYNAMIC_SET_FIRST_RELEASE in msg for msg in printer.compiler.messages
    )


def test_a_rule_without_a_connection_limit_is_untouched_on_any_release():
    printer, result = _print('0.9.0')
    assert result == ''
    assert not printer.compiler.messages
