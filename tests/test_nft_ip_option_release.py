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

"""The nftables release an IPv4 header option match needs.

``ip option lsrr exists`` is an exthdr expression with the IPv4 operation
(``NFT_EXTHDR_OP_IPV4``), which the kernel gained in Linux 5.3 and
nftables in v0.9.2.  An older nftables answers the keyword with a syntax
error and refuses the **whole** ruleset, so a firewall pinned below that
release must not be given the match at all.

``ip hdrlength > 5``, which "match any IP option" compiles to, is an
ordinary header field and is written whatever the release.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import IPService, PolicyAction
from firewallfabrik.platforms.nftables._print_rule import (
    PrintRule_nft,
    print_ip_option_matches,
)
from firewallfabrik.platforms.nftables._utils import NFT_IP_OPTION_FIRST_RELEASE


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

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule() -> CompRule:
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )


def _service(**data) -> IPService:
    srv = IPService()
    srv.name = 'ip-service'
    srv.data = data
    return srv


def _print(version: str, **data):
    printer = PrintRule_nft()
    printer.compiler = _Compiler(version)
    return printer, printer._print_service(_rule(), _service(**data))


@pytest.mark.parametrize('flag', ['lsrr', 'rr', 'rtralt', 'ssrr'])
def test_a_release_that_knows_the_option_writes_the_match(flag):
    printer, result = _print('0.9.2', **{flag: True})
    assert result is not None
    assert 'ip option ' in result
    assert not printer.compiler.messages


@pytest.mark.parametrize('flag', ['lsrr', 'rr', 'rtralt', 'ssrr'])
@pytest.mark.parametrize('version', ['0.9.0', '0.9.1'])
def test_an_older_release_leaves_the_rule_out(flag, version):
    """Emitting it would cost the whole ruleset, not the one rule."""
    printer, result = _print(version, **{flag: True})
    assert result is None
    assert any(NFT_IP_OPTION_FIRST_RELEASE in msg for msg in printer.compiler.messages)


def test_a_firewall_that_pins_nothing_gets_the_match():
    printer, result = _print('', lsrr=True)
    assert result is not None
    assert 'ip option lsrr exists' in result
    assert not printer.compiler.messages


def test_match_any_option_is_an_ordinary_header_field():
    """`ip hdrlength` predates every release the editor offers."""
    printer, result = _print('0.9.0', any_opt=True)
    assert result is not None
    assert 'ip hdrlength > 5' in result
    assert not printer.compiler.messages


def test_the_helper_reports_the_names_it_could_not_write():
    matches, unsupported, too_new = print_ip_option_matches(
        {'lsrr': True, 'ssrr': True, 'ts': True}, False
    )
    assert matches == []
    assert unsupported == ['timestamp']
    assert sorted(too_new) == ['lsrr', 'ssrr']
