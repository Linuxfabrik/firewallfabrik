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

"""What the printers do with an IP service option they cannot write out.

A condition that cannot be rendered must take its rule with it.  Keeping
the rule and dropping the condition turns "accept only AF41" into "accept
everything" and "log only EF" into logging the whole link, and nothing in
the generated script says so.  Both platforms answer such a value the same
way; this pins that they do.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import IPService, PolicyAction
from firewallfabrik.platforms.iptables._print_rule import PrintRule as PrintRuleIpt
from firewallfabrik.platforms.iptables._utils import DEFAULT_IPTABLES_VERSION
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Compiler:
    """The bit of a policy compiler the IP-service branch reaches for."""

    def __init__(self, ipv6: bool = False) -> None:
        self.ipv6_policy = ipv6
        self.shared_inet_table = False
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


def _ipt(srv, ipv6: bool = False):
    printer = PrintRuleIpt()
    printer.compiler = _Compiler(ipv6)
    printer.version = DEFAULT_IPTABLES_VERSION
    return printer, printer._print_ip_service_options(_rule(), srv)


def _nft(srv, ipv6: bool = False):
    printer = PrintRule_nft()
    printer.compiler = _Compiler(ipv6)
    return printer, printer._print_service(_rule(), srv)


@pytest.mark.parametrize(
    ('dscp', 'reason'),
    [
        ('AF4', 'a class name missing its drop precedence'),
        ('184', 'EF written as the whole traffic class byte'),
        ('0xb8', 'the same, in hex'),
        ('CS8', 'there is no class selector 8'),
    ],
)
def test_an_invalid_dscp_takes_the_rule_with_it(dscp, reason):
    """iptables used to report it and emit the rule without the match."""
    for build in (_ipt, _nft):
        printer, result = build(_service(dscp=dscp))
        assert result is None, f'{build.__name__}: {reason}'
        assert printer.compiler.messages, f'{build.__name__}: said nothing'


@pytest.mark.parametrize('dscp', ['AF41', 'EF', 'be', '46', '0x2e', '63'])
def test_a_valid_dscp_is_written_out(dscp):
    _printer, result = _ipt(_service(dscp=dscp))
    assert result is not None
    assert '-m dscp' in result
