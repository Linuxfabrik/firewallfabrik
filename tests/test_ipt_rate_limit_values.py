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

"""Values a rate limit may carry into an iptables command.

Everything here was asked of the real binary in a private network
namespace first, so the numbers are what iptables answers, not what the
source reads like:

    iptables -A INPUT -m hashlimit --hashlimit 100000000/second \\
        --hashlimit-name y            -> Rate too fast
    iptables -A INPUT -m hashlimit --hashlimit 10/second \\
        --hashlimit-name y --hashlimit-burst 2000000
                                      -> out of range (1-1000000)
    iptables -A INPUT -m hashlimit --hashlimit 10/second \\
        --hashlimit-name "a/b"        -> RULE_APPEND failed (Invalid argument)
    ip6tables -A INPUT -m connlimit --connlimit-above 2 \\
        --connlimit-mask 129          -> neither a valid network mask nor
                                         valid CIDR (0-128)

The IPv4 half of the last one is the reason it is checked rather than
passed on: iptables does not refuse `--connlimit-mask 64`, it reads the
value as the dotted mask 0.0.0.64 and groups connections by four bits of
the last octet.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._print_rule import PrintRule


class _Compiler:
    """The bit of PolicyCompiler_ipt the printer reaches for."""

    def __init__(self, ipv6=False):
        self.ipv6_policy = ipv6
        self.muted_now = False
        self.hashlimit_tables = {}
        self.errors = []
        self.warnings = []

    def error(self, rule, message):
        self.errors.append(message)

    def warning(self, rule, message):
        self.warnings.append(message)


def _printer(ipv6=False, version='1.8'):
    printer = PrintRule(name='PrintRule')
    printer.compiler = _Compiler(ipv6=ipv6)
    printer.version = version
    return printer


def _rule(**options):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )


@pytest.mark.parametrize(
    ('options', 'wanted'),
    [
        # Faster than the scale the match stores its rate in.
        ({'hashlimit_value': 100000000}, 'faster than'),
        # Wider than the burst any revision of the match takes.
        ({'hashlimit_value': 10, 'hashlimit_burst': 2000000}, 'out of range'),
        # A name the kernel cannot make a file under /proc out of.
        ({'hashlimit_value': 10, 'hashlimit_name': 'a/b'}, 'cannot make a name'),
        ({'hashlimit_value': 10, 'hashlimit_name': 'a b'}, 'cannot make a name'),
    ],
)
def test_a_rate_limit_iptables_refuses_leaves_the_rule_out(options, wanted):
    printer = _printer()
    assert printer._print_hashlimit(_rule(**options)) is None
    assert any(wanted in message for message in printer.compiler.errors)


def test_a_rate_limit_within_range_is_printed():
    printer = _printer()
    out = printer._print_hashlimit(
        _rule(hashlimit_value=10, hashlimit_burst=5, hashlimit_name='ok')
    )
    assert '-m hashlimit --hashlimit 10 --hashlimit-burst 5' in out
    assert printer.compiler.errors == []


@pytest.mark.parametrize(
    ('ipv6', 'masklen', 'refused'),
    [
        (False, 32, False),
        (False, 33, True),
        (False, 64, True),
        (True, 64, False),
        (True, 128, False),
        (True, 129, True),
    ],
)
def test_a_connection_limit_groups_by_at_most_the_address_width(ipv6, masklen, refused):
    printer = _printer(ipv6=ipv6)
    out = printer._print_connlimit(_rule(connlimit_value=2, connlimit_masklen=masklen))
    if refused:
        assert out is None
        assert any('groups by at most' in m for m in printer.compiler.errors)
    else:
        assert f'--connlimit-mask {masklen}' in out
        assert printer.compiler.errors == []
