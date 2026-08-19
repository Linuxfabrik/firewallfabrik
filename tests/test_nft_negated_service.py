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

"""What a negated service element compiles to on nftables.

iptables says "not this service" with a temporary chain: the rule jumps
into it, a rule matching the service returns, and the action follows
(`PolicyCompiler_ipt::SrvNegation`).  nftables writes `!=` into the rule
itself, and that only works as long as the negation lands on something the
rule actually says.

A service that names nothing but its protocol says only that, so the `!=`
belongs on `meta l4proto`.  Without it the rule reads exactly like the one
it is the negation of, and a Deny written for "anything but TCP" drops
nothing but TCP.  `print_icmp_service` has always put the negation there
for an ICMP service that names no type; the TCP/UDP printer did not.
"""

import uuid

import pytest

from firewallfabrik.core.objects import TCPService, UDPService
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _Rule:
    def __init__(self, srv, negated: bool) -> None:
        self.srv = srv
        self.srv_single_object_negation = negated


def _print(srv, proto: str, negated: bool) -> str:
    printer = PrintRule_nft.__new__(PrintRule_nft)
    return printer._print_tcp_udp_service(_Rule([srv], negated), srv, proto)


@pytest.mark.parametrize(
    ('cls', 'proto'),
    [(TCPService, 'tcp'), (UDPService, 'udp')],
)
def test_whole_protocol_service_carries_the_negation(cls, proto):
    srv = cls(id=uuid.uuid4(), name=f'All {proto.upper()}')
    assert _print(srv, proto, negated=False) == f'meta l4proto {proto}'
    assert _print(srv, proto, negated=True) == f'meta l4proto != {proto}'


@pytest.mark.parametrize(
    ('cls', 'proto'),
    [(TCPService, 'tcp'), (UDPService, 'udp')],
)
def test_a_service_with_a_port_still_negates_the_port(cls, proto):
    srv = cls(id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80)
    assert _print(srv, proto, negated=False) == f'{proto} dport 80'
    assert _print(srv, proto, negated=True) == f'{proto} dport != 80'
