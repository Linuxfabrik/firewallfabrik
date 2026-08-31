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

"""A rule that answers with a TCP reset keeps the protocol it needs.

Every processor that moves the action of a rule into a temporary chain -
the logging expansion and the three negations - clears the service element
there, because the jump rule already matched it.  That would drop the
`-p tcp` `--reject-with tcp-reset` needs: the kernel refuses the rule with
"TCP_RESET invalid for non-tcp" (`reject_tg_check`, netfilter
`net/ipv4/netfilter/ipt_REJECT.c`) and the activation script stops there
with the built-in policies already at DROP.

Which service counts as TCP is asked by protocol name, not by class: a
Custom Service carries a protocol of its own, which is why
`splitServicesIfRejectWithTCPReset` asks that way and says so in its own
comment.  `TCPService::isA` is what fwbuilder asks in the logging
expansion, so a logged Reject-with-TCP-reset rule over a Custom Service
loses the protocol there too - `firewall9` rule 12 of the reference
corpus, whose service is `-p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK`.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import CustomService, IPService, TCPService, UDPService
from firewallfabrik.platforms.linux._netfilter import reset_srv_preserving_tcp


def _rule(service):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=12,
        label='12 (global)',
        comment='',
        options={},
        negations={},
        srv=[service] if service is not None else [],
    )


def _tcp_service():
    srv = TCPService(id=uuid.uuid4(), name='http')
    srv.dst_range_start = 80
    srv.dst_range_end = 80
    return srv


def _custom_service():
    srv = CustomService(id=uuid.uuid4(), name='tcp-flags')
    srv.protocol = 'tcp'
    return srv


def _ip_service(protocol):
    srv = IPService(id=uuid.uuid4(), name=f'proto-{protocol}')
    srv.named_protocols = {'protocol_num': str(protocol)}
    return srv


def test_a_tcp_service_leaves_any_tcp_behind():
    rule = _rule(_tcp_service())
    reset_srv_preserving_tcp(rule)

    assert len(rule.srv) == 1
    assert rule.srv[0].get_protocol_name() == 'tcp'
    assert rule.srv[0].dst_range_start == 0


def test_a_custom_service_that_is_tcp_leaves_any_tcp_behind():
    rule = _rule(_custom_service())
    reset_srv_preserving_tcp(rule)

    assert len(rule.srv) == 1
    assert rule.srv[0].get_protocol_name() == 'tcp'


def test_an_ip_service_naming_protocol_six_leaves_any_tcp_behind():
    rule = _rule(_ip_service(6))
    reset_srv_preserving_tcp(rule)

    assert len(rule.srv) == 1
    assert rule.srv[0].get_protocol_name() == 'tcp'


@pytest.mark.parametrize(
    'service',
    [None, UDPService(id=uuid.uuid4(), name='domain'), _ip_service(50)],
    ids=['any', 'udp', 'esp'],
)
def test_anything_else_leaves_nothing_behind(service):
    rule = _rule(service)
    reset_srv_preserving_tcp(rule)

    assert rule.srv == []
