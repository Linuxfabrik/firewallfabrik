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

"""An IP service naming a protocol number that is not one.

The protocol field of the IP header has one byte, and both tools bound
the value there.  Verified against iptables 1.8.11 and nft 1.1.6:

    iptables -A INPUT -p 300 -j ACCEPT
    -> unknown protocol "300" specified
    nft ... meta l4proto 300 accept
    -> Error: Protocol out of range

iptables reads the argument with ``xtables_strtoui(s, NULL, &proto, 0,
UINT8_MAX)`` and falls through to a name lookup for anything larger
(netfilter iptables libxtables/xtables.c, ``xtables_parse_protocol``), so
the activation script stops there with the built-in policies already at
DROP; nftables refuses the whole ruleset, so the firewall never gets the
new policy at all.

A value that is no number is the worse half: every print rule reads it
with ``int()`` and writes no protocol match when that fails, so a rule
written for one protocol goes out matching all of them.

Both editors bound the field to 0..255 with a spin box
(``ipservicedialog_q.ui``, and Firewall Builder's has the same maximum),
which is why neither compiler asked - the same reasoning as for a port
range that runs backwards.  A data file written by an older release,
another tool or by hand carries whatever it carries.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._service import (
    VerifyIpProtocols,
    ip_protocol_problem,
)
from firewallfabrik.core.objects import IPService, PolicyAction, TCPService


def _srv(protocol=None, cls=IPService):
    srv = cls(id=uuid.uuid4(), name='probe')
    if protocol is not None:
        srv.named_protocols = {'protocol_num': protocol}
    return srv


@pytest.mark.parametrize('protocol', ['256', '300', '65536', '-1', '-5'])
def test_a_number_outside_the_byte_is_reported(protocol):
    assert ip_protocol_problem(_srv(protocol))


@pytest.mark.parametrize('protocol', ['gre', '0x6', 'nonsense', '6.5'])
def test_a_value_that_is_no_protocol_number_is_reported(protocol):
    assert ip_protocol_problem(_srv(protocol))


@pytest.mark.parametrize('protocol', ['0', '1', '47', '112', '255', 255])
def test_a_protocol_both_tools_take(protocol):
    assert not ip_protocol_problem(_srv(protocol))


def test_a_service_naming_no_protocol_is_the_models_any():
    assert not ip_protocol_problem(_srv())


def test_only_an_ip_service_is_asked():
    """A TCP service carries its protocol in its class, not in a field."""
    assert not ip_protocol_problem(_srv('300', cls=TCPService))


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(services, rule_type='PolicyRule', slot='srv'):
    rule = CompRule(
        id=uuid.uuid4(),
        type=rule_type,
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    setattr(rule, slot, services)
    return rule


def _run(rule):
    proc = VerifyIpProtocols(name='VerifyIpProtocols')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return proc


def test_the_rule_is_left_out_and_the_service_is_named():
    proc = _run(_rule([_srv('300')]))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages
    assert 'probe' in proc.compiler.messages[0]


def test_a_nat_rule_is_asked_about_its_original_service():
    proc = _run(_rule([_srv('300')], rule_type='NATRule', slot='osrv'))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages


def test_an_ordinary_ip_rule_passes_through():
    proc = _run(_rule([_srv('47')]))
    assert len(proc.tmp_queue) == 1
    assert proc.compiler.messages == []
