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

"""What a NAT rule keeps of the service its Original Service names.

The policy printers read the TCP flags and the ToS / DSCP of a service;
the NAT printers read neither, and neither does fwbuilder's
(NATCompiler_PrintRule.cpp, _printIP).  A NAT rule whose command is
missing one of them translates every packet between the addresses it
names, not the ones the service describes.

The flags are legal in a nat chain on both back ends, so they are written
out; the ToS and the DSCP have no place in a NAT rule and are reported.

No `.fwb` or `.fwf` of the corpus puts such a service in a NAT rule, so
the forms are asserted here rather than through a fixture.
"""

import uuid

import pytest

from firewallfabrik.core.objects import IPService, NATAction, TCPService


class _Compiler:
    """Just enough compiler for the two NAT service printers."""

    ipv6_policy = False

    def __init__(self) -> None:
        self.messages: list[str] = []

    def warning(self, _rule, msg: str) -> None:
        self.messages.append(msg)

    def error(self, _rule, msg: str) -> None:
        self.messages.append(msg)

    @staticmethod
    def my_platform_name() -> str:
        return 'iptables'

    @staticmethod
    def get_first_osrv(rule):
        return rule.osrv[0] if rule.osrv else None


def _rule(srv):
    from firewallfabrik.compiler._comp_rule import CompRule

    return CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=NATAction.Translate,
        osrv=[srv],
    )


def _tcp_service():
    """A service that inspects SYN and ACK and wants only SYN set."""
    srv = TCPService(id=uuid.uuid4(), name='syn only')
    srv.dst_range_start = 80
    srv.dst_range_end = 80
    srv.tcp_flags_masks = {'syn': True, 'ack': True}
    srv.tcp_flags = {'syn': True}
    return srv


def _ip_service(**data):
    srv = IPService(id=uuid.uuid4(), name='marked')
    srv.data = dict(data)
    return srv


def _ipt_printer():
    from firewallfabrik.platforms.iptables._nat_print_rule import NATPrintRule

    printer = NATPrintRule('print nat rule')
    printer.compiler = _Compiler()
    printer.version = '1.8.11'
    return printer


def _nft_printer():
    from firewallfabrik.platforms.nftables._nat_print_rule import NATPrintRule_nft

    printer = NATPrintRule_nft('print nat rule')
    printer.compiler = _Compiler()
    return printer


def test_a_nat_rule_keeps_the_tcp_flags_of_its_service_on_iptables():
    srv = _tcp_service()
    assert srv.tcp_flag_match() == (['ack', 'syn'], ['syn'])
    out = _ipt_printer()._print_dst_service(_rule(srv))
    assert '--tcp-flags ACK,SYN SYN' in out
    assert '--dport 80' in out


def test_a_nat_rule_keeps_the_tcp_flags_of_its_service_on_nftables():
    srv = _tcp_service()
    rule = _rule(srv)
    out = _nft_printer()._print_service(srv, rule)
    assert 'tcp flags syn / ack,syn' in out
    assert 'tcp dport 80' in out


@pytest.mark.parametrize('field', ['tos', 'dscp'])
def test_a_nat_rule_naming_a_tos_or_dscp_service_is_reported(field):
    for printer, call in (
        (_ipt_printer(), lambda p, r, s: p._print_ip(r, s)),
        (_nft_printer(), lambda p, r, s: p._print_service(s, r)),
    ):
        srv = _ip_service(**{field: '0x10'})
        rule = _rule(srv)
        assert call(printer, rule, srv) is None
        assert any('ToS or DSCP' in m for m in printer.compiler.messages)


def _plain_service():
    """A second TCP service that inspects nothing."""
    srv = TCPService(id=uuid.uuid4(), name='https')
    srv.dst_range_start = 443
    srv.dst_range_end = 443
    return srv


def test_a_service_with_flags_is_given_a_nat_rule_of_its_own():
    """Both printers write ports alone once a rule names several services.

    So a service that inspects the flags has to be alone in its rule by the
    time it gets there.  The policy pipelines have split on it since they
    were written; neither NAT pipeline did, here or in fwbuilder, and the
    rule then translated every TCP packet on those ports instead of the
    handshake stage it was written for.
    """
    from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
    from firewallfabrik.compiler.processors._service import SeparateTCPWithFlags

    class _Feeder(BasicRuleProcessor):
        def __init__(self, rules):
            super().__init__(name='Feeder')
            for rule in rules:
                self.tmp_queue.append(rule)

        def process_next(self) -> bool:
            return False

    with_flags = _tcp_service()
    rule = _rule(with_flags)
    rule.osrv = [with_flags, _plain_service()]

    processor = SeparateTCPWithFlags('split on TCP services with flags')
    processor.prev_processor = _Feeder([rule])
    processor.compiler = _Compiler()
    processor.process_next()

    out = list(processor.tmp_queue)
    assert [[s.name for s in r.osrv] for r in out] == [['syn only'], ['https']]


@pytest.mark.parametrize(
    ('module', 'compiler_name'),
    [
        ('firewallfabrik.platforms.iptables._nat_compiler', 'NATCompiler_ipt'),
        ('firewallfabrik.platforms.nftables._nat_compiler', 'NATCompiler_nft'),
    ],
)
def test_both_nat_pipelines_split_on_tcp_flags(module, compiler_name):
    """The processor existed and worked; it was in neither NAT pipeline."""
    import importlib
    import inspect

    source = inspect.getsource(getattr(importlib.import_module(module), compiler_name))
    assert 'SeparateTCPWithFlags(' in source
