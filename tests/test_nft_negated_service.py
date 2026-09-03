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

A service that names a port, a TCP flag or an ICMP type says more, and
nftables compiles that into a payload match that carries a protocol
dependency: `tcp dport != 80` becomes `meta l4proto tcp` followed by the
port comparison, so a UDP packet - which is not TCP port 80 either - never
reaches the rule.  iptables' temporary chain does see it.  The other half
therefore needs a rule of its own, and that is what
`AddOtherProtocolsForNegatedService` adds.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import (
    ICMPService,
    PolicyAction,
    TCPService,
    UDPService,
)
from firewallfabrik.platforms.nftables._policy_compiler import (
    AddOtherProtocolsForNegatedService,
)
from firewallfabrik.platforms.nftables._print_rule import (
    OTHER_PROTOCOLS_OPTION,
    PrintRule_nft,
)


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


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules: list[CompRule]) -> None:
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self, ipv6: bool = False) -> None:
        self.ipv6_policy = ipv6

    @staticmethod
    def is_action_on_reject_tcp_rst(rule) -> bool:
        return rule.get_option('action_on_reject', '') == 'TCP RST'

    @staticmethod
    def reset_action_on_reject(rule) -> None:
        rule.set_option('action_on_reject', '')


def _comp_rule(services: list, negated: bool = True, **options) -> CompRule:
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0',
        comment='',
        options=dict(options),
        negations={'srv': negated},
        action=PolicyAction.Deny,
    )
    rule.srv = services
    return rule


def _run(rule: CompRule, ipv6: bool = False) -> list[CompRule]:
    processor = AddOtherProtocolsForNegatedService(name='p')
    processor.compiler = _Compiler(ipv6)
    processor.set_data_source(_Feeder([rule]))
    assert processor.process_next() is True
    return list(processor.tmp_queue)


def test_a_negated_port_gets_a_rule_for_the_other_protocols():
    http = TCPService(
        id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80
    )
    out = _run(_comp_rule([http]))
    assert len(out) == 2
    assert out[0].srv == [http]
    assert out[1].srv == []
    assert out[1].get_option(OTHER_PROTOCOLS_OPTION, None) == ['tcp']
    assert out[1].get_neg('srv') is False


def test_two_protocols_are_both_excluded():
    http = TCPService(
        id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80
    )
    dns = UDPService(id=uuid.uuid4(), name='dns', dst_range_start=53, dst_range_end=53)
    out = _run(_comp_rule([http, dns]))
    assert out[1].get_option(OTHER_PROTOCOLS_OPTION, None) == ['tcp', 'udp']


def test_an_icmp_type_is_excluded_by_the_family_s_own_name():
    ping = ICMPService(id=uuid.uuid4(), name='ping', data={'type': 8, 'code': 0})
    assert _run(_comp_rule([ping]))[1].get_option(OTHER_PROTOCOLS_OPTION, None) == [
        'icmp'
    ]
    ping6 = ICMPService(id=uuid.uuid4(), name='ping6', data={'type': 128, 'code': 0})
    out = _run(_comp_rule([ping6]), ipv6=True)
    assert out[1].get_option(OTHER_PROTOCOLS_OPTION, None) == ['ipv6-icmp']


@pytest.mark.parametrize(
    'services',
    [
        # "All TCP" already negates to `meta l4proto != tcp`, which is
        # complete.
        [TCPService(id=uuid.uuid4(), name='All TCP')],
        # An ICMP service that names no type says only its protocol.
        [ICMPService(id=uuid.uuid4(), name='All ICMP', data={'type': -1})],
    ],
)
def test_a_whole_protocol_service_needs_no_second_rule(services):
    assert len(_run(_comp_rule(services))) == 1


def test_a_rule_that_is_not_negated_is_left_alone():
    http = TCPService(
        id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80
    )
    assert len(_run(_comp_rule([http], negated=False))) == 1


def test_the_other_half_of_a_tcp_reset_rule_loses_the_reset():
    """A TCP reset needs a TCP packet, and this rule matches everything else."""
    http = TCPService(
        id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80
    )
    rule = _comp_rule([http], action_on_reject='TCP RST')
    rule.action = PolicyAction.Reject
    out = _run(rule)
    assert out[0].get_option('action_on_reject', '') == 'TCP RST'
    assert out[1].get_option('action_on_reject', '') == ''


def test_the_printer_writes_the_exclusion():
    printer = PrintRule_nft.__new__(PrintRule_nft)
    one = _comp_rule([], negated=False, **{OTHER_PROTOCOLS_OPTION: ['tcp']})
    two = _comp_rule([], negated=False, **{OTHER_PROTOCOLS_OPTION: ['tcp', 'udp']})
    assert printer._print_service(one, None) == 'meta l4proto != tcp'
    assert printer._print_service(two, None) == 'meta l4proto != { tcp, udp }'


class _NATCompiler(_Compiler):
    def __init__(self, ipv6: bool = False) -> None:
        super().__init__(ipv6)
        self.warnings: list[str] = []

    def warning(self, _rule, message: str) -> None:
        self.warnings.append(message)


def _nat_rule(services: list, translated: list | None = None) -> CompRule:
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0 (NAT)',
        comment='',
        options={},
        negations={'osrv': True},
        action=None,
    )
    rule.osrv = services
    rule.tsrv = translated or []
    return rule


def _run_nat(rule: CompRule) -> tuple[list[CompRule], list[str]]:
    from firewallfabrik.platforms.nftables._nat_compiler import (
        AddOtherProtocolsForNegatedServiceInNAT,
    )

    processor = AddOtherProtocolsForNegatedServiceInNAT(name='p')
    processor.compiler = _NATCompiler()
    processor.set_data_source(_Feeder([rule]))
    assert processor.process_next() is True
    return list(processor.tmp_queue), processor.compiler.warnings


def test_a_nat_rule_translates_the_other_protocols_too():
    http = TCPService(
        id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80
    )
    out, warnings = _run_nat(_nat_rule([http]))
    assert len(out) == 2
    assert out[1].osrv == []
    assert out[1].get_option(OTHER_PROTOCOLS_OPTION, None) == ['tcp']
    assert warnings == []


def test_a_translated_port_gets_a_warning_instead_of_a_second_rule():
    """A port belongs to a protocol, and both tools refuse the rule without one."""
    http = TCPService(
        id=uuid.uuid4(), name='http', dst_range_start=80, dst_range_end=80
    )
    new = TCPService(
        id=uuid.uuid4(), name='8080', dst_range_start=8080, dst_range_end=8080
    )
    out, warnings = _run_nat(_nat_rule([http], translated=[new]))
    assert len(out) == 1
    assert len(warnings) == 1
    assert 'untranslated' in warnings[0]


class _MultiRule:
    """A rule whose service element is negated and names several services."""

    def __init__(self, srvs: list) -> None:
        self.srv = srvs
        self.srv_single_object_negation = True
        self.merged_tcp_udp = False

    @staticmethod
    def get_option(_key, default=None):
        return default


def _print_element(srvs: list, ipv6: bool = False) -> str | None:
    from firewallfabrik.platforms.nftables._print_rule import print_negated_services

    return print_negated_services(srvs, ipv6)


def _tcp(name: str, dport: int = 0, sport: int = 0) -> TCPService:
    return TCPService(
        id=uuid.uuid4(),
        name=name,
        src_range_start=sport,
        src_range_end=sport,
        dst_range_start=dport,
        dst_range_end=dport,
    )


def test_several_ports_of_one_protocol_are_one_set():
    assert (
        _print_element([_tcp('ssh', 22), _tcp('http', 80)]) == 'tcp dport != { 22, 80 }'
    )


def test_several_icmp_messages_are_one_concatenation():
    """One rule each says "not echo-request *or* not echo-reply".

    Every ICMP packet satisfies that as soon as the two types differ, so a
    Deny rule written for "any ICMP but ping" dropped ping as well.
    """
    request = ICMPService(id=uuid.uuid4(), name='ping', data={'type': 8, 'code': 0})
    reply = ICMPService(id=uuid.uuid4(), name='pong', data={'type': 0, 'code': 0})
    assert _print_element([request, reply]) == (
        'icmp type . icmp code != { echo-request . 0, echo-reply . 0 }'
    )


def test_several_icmp_types_without_a_code_are_one_set():
    request = ICMPService(id=uuid.uuid4(), name='ping', data={'type': 8})
    reply = ICMPService(id=uuid.uuid4(), name='pong', data={'type': 0})
    assert _print_element([request, reply]) == (
        'icmp type != { echo-request, echo-reply }'
    )


def test_several_packet_marks_are_one_set():
    from firewallfabrik.core.objects import TagService

    one = TagService(id=uuid.uuid4(), name='one', data={'tagcode': '1'})
    two = TagService(id=uuid.uuid4(), name='two', data={'tagcode': '2'})
    assert _print_element([one, two]) == 'meta mark != { 1, 2 }'


def test_several_users_are_one_set():
    from firewallfabrik.core.objects import UserService

    a = UserService(id=uuid.uuid4(), name='a', userid='2000')
    b = UserService(id=uuid.uuid4(), name='b', userid='500')
    assert _print_element([a, b]) == 'meta skuid != { 2000, 500 }'


def test_a_whole_protocol_swallows_the_ports_of_it():
    """ "Anything but all TCP and but SSH" is "anything but TCP".

    Keeping the port match beside it asks for a TCP packet that is not
    port 22, which is exactly what the element excludes.
    """
    assert _print_element([_tcp('All TCP'), _tcp('ssh', 22)]) == 'meta l4proto != tcp'


def test_a_custom_service_cannot_be_excluded():
    from firewallfabrik.core.objects import CustomService

    custom = CustomService(id=uuid.uuid4(), name='c')
    assert _print_element([custom, _tcp('http', 80)]) is None


def test_a_nat_rule_keeps_a_negated_element_whole():
    """`SplitMultipleServices` gave every service a rule of its own.

    On a negated element that turns "translate nothing of these" into
    "not this *or* not that", and the rule then translated every packet
    it was written to leave alone.
    """
    from firewallfabrik.platforms.nftables._nat_compiler import SplitMultipleServices

    request = ICMPService(id=uuid.uuid4(), name='ping', data={'type': 8, 'code': 0})
    reply = ICMPService(id=uuid.uuid4(), name='pong', data={'type': 0, 'code': 0})
    rule = _nat_rule([request, reply])
    rule.osrv_single_object_negation = True

    processor = SplitMultipleServices(name='p')
    processor.compiler = _NATCompiler()
    processor.set_data_source(_Feeder([rule]))
    assert processor.process_next() is True
    assert [r.osrv for r in processor.tmp_queue] == [[request, reply]]


def _flagged() -> TCPService:
    return TCPService(
        id=uuid.uuid4(),
        name='syn only',
        dst_range_start=8443,
        dst_range_end=8443,
        tcp_flags_masks={'syn': True, 'ack': True},
        tcp_flags={'syn': True},
    )


def _separated(rule) -> list[list]:
    from firewallfabrik.compiler.processors._service import SeparateTCPWithFlags

    processor = SeparateTCPWithFlags(name='p')
    processor.compiler = _Compiler()
    processor.set_data_source(_Feeder([rule]))
    assert processor.process_next() is True
    return [r.srv for r in processor.tmp_queue]


def test_a_negated_element_is_not_separated_by_service_type():
    """`SeparateTCPWithFlags` and its siblings split on service *type*.

    That is right for an element whose objects are alternatives and wrong
    for a negated one: the halves say "not this *or* not that", so a
    packet the element excludes matches the half it is not named in.
    """
    flagged, plain = _flagged(), _tcp('http', 80)
    rule = _comp_rule([flagged, plain], negated=False)
    rule.srv_single_object_negation = True
    assert _separated(rule) == [[flagged, plain]]


def test_a_positive_element_is_still_separated():
    flagged, plain = _flagged(), _tcp('http', 80)
    assert _separated(_comp_rule([flagged, plain], negated=False)) == [
        [flagged],
        [plain],
    ]


class _Reporter:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, _rule, message: str) -> None:
        self.errors.append(message)


def _print_single(srv, proto: str) -> tuple[str | None, list[str]]:
    printer = PrintRule_nft.__new__(PrintRule_nft)
    printer.compiler = _Reporter()
    out = printer._print_tcp_udp_service(_Rule([srv], True), srv, proto)
    return out, printer.compiler.errors


def test_a_service_naming_both_ports_is_excluded_as_a_pair():
    """`sport != X dport != Y` is not the negation of `sport X dport Y`.

    It asks for a packet that is on neither, where the service names the
    combination - so a Deny rule written for "anything but 1024 to 443"
    let a packet from 1024 to any other port through.  nftables inverts a
    concatenated lookup as a whole.
    """
    srv = _tcp('mixed', dport=443, sport=1024)
    assert _print_single(srv, 'tcp') == (
        'tcp sport . tcp dport != { 1024 . 443 }',
        [],
    )


def test_a_flagged_service_naming_a_port_is_reported():
    out, errors = _print_single(_flagged(), 'tcp')
    assert out is None
    assert len(errors) == 1
    assert 'TCP flags' in errors[0]


def test_a_service_naming_both_ports_joins_the_others():
    assert _print_element([_tcp('mixed', dport=443, sport=1024), _tcp('http', 80)]) == (
        'tcp dport != 80 tcp sport . tcp dport != { 1024 . 443 }'
    )


def _srv_negation(rule, ipv6: bool = False) -> list:
    from firewallfabrik.platforms.nftables._policy_compiler import SrvNegation

    class _ChainCompiler(_Compiler):
        def __init__(self) -> None:
            super().__init__(ipv6)
            self.chains: list[str] = []

        def get_new_tmp_chain_name(self, _rule) -> str:
            self.chains.append(f'C{len(self.chains)}.0')
            return self.chains[-1]

    processor = SrvNegation(name='p')
    processor.compiler = _ChainCompiler()
    processor.set_data_source(_Feeder([rule]))
    assert processor.process_next() is True
    return list(processor.tmp_queue)


def test_a_flagged_service_with_a_port_gets_a_chain():
    """The shape firewall19 of the regression fixtures carries.

    `tcp dport != 5190 tcp flags ... != syn` is an AND of negations where
    the negation of a conjunction is needed, so the Reject rule written
    for "anything but a new AIM connection" rejected nothing else.
    """
    out = _srv_negation(_comp_rule([_flagged()]))
    assert [r.subrule_suffix for r in out] == ['1', '2', '3']
    jump, ret, action = out
    assert jump.srv == [] and jump.ipt_target == 'C0.0'
    assert [s.name for s in ret.srv] == ['syn only']
    assert ret.ipt_chain == 'C0.0'
    assert ret.action is PolicyAction.Return
    assert action.srv == [] and action.ipt_chain == 'C0.0'
    assert action.action is PolicyAction.Deny


def test_a_packet_mark_beside_a_port_gets_a_chain():
    """The shape firewall38 of the regression fixtures carries.

    A mark match says nothing about the protocol, so it is not disjoint
    from the rule the protocol split makes beside it: an HTTP packet with
    another mark matched "not mark 16" and was accepted, although the
    element excludes HTTP.
    """
    from firewallfabrik.core.objects import TagService

    tag = TagService(id=uuid.uuid4(), name='sixteen', data={'tagcode': '16'})
    out = _srv_negation(_comp_rule([tag, _tcp('http', 80)]))
    assert [r.subrule_suffix for r in out] == ['1', '2', '3']
    assert [s.name for s in out[1].srv] == ['sixteen', 'http']
    assert out[1].action is PolicyAction.Return
    assert out[2].srv == []


def test_an_element_the_rules_can_say_is_left_alone():
    out = _srv_negation(_comp_rule([_tcp('ssh', 22), _tcp('http', 80)]))
    assert len(out) == 1
    assert out[0].get_neg('srv') is True


def test_a_custom_service_keeps_the_old_answer():
    """A chain missing a return rule would act on all traffic.

    The print rule may not be able to match a Custom Service, so such an
    element is left for the printer to report rather than given a chain.
    """
    from firewallfabrik.core.objects import CustomService

    custom = CustomService(id=uuid.uuid4(), name='c')
    out = _srv_negation(_comp_rule([custom, _tcp('http', 80)]))
    assert len(out) == 1
    assert out[0].get_neg('srv') is True
