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

"""The mark a Tag Service carries, before it reaches either packet filter.

The value is free text from the Tag Service editor, and neither back end
takes a word: iptables answers "bad integer value for option" or "trailing
garbage after value" and stops the activation script with every built-in
policy already at DROP, nftables answers a syntax error and refuses the
whole ruleset.  It also goes into the generated script as a bare shell
word, which is the reason the ToS value and the rate-limit table name are
guarded next door.

Every case below was offered to iptables 1.8.11 and nft 1.1.6 first; both
store ``020`` as 16 and both refuse 4294967296.
"""

import uuid

import pytest

from firewallfabrik.core.objects import TagService, is_valid_packet_mark


@pytest.mark.parametrize(
    'value',
    [
        '1',
        '0',
        '0x10',
        # Base 0, so a leading zero is octal.
        '020',
        '4294967295',
        '10/10',
        '0x10/0xff',
    ],
)
def test_a_mark_both_packet_filters_read(value):
    assert is_valid_packet_mark(value)


@pytest.mark.parametrize(
    'value',
    [
        '',
        # A word: iptables says "bad integer value", nftables a syntax error.
        'foo',
        # Trailing garbage; iptables names it, nftables cannot parse it.
        '5abc',
        # One past UINT32_MAX, refused by both.
        '4294967296',
        '4294967295/4294967296',
        # Not part of any spelling either tool accepts.
        '-1',
        '1/2/3',
        # Shell syntax, which is the reason this is checked at all.
        '$(id)',
        '1;reboot',
        '`id`',
        '1 -j ACCEPT',
    ],
)
def test_a_mark_neither_packet_filter_reads(value):
    assert not is_valid_packet_mark(value)


def _tag(code: str) -> TagService:
    service = TagService(id=uuid.uuid4(), name='tag')
    service.data = {'tagcode': code}
    return service


class _Compiler:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.ipv6_policy = False
        self.version = ''

    def error(self, _rule, msg: str = '') -> None:
        self.errors.append(msg)

    @staticmethod
    def my_platform_name() -> str:
        return 'iptables'


class _Rule:
    """The bit of a rule the four service printers reach for."""

    type = 'PolicyRule'
    srv_single_object_negation = False
    osrv_single_object_negation = False
    merged_tcp_udp = False

    def __init__(self, srv) -> None:
        self.srv = [srv]
        self.osrv = [srv]

    @staticmethod
    def is_osrv_any() -> bool:
        return False

    @staticmethod
    def get_option(_key, default=None):
        return default

    @staticmethod
    def get_neg(_slot):
        return False


def _ipt_policy(srv, rule):
    from firewallfabrik.platforms.iptables._print_rule import PrintRule

    printer = PrintRule(name='ipt policy')
    printer.compiler = _Compiler()
    return printer, printer._print_custom_services(rule, srv)


def _ipt_nat(srv, rule):
    from firewallfabrik.platforms.iptables._nat_print_rule import NATPrintRule

    printer = NATPrintRule(name='ipt nat')
    printer.compiler = _Compiler()
    return printer, printer._print_dst_service(rule)


def _nft_policy(srv, rule):
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    printer = PrintRule_nft(name='nft policy')
    printer.compiler = _Compiler()
    return printer, printer._print_service(rule, srv)


def _nft_nat(srv, rule):
    from firewallfabrik.platforms.nftables._nat_print_rule import NATPrintRule_nft

    printer = NATPrintRule_nft(name='nft nat')
    printer.compiler = _Compiler()
    return printer, printer._print_service(srv, rule)


PRINTERS = (_ipt_policy, _ipt_nat, _nft_policy, _nft_nat)


@pytest.mark.parametrize('render', PRINTERS, ids=lambda f: f.__name__)
def test_every_printer_leaves_out_a_rule_whose_tag_is_not_a_mark(render):
    """All four write the mark out, so all four have to check it."""
    srv = _tag('$(id)')
    printer, answer = render(srv, _Rule(srv))

    assert answer is None
    assert any('not a packet mark' in message for message in printer.compiler.errors)


@pytest.mark.parametrize('render', PRINTERS, ids=lambda f: f.__name__)
def test_every_printer_still_writes_a_mark_both_tools_read(render):
    srv = _tag('0x10/0xff')
    printer, answer = render(srv, _Rule(srv))

    assert answer is not None
    assert '0x10' in answer
    assert printer.compiler.errors == []


class _Session:
    """A session that answers with the one Tag Service the rule names."""

    def __init__(self, service) -> None:
        self._service = service

    def get(self, _model, _id):
        return self._service


class _TaggingRule(_Rule):
    """A rule that sets the mark instead of matching on it."""

    def __init__(self, srv, tag_id) -> None:
        super().__init__(srv)
        self.ipt_target = 'MARK'
        self._tag_id = tag_id

    def get_option(self, key, default=None):
        if key == 'tagging':
            return True
        if key == 'tagobject_id':
            return self._tag_id
        return default


def test_the_iptables_target_leaves_out_a_rule_whose_tag_is_not_a_mark():
    from firewallfabrik.platforms.iptables._print_rule import PrintRule

    srv = _tag('1;reboot')
    printer = PrintRule(name='ipt policy')
    printer.compiler = _Compiler()
    printer.compiler.session = _Session(srv)
    rule = _TaggingRule(srv, str(srv.id))

    assert printer._print_target(rule) is None
    assert any('not a packet mark' in message for message in printer.compiler.errors)


def test_the_nftables_statement_leaves_out_a_rule_whose_tag_is_not_a_mark():
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    srv = _tag('1;reboot')
    printer = PrintRule_nft(name='nft policy')
    printer.compiler = _Compiler()
    printer.compiler.session = _Session(srv)
    rule = _TaggingRule(srv, str(srv.id))

    assert printer._print_mangle_statement(rule) is None
    assert any('not a packet mark' in message for message in printer.compiler.errors)
