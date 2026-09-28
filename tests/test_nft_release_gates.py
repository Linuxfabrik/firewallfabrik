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

"""Spellings an older nftables cannot parse, and the release that can.

Each of these was found by loading the corpus, compiled for the release a
distribution ships, on that distribution: nftables loads a ruleset in one
transaction, so one line it cannot parse costs the whole firewall.  The
newer spelling is kept wherever the release reads it, because it is what
current nftables prints back.

* `tcp flags syn / syn,rst,ack` - v0.9.9 (Debian 11 and Leap 15.5 ship
  0.9.8);
* `reject with icmp <code>` without `type` - v1.0.0;
* `priority dstnat` on the output hook - v1.0.9 (Debian 12 ships 1.0.6).
"""

import pytest

from firewallfabrik.platforms.nftables._utils import (
    nft_chain_priority,
    nft_tcp_flags,
)


class _Fw:
    platform = 'nftables'

    def __init__(self, version):
        self.version = version


@pytest.mark.parametrize(
    ('version', 'expected'),
    [
        ('', 'tcp flags syn / syn,rst,ack'),
        ('0.9.9', 'tcp flags syn / syn,rst,ack'),
        ('0.9.5', 'tcp flags & (syn | rst | ack) == syn'),
        ('0.9.1', 'tcp flags & (syn | rst | ack) == syn'),
    ],
)
def test_the_flag_mask_notation_needs_0_9_9(version, expected):
    assert nft_tcp_flags(_Fw(version), ['syn'], ['syn', 'rst', 'ack']) == expected


def test_a_negated_flag_match_keeps_its_operator_in_both_spellings():
    assert (
        nft_tcp_flags(_Fw(''), ['syn'], ['syn', 'rst', 'ack'], negated=True)
        == 'tcp flags != syn / syn,rst,ack'
    )
    assert (
        nft_tcp_flags(_Fw('0.9.5'), ['syn'], ['syn', 'rst', 'ack'], negated=True)
        == 'tcp flags & (syn | rst | ack) != syn'
    )


@pytest.mark.parametrize(
    ('version', 'prerouting', 'output'),
    [
        ('', 'dstnat', 'dstnat'),
        ('1.0.9', 'dstnat', 'dstnat'),
        ('1.0.0', 'dstnat', '-100'),
        ('0.9.1', 'dstnat', '-100'),
        ('0.9.0', '-100', '-100'),
    ],
)
def test_a_nat_priority_is_named_on_the_output_hook_from_1_0_9(
    version, prerouting, output
):
    fw = _Fw(version)
    assert nft_chain_priority(fw, 'dstnat', hook='prerouting') == prerouting
    assert nft_chain_priority(fw, 'dstnat', hook='output') == output


class _Compiler:
    def __init__(self, version, ipv6=False):
        self.fw = _Fw(version)
        self.ipv6_policy = ipv6
        self.messages = []

    def warning(self, _rule, msg=''):
        self.messages.append(msg)


class _Rule:
    def __init__(self, action_on_reject):
        self._options = {'action_on_reject': action_on_reject}

    def get_option(self, key, default=None):
        return self._options.get(key, default)


@pytest.mark.parametrize(
    ('version', 'ipv6', 'expected'),
    [
        ('', False, 'reject with icmp host-unreachable'),
        ('1.0.0', False, 'reject with icmp host-unreachable'),
        ('0.9.5', False, 'reject with icmp type host-unreachable'),
        ('0.9.5', True, 'reject with icmpv6 type addr-unreachable'),
    ],
)
def test_the_reject_code_drops_its_type_keyword_from_1_0_0(version, ipv6, expected):
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    printer = PrintRule_nft.__new__(PrintRule_nft)
    printer.compiler = _Compiler(version, ipv6)
    assert printer._print_reject(_Rule('ICMP host unreachable')) == expected


def test_a_translated_custom_service_follows_the_flag_spelling():
    """The Custom Service translation writes flag matches of its own."""
    from firewallfabrik.platforms.linux._netfilter import custom_service_nftables_code

    code = '-p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK'
    assert ' / ' in custom_service_nftables_code(code)
    old = custom_service_nftables_code(code, flag_mask=False)
    assert ' / ' not in old
    assert 'tcp flags & (' in old


@pytest.mark.parametrize(
    ('version', 'kept'), [('', True), ('0.9.1', True), ('0.9.0', False)]
)
def test_a_rate_limit_per_key_needs_0_9_1(version, kept):
    """0.9.0 is also the entry RHEL 8.0 to 8.5 take, whose kernel refuses it."""
    import uuid

    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.core.objects import PolicyAction
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    class _KeyedCompiler(_Compiler):
        muted_now = True  # a rehearsal: nothing is registered

        def error(self, _rule, msg=''):
            self.messages.append(msg)

        def get_rule_set_name(self):
            return 'Policy'

        def register_meter(self, *_args):
            return True, True

    printer = PrintRule_nft.__new__(PrintRule_nft)
    printer.compiler = _KeyedCompiler(version)
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0',
        comment='',
        options={'hashlimit_value': 10, 'hashlimit_mode_srcip': True},
        negations={},
        action=PolicyAction.Accept,
    )
    out = printer._print_hashlimit(rule)
    assert (out is not None) is kept
