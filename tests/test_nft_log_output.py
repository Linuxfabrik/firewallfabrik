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

"""Tests for the nftables log statement.

nftables refuses a log statement that carries both a netlink group and
log flags ("flags and group are mutually exclusive", netfilter nftables
src/evaluate.c), which makes the whole ruleset fail to load.
"""

import io
import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


class _FakeFw:
    def __init__(self, options):
        self.version = ''
        self._options = options

    def get_option(self, key, default=None):
        return self._options.get(key, default)


class _FakeNftCompiler:
    def __init__(self, options):
        self.fw = _FakeFw(options)
        self.ipv6_policy = False
        # Single-family table, so no rule needs a `meta nfproto` qualifier
        # and the assertions below see the match clauses on their own.
        self.shared_inet_table = False
        self.output = io.StringIO()
        self.warnings: list[str] = []

    def my_platform_name(self):
        return 'nftables'

    def error(self, rule, msg):
        raise AssertionError(msg)

    def warning(self, rule, msg):
        self.warnings.append(msg)

    def get_errors_for_rule(self, rule):
        return ''


def _make_rule():
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='test',
        comment='',
        options={'stateless': True},
        negations={},
        action=PolicyAction.Accept,
        direction=Direction.Inbound,
        ipt_chain='input',
        ipt_target='ACCEPT',
    )


def _render(options):
    rule = _make_rule()
    rule.nft_log = True
    pr = PrintRule_nft()
    pr.compiler = _FakeNftCompiler(options)
    return pr._build_rule(rule), pr.compiler.warnings


_LOG_FLAGS = {
    'log_ip_opt': True,
    'log_tcp_opt': True,
    'log_tcp_seq': True,
}


def test_log_flags_emitted_without_nflog():
    line, warnings = _render({'log_level': 'info', **_LOG_FLAGS})
    assert 'flags tcp sequence' in line
    assert 'flags tcp options' in line
    assert 'flags ip options' in line
    assert not warnings


def test_log_flags_dropped_with_nflog():
    line, warnings = _render({'use_NFLOG': True, 'ulog_nlgroup': 1, **_LOG_FLAGS})
    assert 'log group 1' in line
    assert 'flags' not in line
    assert warnings


def test_nflog_copy_range_and_queue_threshold():
    line, _ = _render(
        {
            'ulog_cprange': 256,
            'ulog_nlgroup': 2,
            'ulog_qthreshold': 25,
            'use_NFLOG': True,
        }
    )
    assert 'log group 2 snaplen 256 queue-threshold 25' in line


def test_nflog_defaults_stay_out_of_the_rule():
    line, _ = _render(
        {
            'ulog_cprange': 0,
            'ulog_nlgroup': 1,
            'ulog_qthreshold': 1,
            'use_NFLOG': True,
        }
    )
    assert 'snaplen' not in line
    assert 'queue-threshold' not in line


def test_iptables_rejects_a_log_level_it_does_not_know():
    """`--log-level audit` is answered with `log level "audit" unknown`.

    That stops the activation script with the built-in policies already at
    DROP, so the level is dropped and the rule logs at the target's
    default.  Verified against iptables 1.8.11 in a network namespace,
    where `audit` and `bogus` are refused and `info`, `6`, `panic` and
    `warning` are taken.
    """
    from firewallfabrik.platforms.iptables._print_rule import _is_known_log_level

    assert not _is_known_log_level('audit')
    assert not _is_known_log_level('bogus')
    assert not _is_known_log_level('8')
    assert _is_known_log_level('info')
    assert _is_known_log_level('6')
    assert _is_known_log_level('panic')
    assert _is_known_log_level('warning')
