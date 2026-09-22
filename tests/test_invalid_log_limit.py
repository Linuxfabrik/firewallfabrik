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

"""Packets in state INVALID are dropped and logged, at the logging limit.

Both options are on by default, so a packet conntrack rejects is logged
with its own prefix instead of turning up as a policy hit of the catch-all
rule. The log obeys the firewall's logging limit, which defaults to
10/second, so a flood of such packets does not fill the kernel log.
"""

import pytest

from firewallfabrik.platforms._defaults import get_platform_defaults
from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.nftables._os_configurator import OSConfigurator_nft


class _FakeFW:
    version = ''

    def __init__(self, options):
        self._options = options

    def get_option(self, key):
        return self._options.get(key)

    @property
    def interfaces(self):
        return []


def _options(**overrides):
    options = {
        'accept_established': True,
        'accept_new_tcp_with_no_syn': True,
        'add_rules_for_ipv6_neighbor_discovery': False,
        'bridging_fw': False,
        'drop_invalid': True,
        'limit_suffix': '/second',
        'limit_value': 10,
        'linux24_ip_forward': '1',
        'linux24_ipv6_forward': '1',
        'log_invalid': True,
        'mgmt_ssh': False,
        'use_NFLOG': False,
        'use_iptables_restore': False,
    }
    options.update(overrides)
    return options


def _ipt(**overrides) -> tuple[list[str], list[str]]:
    compiler = PolicyCompiler_ipt.__new__(PolicyCompiler_ipt)
    compiler.fw = _FakeFW(_options(**overrides))
    compiler.single_rule_compile_mode = False
    compiler.version = '1.8'
    compiler.ipv6_policy = False
    compiler.chain_prefix = ''
    warnings = []
    compiler.warning = warnings.append
    out = compiler.print_automatic_rules()
    lines = [line.strip() for line in out.splitlines() if 'drop_invalid' in line]
    return lines, warnings


def _nft(**overrides) -> tuple[list[str], list[str]]:
    oc = OSConfigurator_nft.__new__(OSConfigurator_nft)
    oc.fw = _FakeFW(_options(**overrides))
    warnings = []
    oc.warning = warnings.append
    out = oc.generate_automatic_rules('input', have_ipv6=False)
    lines = [line.strip() for line in out.splitlines() if 'ct state invalid' in line]
    return lines, warnings


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_drop_and_log_invalid_at_ten_per_second_by_default(platform):
    schema = get_platform_defaults(platform)
    assert schema['drop_invalid']['default'] is True
    assert schema['log_invalid']['default'] is True
    assert schema['limit_value']['default'] == 10
    assert schema['limit_suffix']['default'] == '/second'


def test_ipt_logs_at_the_limit():
    lines, warnings = _ipt()
    assert (
        '$IPTABLES -A drop_invalid -m limit --limit 10/second -j LOG '
        '--log-level debug --log-prefix "INVALID state -- DENY "'
    ) in lines
    assert '$IPTABLES -A drop_invalid -j DROP' in lines
    assert not warnings


def test_ipt_nflog_logs_at_the_limit():
    lines, _ = _ipt(use_NFLOG=True, limit_value=3, limit_suffix='/minute')
    assert any(
        line.startswith('$IPTABLES -A drop_invalid -m limit --limit 3/minute -j NFLOG')
        for line in lines
    )


def test_ipt_no_limit_when_it_is_off():
    lines, _ = _ipt(limit_value=0)
    assert not any('-m limit' in line for line in lines)
    assert any('-j LOG' in line for line in lines)


def test_ipt_reports_a_rate_the_limit_match_cannot_express():
    lines, warnings = _ipt(limit_value=20000)
    assert not any('-m limit' in line for line in lines)
    assert any('faster than the iptables limit match' in w for w in warnings)


def test_nft_logs_at_the_limit_and_drops_every_invalid_packet():
    # `limit` is a match: sharing one rule with the drop would let a packet
    # above the rate skip the drop and go on to the policy.
    lines, warnings = _nft()
    assert lines == [
        'ct state invalid limit rate 10/second counter log prefix '
        '"INVALID state -- DENY " level debug',
        'ct state invalid counter drop',
    ]
    assert not warnings


def test_nft_one_rule_when_the_limit_is_off():
    lines, _ = _nft(limit_value=0)
    assert lines == [
        'ct state invalid counter log prefix "INVALID state -- DENY " level debug drop'
    ]


def test_nft_no_log_rule_without_log_invalid():
    lines, _ = _nft(log_invalid=False)
    assert lines == ['ct state invalid counter drop']


def test_ipt_no_log_without_log_invalid():
    lines, _ = _ipt(log_invalid=False)
    assert not any('drop_invalid' in line for line in lines)


def test_ipt_iptables_restore_format():
    lines, _ = _ipt(use_iptables_restore=True)
    assert (
        'echo "-A drop_invalid -m limit --limit 10/second -j LOG '
        '--log-level debug --log-prefix \\"INVALID state -- DENY \\""'
    ) in lines


@pytest.mark.parametrize('build', [_ipt, _nft])
def test_an_unknown_unit_is_reported_and_logged_without_a_limit(build):
    lines, warnings = build(limit_suffix='/fortnight')
    assert not any('limit' in line for line in lines)
    assert any('"/fortnight" is not a unit' in w for w in warnings)
