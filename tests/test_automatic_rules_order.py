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

"""The automatic rules come in the same order on iptables and nftables.

The order is the one of the iptables configlet
(``resources/configlets/linux24/automatic_rules``): established/related,
backup ssh, new TCP without SYN, IPv6 neighbour discovery, invalid. The drop
of INVALID packets is last, so a neighbour discovery message conntrack calls
INVALID - a truncated one, or one with a bad checksum in prerouting - is
accepted by the discovery rule on both packet filters alike.
"""

import pytest

from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.nftables._os_configurator import OSConfigurator_nft

_ORDER = ('established', 'ssh', 'no-syn', 'nd', 'invalid')


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
        'accept_new_tcp_with_no_syn': False,
        'add_rules_for_ipv6_neighbor_discovery': True,
        'bridging_fw': False,
        'drop_invalid': True,
        'linux24_ip_forward': '1',
        'linux24_ipv6_forward': '1',
        'log_invalid': False,
        'mgmt_addr': '2001:db8::9',
        'mgmt_ssh': True,
        'use_NFLOG': False,
        'use_iptables_restore': False,
    }
    options.update(overrides)
    return options


def _kind(line: str) -> str | None:
    if 'ESTABLISHED,RELATED -j ACCEPT' in line and '--sport 22' not in line:
        return 'established'
    if line == 'ct state established,related counter accept':
        return 'established'
    if 'dport 22' in line or 'sport 22' in line:
        return 'ssh'
    if '--tcp-flags SYN,RST,ACK SYN' in line or 'tcp flags != syn' in line:
        return 'no-syn'
    if '--hl-eq 255' in line or 'hoplimit 255' in line:
        return 'nd'
    if 'INVALID' in line or 'ct state invalid' in line:
        return 'invalid'
    return None


def _order(lines) -> list[str]:
    """Return the kinds of rule in the order they first appear."""
    seen = []
    for line in lines:
        kind = _kind(line.strip())
        if kind and kind not in seen:
            seen.append(kind)
    return seen


def _ipt_chain(chain: str, **overrides) -> list[str]:
    compiler = PolicyCompiler_ipt.__new__(PolicyCompiler_ipt)
    compiler.fw = _FakeFW(_options(**overrides))
    compiler.single_rule_compile_mode = False
    compiler.version = '1.8'
    compiler.ipv6_policy = True
    compiler.chain_prefix = ''
    compiler._warnings = []
    compiler.warning = compiler._warnings.append
    out = compiler.print_automatic_rules()
    return [line for line in out.splitlines() if f'-A {chain} ' in line]


def _nft_chain(chain: str, **overrides) -> list[str]:
    oc = OSConfigurator_nft.__new__(OSConfigurator_nft)
    oc.fw = _FakeFW(_options(**overrides))
    return oc.generate_automatic_rules(chain, have_ipv6=True).splitlines()


@pytest.mark.parametrize('log_invalid', [False, True])
@pytest.mark.parametrize(
    ('ipt_chain', 'nft_chain'), [('INPUT', 'input'), ('OUTPUT', 'output')]
)
def test_both_packet_filters_follow_the_configlet(ipt_chain, nft_chain, log_invalid):
    ipt = _order(_ipt_chain(ipt_chain, log_invalid=log_invalid))
    nft = _order(_nft_chain(nft_chain, log_invalid=log_invalid))
    assert ipt == list(_ORDER)
    assert nft == list(_ORDER)


def test_bridging_forward_chain_follows_the_configlet():
    # The backup ssh rule has no business in the forward chain, the
    # discovery rules only on a bridge.
    expected = [kind for kind in _ORDER if kind != 'ssh']
    assert _order(_ipt_chain('FORWARD', bridging_fw=True)) == expected
    assert _order(_nft_chain('forward', bridging_fw=True)) == expected
