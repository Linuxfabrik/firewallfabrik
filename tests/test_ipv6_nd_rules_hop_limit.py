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

"""The IPv6 neighbour discovery rules need a match old ip6tables has not.

Every one of them carries ``-m hl --hl-eq 255``, and ``libip6t_hl.c``
first ships in iptables 1.2.8 (re-derived from the netfilter history by
``test_ipt_version_gates.py``).  An older ip6tables answers "Couldn't
load match `hl'", which stops the activation script with the built-in
policies already set to DROP - so the firewall ends up with no rules at
all rather than without neighbour discovery.

``-m icmp6`` beside it needs no gate: the extension registers itself
under that name as far back as v1.2.5, under the file name
``libip6t_icmpv6.c``.

Firewall Builder emits the rules whatever the release - the same lines
are in its own ``automatic_rules`` configlet with no gate around them -
so leaving them out is a deliberate divergence.  The nftables compiler
needs nothing: ``ip6 hoplimit`` is an ordinary header field and has been
there since the oldest release a firewall can name here.
"""

from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.iptables._utils import (
    MATCH_FIRST_RELEASE,
    get_iptables_version,
    version_compare,
)

_ND_MARKER = 'rules to permit IPv6 Neighbor discovery'


def _hl_warnings(warnings: list) -> list:
    """Only the ones about the hop limit.

    A release below 1.2.8 is also below the 1.3.5 the connection state
    match needs, and that gate reports next door; asserting on the whole
    list would make this test fail for the neighbour's reason.
    """
    return [w for w in warnings if '"hl"' in w]


class _FakeFW:
    version = ''
    platform = 'iptables'

    def __init__(self, options):
        self._options = options

    def get_option(self, key):
        return self._options.get(key)

    @property
    def interfaces(self):
        return []


def _automatic_rules(version: str, ipv6: bool = True, **overrides) -> tuple[str, list]:
    options = {
        'accept_established': True,
        'accept_new_tcp_with_no_syn': True,
        'add_rules_for_ipv6_neighbor_discovery': True,
        'bridging_fw': False,
        'drop_invalid': False,
        'linux24_ip_forward': '1',
        'linux24_ipv6_forward': '1',
        'log_invalid': False,
        'mgmt_addr': '',
        'mgmt_ssh': False,
        'use_NFLOG': False,
        'use_iptables_restore': False,
    }
    options.update(overrides)

    compiler = PolicyCompiler_ipt.__new__(PolicyCompiler_ipt)
    compiler.fw = _FakeFW(options)
    compiler.single_rule_compile_mode = False
    compiler.version = version
    compiler.ipv6_policy = ipv6
    compiler.chain_prefix = ''
    warnings: list[str] = []
    compiler.warning = warnings.append
    return compiler.print_automatic_rules(), warnings


def test_the_rules_are_written_for_a_release_that_has_the_match():
    out, warnings = _automatic_rules('1.2.8')
    assert _ND_MARKER in out
    assert '-m hl --hl-eq 255' in out
    assert not _hl_warnings(warnings)


def test_the_rules_are_left_out_below_that_release():
    out, warnings = _automatic_rules('ge_1.2.6')
    assert _ND_MARKER not in out
    assert '-m hl' not in out
    assert any('no "hl" match' in w for w in warnings), warnings


def test_an_unpinned_firewall_gets_the_rules():
    """An empty release means the newest, not the oldest.

    ``version_compare('', '1.2.8')`` is negative, so a gate reading the
    stored value would take the rules away from every firewall that names
    no release - which is most of them.  What the compiler asks is
    ``get_iptables_version``, which answers the current release for an
    empty field, and that is the invariant this gate rests on.
    """
    resolved = get_iptables_version(_FakeFW({}))
    assert version_compare(resolved, MATCH_FIRST_RELEASE['hl'][1]) >= 0
    out, warnings = _automatic_rules(resolved)
    assert _ND_MARKER in out
    assert not _hl_warnings(warnings)


def test_nothing_is_said_when_the_rules_were_not_wanted():
    _, warnings = _automatic_rules(
        'ge_1.2.6', add_rules_for_ipv6_neighbor_discovery=False
    )
    assert not _hl_warnings(warnings)


def test_the_ipv4_pass_never_carries_them():
    out, warnings = _automatic_rules('ge_1.2.6', ipv6=False)
    assert _ND_MARKER not in out
    assert not _hl_warnings(warnings)
