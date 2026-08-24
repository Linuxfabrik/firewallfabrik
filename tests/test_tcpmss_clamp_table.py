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

"""Which table the TCPMSS clamp goes into, and when it is left out.

Firewall Builder emits the rule from one method and decides the table by
the pinned release, with the same comment above both call sites:
"iptables accepted TCPMSS target in filter table, FORWARD chain in the
older versions, but requires it to be in mangle filter starting somewhere
1.3.x".  Below 1.3.0 it is ``PolicyCompiler_ipt::printAutomaticRules``,
from 1.3.0 on ``MangleTableCompiler_ipt::printAutomaticRulesForMangle
Table``.

fwf had only the second half, so a firewall pinning an older release got
no clamp at all - the reference output for firewall10 (1.2.9),
firewall2-1 and firewall61-1.2.5 (both "1.2.5 or earlier") carries the
filter-table form and fwf produced nothing.  Path MTU discovery then goes
unhelped on exactly the forwarding firewalls the option exists for.

Current kernels take the target in either table: ``xt_TCPMSS`` registers
no ``.table`` restriction (net/netfilter/xt_TCPMSS.c), and iptables
1.8.11 accepts ``-t filter -A FORWARD ... -j TCPMSS
--clamp-mss-to-pmtu``, so the old form still loads.
"""

import pytest

from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt

CLAMP = 'FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'


class _Firewall:
    def __init__(self, **options) -> None:
        self.options = {'clamp_mss_to_mtu': True, 'version': ''}
        self.options.update(options)

    def get_option(self, key, default=None):
        return self.options.get(key, default)


class _Compiler:
    """Just enough of the compiler for ``clamp_tcp_to_mss_rule``."""

    clamp_tcp_to_mss_rule = PolicyCompiler_ipt.clamp_tcp_to_mss_rule

    def __init__(self, fw, ipv6=False, version='1.4.0') -> None:
        self.fw = fw
        self.ipv6_policy = ipv6
        self.version = version
        self.warnings: list[str] = []

    def warning(self, msg, *_args) -> None:
        self.warnings.append(msg)


def test_a_forwarding_firewall_gets_the_clamp():
    assert _Compiler(_Firewall()).clamp_tcp_to_mss_rule() == CLAMP


def test_the_option_being_off_leaves_it_out():
    fw = _Firewall(clamp_mss_to_mtu=False)
    assert _Compiler(fw).clamp_tcp_to_mss_rule() == ''


def test_a_firewall_that_does_not_forward_gets_no_clamp():
    """The rule only ever acts on forwarded traffic."""
    fw = _Firewall(linux24_ip_forward='0')
    assert _Compiler(fw).clamp_tcp_to_mss_rule() == ''


def test_no_change_counts_as_forwarding():
    """An empty setting leaves the kernel alone, so the box may forward."""
    fw = _Firewall(linux24_ip_forward='')
    assert _Compiler(fw).clamp_tcp_to_mss_rule() == CLAMP


def test_the_ipv6_pass_asks_the_ipv6_switch():
    fw = _Firewall(linux24_ip_forward='1', linux24_ipv6_forward='0')
    assert _Compiler(fw, ipv6=True).clamp_tcp_to_mss_rule() == ''


@pytest.mark.parametrize('version', ['1.2.9', '1.3.0', '1.3.7'])
def test_ip6tables_before_1_3_8_says_so_instead_of_going_quiet(version):
    """fwbuilder bug #2477775; libip6t_TCPMSS.c first ships in 1.3.8."""
    compiler = _Compiler(_Firewall(), ipv6=True, version=version)
    answer = compiler.clamp_tcp_to_mss_rule()
    assert answer.startswith('# target TCPMSS is not supported')
    assert compiler.warnings


def test_ip6tables_from_1_3_8_on_gets_the_rule():
    compiler = _Compiler(_Firewall(), ipv6=True, version='1.3.8')
    assert compiler.clamp_tcp_to_mss_rule() == CLAMP
    assert compiler.warnings == []


def test_a_firewall_that_does_not_forward_ipv6_is_not_told_about_the_release():
    """Nothing would have been emitted anyway, so there is nothing to say."""
    fw = _Firewall(linux24_ipv6_forward='0')
    compiler = _Compiler(fw, ipv6=True, version='1.2.9')
    assert compiler.clamp_tcp_to_mss_rule() == ''
    assert compiler.warnings == []
