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

"""When the IPv6 kernel-hardening lines are written.

`net.ipv6.conf.*/accept_redirects` and `.../accept_source_route` are host
settings, not rules: what decides them is whether the firewall speaks IPv6
at all.  The iptables driver used to pass a flag that says something else -
whether the IPv6 pass had produced at least one command - so a firewall
with an IPv6 policy whose rules were all dropped hardened its IPv4 stack
and left its IPv6 stack alone, while the nftables driver hardened both.

One option has to mean one thing on either platform, so both drivers ask
the same question.
"""

import ast
import inspect

from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft


def _argument_of(source: str, method: str) -> str:
    """The first argument of the one call to *method* in *source*."""
    calls = [
        node
        for node in ast.walk(ast.parse(inspect.cleandoc(source)))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
    ]
    assert len(calls) == 1, f'{len(calls)} calls to {method}'
    return ast.unparse(calls[0].args[0])


def test_both_drivers_ask_whether_the_firewall_speaks_ipv6():
    ipt = _argument_of(
        inspect.getsource(CompilerDriver_ipt.run), 'process_firewall_options'
    )
    nft = _argument_of(
        inspect.getsource(CompilerDriver_nft._assemble_shell_script),
        'process_firewall_options',
    )
    assert ipt == 'any_rs_ipv6'
    assert nft == 'self._any_rs_ipv6'


def test_the_two_names_stand_for_the_same_expression():
    """Both are `any(rs.ipv6 for rs in (*all_policies, *all_nat))`."""
    for source in (
        inspect.getsource(CompilerDriver_ipt.run),
        inspect.getsource(CompilerDriver_nft.run),
    ):
        assert 'any(rs.ipv6 for rs in (*all_policies, *all_nat))' in source
