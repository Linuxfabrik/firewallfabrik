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

"""What a NAT branch rule set filled in the other address-family pass.

A NAT branch rule set is compiled into named chains, and the rule that
branches into it needs to know which of them were filled so it can put its
jump in the matching built-in chain (`SplitNATBranchRule`).  The map that
answers that lives on the driver, and the nat table is per address family:
what a branch rule set filled for IPv4 says nothing about the IPv6 pass,
where it may not be compiled at all.

Jumping to a chain the pass never created is answered by `ip6tables` with
"No chain/target/match by that name", and the activation script stops
there with the built-in policies already set to DROP.
"""

import ast
import pathlib

import pytest

DRIVERS = {
    'iptables': 'src/firewallfabrik/platforms/iptables/_compiler_driver.py',
    'nftables': 'src/firewallfabrik/platforms/nftables/_compiler_driver.py',
}


def _address_family_loop(path: str) -> ast.For:
    """The `for policy_af in ...` loop of the driver's `run` method."""
    tree = ast.parse(pathlib.Path(path).read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and node.target.id == 'policy_af'
        ):
            return node
    raise AssertionError(f'no per-address-family loop found in {path}')


@pytest.mark.parametrize('platform', sorted(DRIVERS))
def test_the_branch_chain_map_is_cleared_per_address_family(platform):
    """Both drivers have to answer this the same way."""
    loop = _address_family_loop(DRIVERS[platform])

    cleared = [
        node
        for node in ast.walk(loop)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Attribute) and t.attr == '_nat_branch_chains'
            for t in node.targets
        )
        and isinstance(node.value, ast.Dict)
        and not node.value.keys
    ]
    assert cleared, (
        f'the {platform} driver carries the NAT branch chains of one address '
        'family into the next'
    )
