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

"""A rule on several interfaces is one rule per interface before any chain.

``checkInterfaceAgainstAddressFamily`` and every chain decision behind it
read the *first* interface of the rule, so a rule the editor shows on
"eth0, eth1" has to become one rule per interface first.  Firewall Builder
splits it exactly there and says why: "trying process rules with multiple
interfaces as late as possible" - as late as possible, but still ahead of
``checkInterfaceAgainstAddressFamily`` (``PolicyCompiler_ipt.cpp:4580``).

With the split behind those, a dual-stack rule on an IPv4-only and an
IPv6-only interface is compiled for whichever family the first interface
carries and disappears from the other one: firewall-ipv6-5 of the Firewall
Builder reference corpus emits its rule 2 for eth0 in the IPv4 pass and for
eth1 in the IPv6 pass, and fwf emitted it for both interfaces in the IPv4
pass and not at all in the IPv6 one.
"""

import pytest

from tests.test_expand_before_chain_decisions import (
    _POLICY_COMPILERS,
    _pipeline_order,
)

#: What each platform calls "one rule per interface".
_SPLITTERS = {
    'iptables': 'InterfacePolicyRulesWithOptimization',
    'nftables': 'ConvertToAtomicForInterfaces',
}

#: Everything that reads the rule's first interface afterwards.
_READS_THE_FIRST_INTERFACE = (
    'CheckInterfaceAgainstAddressFamily',
    'DecideOnChainIfLoopback',
    'FinalizeChain',
    'SpecialCaseWithFWInDstAndOutbound',
)


@pytest.mark.parametrize('platform', sorted(_POLICY_COMPILERS))
def test_the_rule_is_split_per_interface_before_the_chain_is_decided(platform):
    order = _pipeline_order(_POLICY_COMPILERS[platform])
    splitter = _SPLITTERS[platform]

    assert splitter in order, f'{splitter} is missing from the {platform} pipeline'
    split_at = order.index(splitter)

    for name in _READS_THE_FIRST_INTERFACE:
        assert name in order, f'{name} is missing from the {platform} pipeline'
        assert order.index(name) > split_at, (
            f'{name} runs before the rule is split per interface on '
            f'{platform}, so it answers for the whole rule what it was '
            f'asked about one interface'
        )
