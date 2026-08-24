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

"""A Custom Service that does its own connection-state matching.

Such a service is split into a rule of its own and that rule is marked
stateless, so the compiler does not add its own ``NEW`` next to the
state the service already asks for - the two together match nothing.
fwbuilder decides it with a case-sensitive ``find("ESTABLISHED")``
(``PolicyCompiler_ipt::specialCasesWithCustomServices``), which is
narrower than what the tools accept:

    iptables -A INPUT -m conntrack --ctstate established,related -j ACCEPT
    -> -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

``libxt_conntrack.c`` and ``libxt_state.c`` compare the state names with
``strncasecmp``, and nftables knows the lowercase spelling and no other.
So an administrator may write either case - and the port asked
case-insensitively on nftables and case-sensitively on iptables, which
left one and the same Custom Service compiled stateless on one platform
and stateful on the other.
"""

import pytest

from firewallfabrik.platforms.linux._netfilter import custom_service_matches_state


@pytest.mark.parametrize(
    'code',
    [
        # What Firewall Builder's own standard library carries.
        '-m state --state ESTABLISHED,RELATED',
        '-m conntrack --ctstate ESTABLISHED',
        # The spelling both tools also take, and the only one nftables has.
        '-m conntrack --ctstate established,related',
        'ct state { established, related }',
        'ct state related',
        # Mixed case, because nothing stops it.
        '-m conntrack --ctstate Established',
    ],
)
def test_a_code_that_matches_on_the_connection_state(code):
    assert custom_service_matches_state(code)


@pytest.mark.parametrize(
    'code',
    [
        '',
        '-m rpc --rpcs 100003',
        'tcp dport 22',
        '-p tcp --tcp-flags SYN,ACK SYN',
    ],
)
def test_a_code_that_does_not(code):
    assert not custom_service_matches_state(code)


def test_both_platforms_ask_the_same_question():
    """The two `SpecialCasesWithCustomServices` used to differ in case.

    Reading the predicate out of the shared module is what keeps them
    from drifting again; this pins that both import the same one.
    """
    from firewallfabrik.platforms.iptables import _policy_compiler as ipt
    from firewallfabrik.platforms.nftables import _policy_compiler as nft

    assert ipt.custom_service_matches_state is custom_service_matches_state
    assert nft.custom_service_matches_state is custom_service_matches_state
