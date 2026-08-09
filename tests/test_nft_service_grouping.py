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

"""Splitting a service list into the rules one nft rule can carry.

One nft rule holds a single destination port set, so a service list has to
be split before it is printed. Two things decide the split: services that
disagree on the source port cannot share a set, and a service that names no
port at all cannot be a member of one.
"""

import pytest

from firewallfabrik.core.objects import ICMPService, TCPService, UDPService
from firewallfabrik.platforms.nftables._policy_compiler import GroupServicesByProtocol


def _srv(cls, sport=(0, 0), dport=(0, 0), name='s'):
    srv = cls()
    srv.name = name
    srv.src_range_start, srv.src_range_end = sport
    srv.dst_range_start, srv.dst_range_end = dport
    return srv


def _chunks(srvs):
    return GroupServicesByProtocol._printable_chunks(srvs)


def test_services_sharing_a_source_port_stay_together():
    http = _srv(TCPService, dport=(80, 80), name='http')
    https = _srv(TCPService, dport=(443, 443), name='https')
    assert _chunks([http, https]) == [[http, https]]


def test_services_differing_in_source_port_are_split():
    a = _srv(TCPService, sport=(1024, 65535), dport=(80, 80), name='a')
    b = _srv(TCPService, sport=(53, 53), dport=(80, 80), name='b')
    assert sorted(len(c) for c in _chunks([a, b])) == [1, 1]


def test_a_service_naming_no_port_gets_a_rule_of_its_own():
    """Otherwise it vanishes into the port set and stops matching at all."""
    all_tcp = _srv(TCPService, name='All TCP')
    http = _srv(TCPService, dport=(80, 80), name='http')
    assert _chunks([all_tcp, http]) == [[all_tcp], [http]]


def test_non_tcp_services_each_get_a_rule():
    a = _srv(ICMPService, name='echo request')
    b = _srv(ICMPService, name='echo reply')
    assert _chunks([a, b]) == [[a], [b]]


@pytest.mark.parametrize(
    ('tcp', 'udp', 'expected'),
    [
        # The same single service on both protocols: one merged rule.
        ([((0, 0), (53, 53))], [((0, 0), (53, 53))], True),
        # Same destination ports, same source ports, but not the same
        # PAIRS. Merging would emit the cross product,
        # `th sport { 1, 2 } th dport { 80, 25 }`, which lets through what
        # only one of the two services allowed.
        (
            [((1, 1), (80, 80)), ((2, 2), (25, 25))],
            [((1, 1), (80, 80)), ((2, 2), (25, 25))],
            False,
        ),
        # Same pairs, one source port: still one printable chunk.
        (
            [((0, 0), (80, 80)), ((0, 0), (25, 25))],
            [((0, 0), (80, 80)), ((0, 0), (25, 25))],
            True,
        ),
        # Different destination ports: nothing to merge.
        ([((0, 0), (80, 80))], [((0, 0), (53, 53))], False),
        # An unrestricted service next to a port needs its own rule, which
        # the merged form cannot give it.
        (
            [((0, 0), (0, 0)), ((0, 0), (80, 80))],
            [((0, 0), (0, 0)), ((0, 0), (80, 80))],
            False,
        ),
    ],
)
def test_can_merge_tcp_udp(tcp, udp, expected):
    groups = {
        6: [_srv(TCPService, sport=s, dport=d) for s, d in tcp],
        17: [_srv(UDPService, sport=s, dport=d) for s, d in udp],
    }
    assert GroupServicesByProtocol._can_merge_tcp_udp(groups) is expected
