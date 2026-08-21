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

"""What the source half of a split SDNAT rule matches on.

A rule that translates source *and* destination becomes two rules: a
destination translation and, behind it, a source translation.  The second
one has to recognise the packets the first one rewrote, so it matches on
the translated destination port.  It must not match on the translated
*source* port as well: a destination translation cannot write one, so such
a rule matches nothing and the source is never translated
(``NATCompiler_ipt::splitSDNATRule`` builds a service carrying the
destination half alone for exactly that reason).
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import IPv4, NATRuleType, TCPService
from firewallfabrik.platforms.iptables._nat_compiler import (
    SplitSDNATRule as SplitSDNATRule_ipt,
)
from firewallfabrik.platforms.nftables._nat_compiler import (
    SplitSDNATRule as SplitSDNATRule_nft,
)


class _Source:
    def __init__(self, rules):
        self._rules = list(rules)

    def get_next_rule(self):
        return self._rules.pop(0) if self._rules else None


def _address(name, address):
    obj = IPv4()
    obj.id = uuid.uuid4()
    obj.name = name
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


def _tcp(name, src=(0, 0), dst=(0, 0)):
    srv = TCPService()
    srv.id = uuid.uuid4()
    srv.name = name
    srv.src_range_start, srv.src_range_end = src
    srv.dst_range_start, srv.dst_range_end = dst
    return srv


def _sdnat_rule(osrv, tsrv):
    return CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0 (NAT)',
        comment='',
        options={},
        negations={},
        osrc=[_address('client', '192.0.2.10')],
        odst=[_address('vip', '198.51.100.1')],
        osrv=[osrv],
        tsrc=[_address('outside', '203.0.113.1')],
        tdst=[_address('server', '10.0.0.5')],
        tsrv=[tsrv],
        nat_rule_type=NATRuleType.SDNAT,
    )


def _split(processor, rule):
    processor.compiler = None
    processor.prev_processor = _Source([rule])
    out = []
    while True:
        r = processor.get_next_rule()
        if r is None:
            break
        out.append(r)
    return out


@pytest.mark.parametrize(
    'processor',
    [SplitSDNATRule_ipt('split'), SplitSDNATRule_nft('split')],
    ids=['ipt', 'nft'],
)
def test_the_source_half_matches_the_translated_destination_port_only(processor):
    osrv = _tcp('http', dst=(80, 80))
    tsrv = _tcp('translate-both', src=(20000, 20010), dst=(8080, 8080))
    dnat_rule, snat_rule = _split(processor, _sdnat_rule(osrv, tsrv))

    assert dnat_rule.tsrc == []
    assert snat_rule.tdst == []

    match = snat_rule.osrv[0]
    assert match.dst_range_start == 8080
    assert match.dst_range_end == 8080
    # The port the first rule could never have written.
    assert not match.src_range_start
    assert not match.src_range_end


@pytest.mark.parametrize(
    'processor',
    [SplitSDNATRule_ipt('split'), SplitSDNATRule_nft('split')],
    ids=['ipt', 'nft'],
)
def test_a_destination_only_translation_is_matched_as_it_stands(processor):
    osrv = _tcp('http', dst=(80, 80))
    tsrv = _tcp('translate-dport', dst=(8080, 8080))
    _dnat_rule, snat_rule = _split(processor, _sdnat_rule(osrv, tsrv))

    assert snat_rule.osrv == [tsrv]
