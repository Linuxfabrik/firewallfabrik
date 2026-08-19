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

"""Which addresses stand for "the firewall" in a firewall-to-firewall rule.

`specialCaseWithFW2` replaces both ends of such a rule with the addresses of
the firewall's own interfaces, and Firewall Builder leaves two kinds out:
an unnumbered interface, which has none, and a **bridge port**
(`PolicyCompiler_ipt.cpp`, `if (iface->isUnnumbered() || iface->isBridgePort())
continue`).  A port of a bridge carries the bridge's traffic and terminates
none of it, so an address configured there is the bridge's; writing it into
the rule makes it match packets that never reach the firewall as their
destination.

Both compilers have to answer the same, which is what this pins.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import Firewall, Interface, IPv4, PolicyAction


class _Feeder(BasicRuleProcessor):
    """Minimal source processor that yields pre-built CompRules."""

    def __init__(self, rules: list[CompRule]) -> None:
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    ipv6_policy = False

    def __init__(self, fw) -> None:
        self.fw = fw


def _address(addr: str) -> IPv4:
    return IPv4(
        id=uuid.uuid4(),
        name=addr,
        inet_addr_mask={'address': addr, 'netmask': '255.255.255.255'},
    )


def _interface(name: str, addr: str, data: dict | None = None, **options) -> Interface:
    iface = Interface(
        id=uuid.uuid4(), name=name, data=data or {}, options=options or {}
    )
    iface.addresses = [_address(addr)]
    return iface


def _firewall() -> Firewall:
    fw = Firewall(id=uuid.uuid4(), name='fw')
    fw.interfaces = [
        _interface('eth0', '192.0.2.1'),
        _interface('br0', '198.51.100.1'),
        # A port of br0.  The explicit option is the spelling an imported
        # file may carry; the derived answer needs a parent, which is what
        # the object tree gives it.
        _interface('eth1', '203.0.113.1', bridge_port=True),
        _interface('eth2', '203.0.113.2', data={'unnum': True}),
    ]
    return fw


def _rule(fw: Firewall) -> CompRule:
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    rule.src = [fw]
    rule.dst = [fw]
    return rule


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
def test_bridge_port_and_unnumbered_are_left_out(platform):
    if platform == 'ipt':
        from firewallfabrik.platforms.iptables._policy_compiler import (
            SpecialCaseWithFW2,
        )
    else:
        from firewallfabrik.platforms.nftables._policy_compiler import (
            SpecialCaseWithFW2,
        )

    fw = _firewall()
    rule = _rule(fw)
    processor = SpecialCaseWithFW2(name='SpecialCaseWithFW2')
    processor.compiler = _Compiler(fw)
    processor.set_data_source(_Feeder([rule]))

    assert processor.process_next() is True
    out = processor.tmp_queue[0]

    addresses = sorted(obj.get_address() for obj in out.src)
    assert addresses == ['192.0.2.1', '198.51.100.1']
    assert sorted(obj.get_address() for obj in out.dst) == addresses
