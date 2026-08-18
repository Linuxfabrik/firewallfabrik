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

"""Where an nftables NAT rule may match on a MAC address.

`nft_payload_eval` gives up on a link-layer read when the packet carries
no MAC header (`net/netfilter/nft_payload.c`: `if
(!skb_mac_header_was_set(skb) || skb_mac_header_len(skb) == 0) goto err`),
so the rule loads and then never matches.  A locally generated packet is
that case; a forwarded one still carries the header it arrived with, which
is why this platform's `CheckMACInOUTPUTChain` allows postrouting.  The NAT
guard next door forbade postrouting as well, and then left a
`CombinedAddress` in the rule - so the rule kept its `ether saddr` and the
generated script carried a warning saying the MAC had been removed.  Both
halves of that could not be true.
"""

import uuid

import pytest

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.core.objects import IPv4, PhysAddress
from firewallfabrik.platforms.nftables._nat_compiler import VerifyRuleWithMAC


def _addr(name: str, address: str) -> IPv4:
    obj = IPv4(id=uuid.uuid4(), name=name)
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


def _mac(name: str, address: str) -> PhysAddress:
    obj = PhysAddress(id=uuid.uuid4(), name=name)
    obj.data = {'address': address}
    return obj


class _Compiler:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.aborts: list[str] = []

    def warning(self, _rule, msg: str = '') -> None:
        self.warnings.append(msg)

    def abort(self, _rule, msg: str = '') -> None:
        self.aborts.append(msg)


class _Rule:
    type = 'NATRule'

    def __init__(self, chain, osrc) -> None:
        self.ipt_chain = chain
        self.osrc = osrc


class _Feeder(NATRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _verify(rule):
    proc = VerifyRuleWithMAC('verify MAC')
    proc.compiler = _Compiler()
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    return proc


@pytest.mark.parametrize('chain', ['prerouting', 'forward', 'input', 'postrouting'])
def test_a_mac_survives_every_chain_that_sees_a_link_layer_header(chain):
    combined = CombinedAddress(
        _addr('host', '192.168.1.10'), _mac('host-pa', '00:10:4b:de:e9:6f')
    )
    proc = _verify(_Rule(chain, [combined]))

    assert proc.tmp_queue[0].osrc == [combined]
    assert proc.compiler.warnings == []


def test_the_output_chain_keeps_the_address_and_loses_the_mac():
    """A locally generated packet has no link-layer header at all."""
    ip = _addr('host', '192.168.1.10')
    combined = CombinedAddress(ip, _mac('host-pa', '00:10:4b:de:e9:6f'))
    proc = _verify(_Rule('output', [combined]))

    assert proc.tmp_queue[0].osrc == [ip]
    assert any('removed from the rule' in msg for msg in proc.compiler.warnings)


def test_a_rule_that_is_nothing_but_a_mac_is_reported_in_the_output_chain():
    proc = _verify(_Rule('output', [_mac('host-pa', '00:10:4b:de:e9:6f')]))

    assert len(proc.tmp_queue) == 0
    assert any("becomes 'Any'" in msg for msg in proc.compiler.aborts)


def test_the_two_nftables_guards_agree_on_which_chains_are_forbidden():
    """Two neighbours naming the same kernel fact differently is the bug."""
    from firewallfabrik.platforms.nftables._policy_compiler import (
        CheckMACInOUTPUTChain,
    )

    assert VerifyRuleWithMAC.FORBIDDEN_CHAINS == CheckMACInOUTPUTChain.FORBIDDEN_CHAINS
