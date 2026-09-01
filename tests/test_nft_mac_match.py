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

"""Which nftables chains can match a MAC address.

`nft_payload_eval` gives up on any link-layer read of a packet with no
link-layer header (net/netfilter/nft_payload.c: `if
(!skb_mac_header_was_set(skb) || skb_mac_header_len(skb) == 0) goto
err`).  A locally generated packet reaching the output hook has none, so
such a rule loads and then never matches - the quiet failure a guard
exists to prevent.

A forwarded packet in postrouting still carries the header it arrived
with, which is why postrouting is deliberately not on the list even
though the iptables mac match cannot be used there at all.
"""

import uuid
from collections import defaultdict

import pytest

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core.objects import PhysAddress
from firewallfabrik.platforms.nftables._policy_compiler import CheckMACInOUTPUTChain

MAC = 'aa:bb:cc:dd:ee:ff'


class _Compiler:
    # The guard asks the hook a chain hangs off, not the chain's name, so
    # the stub answers that question with the real implementation.
    is_chain_descendant_of = PolicyCompiler.is_chain_descendant_of
    insert_upstream_chain = PolicyCompiler.insert_upstream_chain

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.upstream_chains: dict[str, list[str]] = defaultdict(list)

    def abort(self, _rule, msg: str) -> None:
        self.messages.append(msg)

    def warning(self, _rule, msg: str) -> None:
        self.messages.append(msg)

    def error(self, _rule, msg: str) -> None:
        self.messages.append(msg)


def _phys() -> PhysAddress:
    """A real PhysAddress: the guard tests the model type, not a duck."""
    return PhysAddress(
        id=uuid.uuid4(),
        name='mac-only-host',
        inet_addr_mask={'address': MAC},
    )


class _Address:
    def __init__(self, name: str, address: str) -> None:
        self.name = name
        self._address = address

    def get_address(self) -> str:
        return self._address


class _Rule:
    type = 'PolicyRule'

    def __init__(self, chain: str, src: list, dst: list) -> None:
        self.ipt_chain = chain
        self.src = src
        self.dst = dst


class _Feeder(PolicyRuleProcessor):
    def __init__(self, rule) -> None:
        super().__init__(name='feeder')
        self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _check(chain: str, src=(), dst=(), jumps=()):
    compiler = _Compiler()
    for parent, child in jumps:
        compiler.insert_upstream_chain(parent, child)
    proc = CheckMACInOUTPUTChain('check MAC')
    proc.compiler = compiler
    proc.set_data_source(_Feeder(_Rule(chain, list(src), list(dst))))
    proc.process_next()
    return bool(proc.tmp_queue), compiler.messages


_COMBINED = CombinedAddress(_Address('host-with-mac/addr', '192.0.2.5'), _phys())


@pytest.mark.parametrize(
    'element',
    [
        {'src': [_phys()]},
        # `ether daddr` is rendered as readily as `ether saddr`.
        {'dst': [_phys()]},
    ],
)
def test_a_rule_that_is_nothing_but_a_mac_goes(element):
    """Removing the object would leave an element that means "any"."""
    kept, messages = _check('output', **element)
    assert not kept
    assert messages and 'Can not match the MAC address' in messages[0]


@pytest.mark.parametrize(
    'element',
    [
        {'src': [_COMBINED]},
        {'dst': [_COMBINED]},
        # The second object of the element counts too; the guard used to
        # look at the first one only.
        {'src': [_Address('plain', '192.0.2.1'), _phys()]},
    ],
)
def test_an_address_half_survives_the_chain_that_has_no_header(element):
    """``setPhysAddress("")`` in ``PolicyCompiler_ipt::checkMACinOUTPUTChain``.

    A combined address is an address *and* a MAC, and the address half is
    a match the output chain can perfectly well make.  Dropping the whole
    rule loses a rule the administrator wrote.
    """
    kept, messages = _check('output', **element)
    assert kept
    assert messages and 'matches on the address alone' in messages[0]


@pytest.mark.parametrize('chain', ['input', 'forward', 'prerouting', 'postrouting'])
def test_mac_is_kept_where_the_header_is_there(chain):
    kept, messages = _check(chain, src=[_COMBINED])
    assert kept
    assert not messages


def test_a_rule_without_a_mac_passes_through_output():
    kept, messages = _check('output', src=[_Address('plain', '192.0.2.1')])
    assert kept
    assert not messages


def test_a_temporary_chain_is_judged_by_the_hook_it_hangs_off():
    """`TimeNegation` and `SplitLogWithStatefulLimit` build chains here.

    Both run before this check and both move the rule into a chain of
    their own, so asking whether the chain is called "output" answers no
    for a rule that is reached from exactly that hook - and `ether saddr`
    there matches no packet, because the header is not written yet.
    """
    kept, messages = _check(
        'C0123456789ab.0',
        src=[_phys()],
        jumps=[('output', 'C0123456789ab.0')],
    )
    assert not kept
    assert messages and 'output chain' in messages[0]


def test_a_temporary_chain_of_another_hook_keeps_its_match():
    kept, messages = _check(
        'C0123456789ab.0',
        src=[_phys()],
        jumps=[('forward', 'C0123456789ab.0')],
    )
    assert kept
    assert not messages


def test_a_chain_reached_through_two_jumps_is_still_found():
    """A nested negation builds a chain inside a chain."""
    kept, _messages = _check(
        'Cffff.0',
        src=[_phys()],
        jumps=[('output', 'C0123456789ab.0'), ('C0123456789ab.0', 'Cffff.0')],
    )
    assert not kept
