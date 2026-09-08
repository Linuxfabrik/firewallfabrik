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

"""Which address a DNAT rule makes the firewall answer for.

A destination translation needs the firewall to carry the address it
translates, or the traffic never reaches it: ``addVirtualAddress`` hands
the Original Destination to the OS configurator, which writes it into the
``update_addresses_of_interface`` line of the generated script.

An Original Destination the rule *excludes* by naming several addresses
is not such an address, and iptables never registers one: by the time
this processor runs, ``doODstNegation`` has moved those objects into a
temporary chain and the element is empty.  The nftables pipeline writes
the same exclusion as an inline ``!=`` and leaves the objects in place,
so it registered every one of them - and an excluded address that *is* on
one of the firewall's networks was configured as an interface alias, so
the firewall answered ARP for, and accepted traffic to, an address the
rule was written to leave alone.

A *single* excluded address is a different case and stays registered on
both platforms.  It is what ``! -d`` is, the element keeps the object
there too, and the shape it comes from is the transparent proxy -
"everything on port 80 that is not already going to the proxy" names the
proxy's own address, which the firewall does have to carry.  Firewall
Builder registers it (firewall2 of its regression suite has the address
on eth0), and taking it away would stop the proxy receiving traffic.
"""

import uuid

import pytest

from firewallfabrik.compiler.processors._generic import AddVirtualAddress
from firewallfabrik.core.objects import IPv4, NATRuleType


def _address(name, addr) -> IPv4:
    made = IPv4(id=uuid.uuid4(), name=name)
    made.data = {'address': addr, 'netmask': '255.255.255.255'}
    return made


class _OSConfigurator:
    def __init__(self) -> None:
        self.registered = []

    def add_virtual_address_for_nat(self, address, expand_network=False) -> None:
        self.registered.append(address)


class _Compiler:
    def __init__(self) -> None:
        self.oscnf = _OSConfigurator()
        self.fw = object()

    def get_cluster(self):
        return None

    def complex_match(self, _a, _b) -> bool:
        return False

    def warning(self, _rule, _message) -> None:
        pass


class _Rule:
    type = 'NATRule'

    def __init__(self, rule_type, odst, inline=False, single=False) -> None:
        self.nat_rule_type = rule_type
        self.osrc = []
        self.odst = odst
        self.tsrc = []
        self.negations = {'odst': False}
        # What the two negation processors leave behind.  The inline one
        # sets both flags, the single-object one only the first.
        self.odst_single_object_negation = single or inline
        self.odst_inline_negation = inline

    def get_neg(self, slot):
        return bool(self.odst) and bool(self.negations.get(slot, False))


class _Feeder:
    def __init__(self, rule) -> None:
        self._rule = rule

    def get_next_rule(self):
        rule, self._rule = self._rule, None
        return rule


def _run(rule):
    proc = AddVirtualAddress()
    proc.compiler = _Compiler()
    proc.set_data_source(_Feeder(rule))
    proc.process_next()
    return proc.compiler.oscnf.registered


SERVER = _address('server', '198.51.100.10')


def test_a_plain_destination_translation_asks_for_its_address():
    rule = _Rule(NATRuleType.DNAT, [SERVER])

    assert _run(rule) == [SERVER]


def test_an_inline_negation_does_not():
    """The nftables shape: the objects stay and the rule says "not these"."""
    rule = _Rule(NATRuleType.DNAT, [SERVER], inline=True)

    assert _run(rule) == []


def test_a_single_excluded_address_is_still_registered():
    """The transparent proxy, and what Firewall Builder does with it."""
    rule = _Rule(NATRuleType.DNAT, [SERVER], single=True)

    assert _run(rule) == [SERVER]


@pytest.mark.parametrize('rule_type', [NATRuleType.SNAT, NATRuleType.SNetnat])
def test_a_source_translation_is_not_affected(rule_type):
    """Its address comes from TSrc, where negation is refused outright."""
    rule = _Rule(rule_type, [SERVER], inline=True)

    assert _run(rule) == []
    assert rule.tsrc == []
