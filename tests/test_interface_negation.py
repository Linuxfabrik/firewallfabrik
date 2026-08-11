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
"""The interface negation must not leave the element empty."""

import uuid

from firewallfabrik.compiler.processors._policy import expand_interface_negation
from firewallfabrik.core.objects import Interface


def _interface(name: str) -> Interface:
    """A real Interface: the helper tests the model type, not a duck.

    `is_loopback()` reads the name, so "lo" is the loopback without any
    further setup.
    """
    return Interface(id=uuid.uuid4(), name=name)


class _Firewall:
    def __init__(self, interfaces) -> None:
        self.interfaces = interfaces


class _Compiler:
    def __init__(self, fw) -> None:
        self.fw = fw
        self.messages: list[str] = []

    def warning(self, _rule, msg: str) -> None:
        self.messages.append(msg)


class _Rule:
    def __init__(self, slot: str, objects, negated: bool) -> None:
        self._slot = slot
        self._neg = {slot: negated}
        setattr(self, slot, list(objects))

    def get_neg(self, slot: str) -> bool:
        return self._neg.get(slot, False)

    def set_neg(self, slot: str, value: bool) -> None:
        self._neg[slot] = value


ETH0 = _interface('eth0')
ETH1 = _interface('eth1')
LO = _interface('lo')


def _run(objects, negated=True, slot='itf', interfaces=(ETH0, ETH1, LO)):
    compiler = _Compiler(_Firewall(list(interfaces)))
    rule = _Rule(slot, objects, negated)
    kept = expand_interface_negation(compiler, rule, slot)
    return kept, getattr(rule, slot), compiler.messages


def test_the_other_interfaces_replace_the_negated_one():
    kept, remaining, messages = _run([ETH0])
    assert kept
    assert [i.name for i in remaining] == ['eth1']
    assert not messages


def test_negating_every_interface_leaves_no_rule():
    """An empty element reads as "any" downstream.

    Keeping the rule would apply it on exactly the interfaces it was
    written to skip, which on an Accept rule is a hole in the firewall.
    """
    kept, remaining, messages = _run([ETH0, ETH1])
    assert not kept
    assert remaining == []
    assert messages and 'excludes every interface' in messages[0]


def test_an_element_that_is_not_negated_is_untouched():
    kept, remaining, messages = _run([ETH0], negated=False)
    assert kept
    assert remaining == [ETH0]
    assert not messages


def test_the_nat_slots_go_through_the_same_helper():
    for slot in ('itf_inb', 'itf_outb'):
        kept, _remaining, messages = _run([ETH0, ETH1], slot=slot)
        assert not kept, slot
        assert messages, slot
