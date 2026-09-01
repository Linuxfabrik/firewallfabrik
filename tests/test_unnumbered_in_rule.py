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

"""An unnumbered or bridge-port interface named as a source or destination.

Such an interface carries no address, so there is nothing for the rule to
match on.  An element that renders to nothing is "any", so keeping the rule
widens it to every address on that side - the opposite of what naming an
interface asks for.

``PolicyCompiler::checkForUnnumbered`` writes ``compiler->abort(...)``
followed by ``tmp_queue.push_back(rule)``, and the second line is
unreachable because ``abort()`` throws.  fwf's ``abort()`` only reports, so
a port that transcribes those two lines literally reports *and* compiles
the rule.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler.processors._policy import CheckForUnnumbered
from firewallfabrik.core.objects import Interface, PolicyAction


class _Compiler:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def abort(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _interface(**flags) -> Interface:
    """An interface carrying the flags the way the model stores them.

    ``unnum`` lives in the object's own data, ``bridge_port`` among its
    options, which is what `Interface.is_unnumbered` / `is_bridge_port`
    read.
    """
    iface = Interface()
    iface.name = 'eth0'
    iface.data = {'unnum': True} if flags.get('unnum') else {}
    iface.options = {'bridge_port': True} if flags.get('bridge_port') else {}
    return iface


def _rule(**slots) -> CompRule:
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    for name, value in slots.items():
        setattr(rule, name, value)
    return rule


def _run(rule):
    processor = CheckForUnnumbered('check for unnumbered')
    processor.compiler = _Compiler()
    processor.tmp_queue = []
    queue = [rule]
    processor.get_next = lambda: queue.pop(0) if queue else None
    processor.process_next()
    return processor


@pytest.mark.parametrize('flag', ['unnum', 'bridge_port'])
@pytest.mark.parametrize('slot', ['src', 'dst'])
def test_the_rule_is_left_out_and_the_reason_is_said(flag, slot):
    processor = _run(_rule(**{slot: [_interface(**{flag: True})]}))
    assert processor.tmp_queue == [], 'the rule was compiled anyway'
    assert processor.compiler.messages


def test_an_ordinary_interface_keeps_its_rule():
    rule = _rule(src=[_interface()])
    processor = _run(rule)
    assert processor.tmp_queue == [rule]
    assert not processor.compiler.messages


def test_both_platforms_ask_one_check():
    """The C++ has one `checkForUnnumbered`; two copies here had drifted."""
    from firewallfabrik.platforms.iptables import _policy_compiler as ipt
    from firewallfabrik.platforms.nftables import _policy_compiler as nft

    assert ipt.CheckForUnnumbered is CheckForUnnumbered
    assert nft.CheckForUnnumbered is CheckForUnnumbered
