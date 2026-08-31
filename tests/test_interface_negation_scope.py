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

"""What "not these interfaces" is a negation of.

Firewall Builder reads it as the firewall's *other* protected interfaces:
`Compiler::fullInterfaceNegationInRE` collects the interfaces of the object
tree and leaves out the loopback, the unprotected ones (its bug #2710034),
the bridge ports of a non-bridging firewall and the cluster interfaces.
The reference output for firewall1 rule 7 shows it - a rule written as "not
eth1, not eth3" comes out as `-i eth0` and `-i eth2`, with no rule for `lo`.

`iifname != { "eth1", "eth3" }` is a different rule: it also matches the
loopback, an interface the object tree does not know about and one the
admin marked unprotected.  On a Deny rule that stops traffic nobody asked
to stop, on an Accept rule it opens what nobody asked to open.  Both
pipelines have to expand it the same way, which is what this pins.
"""

import uuid

import pytest

from firewallfabrik.compiler.processors._policy import (
    ItfNegation,
    SingleObjectNegationItf,
    expand_interface_negation,
)
from firewallfabrik.core.objects import Interface


def _interface(name: str, **kwargs) -> Interface:
    return Interface(id=uuid.uuid4(), name=name, **kwargs)


class _Firewall:
    def __init__(self, interfaces, options=None) -> None:
        self.interfaces = interfaces
        self.options = options or {}

    def get_option(self, key, default=None):
        return self.options.get(key, default)


class _Compiler:
    def __init__(self, fw) -> None:
        self.fw = fw
        self.messages: list[str] = []

    def warning(self, _rule, msg: str) -> None:
        self.messages.append(msg)


class _Rule:
    type = 'PolicyRule'

    def __init__(self, itf) -> None:
        self.itf = itf
        self.itf_single_object_negation = False
        self._neg = {'itf': True}

    def get_neg(self, slot):
        return self._neg.get(slot, False)

    def set_neg(self, slot, value):
        self._neg[slot] = value


ETH0 = _interface('eth0')
ETH1 = _interface('eth1')
ETH2 = _interface('eth2')
ETH3 = _interface('eth3')
LO = _interface('lo')
FW = _Firewall([ETH0, ETH1, ETH2, ETH3, LO])


def test_the_negation_leaves_the_loopback_out():
    """The reference output for firewall1 rule 7 names eth0 and eth2 only."""
    rule = _Rule([ETH1, ETH3])
    assert expand_interface_negation(_Compiler(FW), rule, 'itf')

    assert [iface.name for iface in rule.itf] == ['eth0', 'eth2']
    assert rule.get_neg('itf') is False


def test_the_negation_leaves_an_unprotected_interface_out():
    """The administrator asked for no rules on it at all."""
    unprotected = _interface('eth4', data={'unprotected': True})
    fw = _Firewall([ETH0, ETH1, ETH2, ETH3, LO, unprotected])
    rule = _Rule([ETH1, ETH3])

    assert expand_interface_negation(_Compiler(fw), rule, 'itf')

    assert [iface.name for iface in rule.itf] == ['eth0', 'eth2']


def test_the_negation_leaves_a_dedicated_failover_interface_out():
    """`Interface::isUnprotected()` answers for that checkbox as well.

    A dedicated failover link carries the cluster's heartbeat and nothing
    else, so Firewall Builder treats it exactly like an unprotected
    interface and writes no rule for it.
    """
    failover = _interface('eth4', data={'dedicated_failover': True})
    fw = _Firewall([ETH0, ETH1, ETH2, ETH3, LO, failover])
    rule = _Rule([ETH1, ETH3])

    assert expand_interface_negation(_Compiler(fw), rule, 'itf')

    assert [iface.name for iface in rule.itf] == ['eth0', 'eth2']


def test_the_negation_leaves_a_bridge_port_out_unless_the_firewall_bridges():
    """A routing firewall sees the packet on the bridge, not on the port."""
    bridge = _interface('br0', options={'type': 'bridge'})
    port = _interface('eth4', options={'type': 'ethernet'})
    port.parent_interface = bridge
    interfaces = [ETH0, ETH1, ETH2, ETH3, LO, bridge, port]

    rule = _Rule([ETH1, ETH3])
    assert expand_interface_negation(_Compiler(_Firewall(interfaces)), rule, 'itf')
    assert [iface.name for iface in rule.itf] == ['eth0', 'eth2', 'br0']

    bridging = _Firewall(interfaces, {'bridging_fw': True})
    rule = _Rule([ETH1, ETH3])
    assert expand_interface_negation(_Compiler(bridging), rule, 'itf')
    assert [iface.name for iface in rule.itf] == ['eth0', 'eth2', 'br0', 'eth4']


def test_the_negation_leaves_a_cluster_interface_out():
    """It belongs to the cluster, not to the member being compiled."""
    cluster_iface = _interface('eth4', options={'cluster_interface': True})
    fw = _Firewall([ETH0, ETH1, ETH2, ETH3, LO, cluster_iface])
    rule = _Rule([ETH1, ETH3])

    assert expand_interface_negation(_Compiler(fw), rule, 'itf')

    assert [iface.name for iface in rule.itf] == ['eth0', 'eth2']


def _pipeline_of(compiler_class):
    """The processor classes a compiler wires into its pipeline, by name."""
    import ast
    import inspect

    source = inspect.getsource(compiler_class.compile)
    return [
        call.args[0].func.id
        for call in ast.walk(ast.parse(source.lstrip()))
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == 'add'
        and call.args
        and isinstance(call.args[0], ast.Call)
        and isinstance(call.args[0].func, ast.Name)
    ]


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_both_policy_pipelines_expand_a_negated_interface(platform):
    """Neither back end may leave this to its own `!=` operator."""
    module = __import__(
        f'firewallfabrik.platforms.{platform}._policy_compiler',
        fromlist=['x'],
    )
    compiler_class = getattr(
        module, 'PolicyCompiler_ipt' if platform == 'iptables' else 'PolicyCompiler_nft'
    )
    wired = _pipeline_of(compiler_class)

    assert SingleObjectNegationItf.__name__ in wired
    assert ItfNegation.__name__ in wired
    # The single-object step has to come first, or every negated interface
    # would be expanded and `! -i eth0` / `iifname != "eth0"` would never
    # be emitted - which is what fwbuilder does emit.
    assert wired.index(SingleObjectNegationItf.__name__) < wired.index(
        ItfNegation.__name__
    )


def test_a_single_negated_interface_stays_an_inline_negation():
    """Both tools can say "not this one", and fwbuilder says it too."""
    rule = _Rule([ETH1])
    proc = SingleObjectNegationItf('single')
    proc.compiler = _Compiler(FW)
    proc.set_data_source(_Feeder(rule))
    proc.process_next()

    assert rule.itf_single_object_negation is True
    assert [iface.name for iface in rule.itf] == ['eth1']


class _Feeder:
    def __init__(self, rule) -> None:
        self._rule = rule

    def get_next_rule(self):
        rule, self._rule = self._rule, None
        return rule
