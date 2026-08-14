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

"""Which chain can match which interface, and who decides.

The postrouting hook is entered with the device a routed packet came in on
since kernel commit 28f8bfd1ac94 ("netfilter: Support iif matches in
POSTROUTING", first in v5.5), so whether a rule can match there is a
question about the back end: nftables takes ``iifname``, iptables refuses
``-i`` but takes the ``-m physdev --physdev-in`` a bridge port is written
as.  Everything else stays impossible - a packet has no outgoing device
before the routing decision and a locally generated one no incoming device
at all.
"""

import pytest

from firewallfabrik.core.objects import Interface
from firewallfabrik.platforms.iptables._utils import (
    bridge_port_matches_inbound_in_postrouting,
)
from firewallfabrik.platforms.linux._netfilter import (
    bridge_port_match_needs_the_bridge,
    interface_direction_problem,
    nat_interface_problem,
)


def _bridge():
    bridge = Interface()
    bridge.name = 'br0'
    bridge.options = {'type': 'bridge'}
    return bridge


def _iface(name, bridge_port=False, parent=None):
    iface = Interface()
    iface.name = name
    iface.options = {'type': 'ethernet', 'bridge_port': bridge_port}
    iface.parent_interface = parent
    return iface


class _FakeFW:
    def __init__(self, bridges=0):
        self.interfaces = [_bridge() for _ in range(bridges)]


class _FakeCompiler:
    def __init__(self, version='1.8', bridges=1):
        self.version = version
        self.fw = _FakeFW(bridges)


@pytest.mark.parametrize('chain', ['OUTPUT', 'output'])
def test_output_never_has_an_incoming_device(chain):
    # A locally generated packet enters LOCAL_OUT with NULL for `in`.
    assert interface_direction_problem(chain, inbound=True)
    assert interface_direction_problem(chain, inbound=True, iif_in_postrouting=True)


@pytest.mark.parametrize('chain', ['PREROUTING', 'INPUT', 'prerouting', 'input'])
def test_no_outgoing_device_before_the_routing_decision(chain):
    assert interface_direction_problem(chain, inbound=False)


def test_postrouting_answer_follows_the_back_end():
    assert interface_direction_problem('POSTROUTING', inbound=True)
    assert not interface_direction_problem(
        'postrouting', inbound=True, iif_in_postrouting=True
    )


def test_postrouting_message_names_the_tool_and_not_the_packet():
    # The kernel does offer the device there; only iptables refuses it.
    problem = interface_direction_problem('POSTROUTING', inbound=True)
    assert 'iptables refuses' in problem
    assert 'no incoming interface' not in problem


def test_postrouting_still_takes_an_outgoing_device():
    assert not interface_direction_problem('POSTROUTING', inbound=False)


def test_nat_passes_the_answer_on():
    assert nat_interface_problem('postrouting', True, False)
    assert not nat_interface_problem(
        'postrouting', True, False, iif_in_postrouting=True
    )
    # The outbound half is unaffected by it.
    assert nat_interface_problem('prerouting', False, True, iif_in_postrouting=True)


def test_iptables_says_yes_only_for_a_bridge_port():
    compiler = _FakeCompiler()
    assert not bridge_port_matches_inbound_in_postrouting(compiler, None)
    assert not bridge_port_matches_inbound_in_postrouting(compiler, _iface('eth0'))
    assert bridge_port_matches_inbound_in_postrouting(
        compiler, _iface('eth0', bridge_port=True)
    )


def test_iptables_says_no_without_the_physdev_match():
    # physdev reached iptables in 1.3.0; before that the print rules fall
    # back to `-i`, which POSTROUTING refuses.
    compiler = _FakeCompiler(version='1.2.9')
    assert not bridge_port_matches_inbound_in_postrouting(
        compiler, _iface('vnet0', bridge_port=True)
    )


def test_iptables_says_no_when_the_bridge_has_to_be_named():
    # A wildcard port on a firewall with two bridges needs an `-i br0` next
    # to the physdev match, and that is what POSTROUTING refuses.
    port = _iface('vnet+', bridge_port=True, parent=_bridge())
    assert bridge_port_match_needs_the_bridge(port, 2)
    assert not bridge_port_matches_inbound_in_postrouting(
        _FakeCompiler(bridges=2), port
    )
    # One bridge tells itself apart.
    assert not bridge_port_match_needs_the_bridge(port, 1)
    assert bridge_port_matches_inbound_in_postrouting(_FakeCompiler(bridges=1), port)


def test_the_bridge_is_only_named_for_a_wildcard_port():
    named = _iface('vnet0', bridge_port=True, parent=_bridge())
    assert not bridge_port_match_needs_the_bridge(named, 2)
    # fwbuilder stores the wildcard as `*`, the print rules write `+`.
    for wildcard in ('vnet*', 'vnet+'):
        port = _iface(wildcard, bridge_port=True, parent=_bridge())
        assert bridge_port_match_needs_the_bridge(port, 2)
