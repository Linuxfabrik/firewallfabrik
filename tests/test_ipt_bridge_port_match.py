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

"""Which bridge a rule matching a bridge port is about.

``-m physdev`` names the port and not the bridge it hangs on, so two
bridges sharing one wildcard port name - ``vnet+`` on br0 and on br1, the
shape libvirt gives a host with more than one virtual network - cannot be
told apart by the port match alone.  The policy printer names the bridge
next to it (fwbuilder PolicyCompiler_PrintRule.cpp, ``bridge_count > 1``);
the NAT printer did not, so a NAT rule written for one bridge also
translated the other bridge's guests.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Interface
from firewallfabrik.platforms.iptables._nat_print_rule import NATPrintRule
from firewallfabrik.platforms.iptables._print_rule import PrintRule
from firewallfabrik.platforms.iptables._utils import DEFAULT_IPTABLES_VERSION


class _Compiler:
    def __init__(self, bridge_count: int) -> None:
        self.ipv6_policy = False
        self.bridge_count = bridge_count

    def error(self, _rule, msg: str = '') -> None:
        pass

    def warning(self, _rule, msg: str = '') -> None:
        pass


def _bridge_port(name='vnet+', bridge='br0'):
    parent = Interface()
    parent.name = bridge
    parent.options = {'type': 'bridge'}
    port = Interface()
    port.name = name
    port.options = {'type': 'ethernet'}
    port.parent_interface = parent
    return port


def _rule(port):
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0 (NAT)',
        comment='',
        options={},
        negations={},
        action=None,
    )
    rule.itf_inb = [port]
    rule.itf_outb = [port]
    rule.itf = [port]
    return rule


def _nat(bridge_count, inbound):
    printer = NATPrintRule()
    printer.compiler = _Compiler(bridge_count)
    printer.version = DEFAULT_IPTABLES_VERSION
    port = _bridge_port()
    slot = 'itf_inb' if inbound else 'itf_outb'
    return printer._print_iface_option(_rule(port), slot, port.name, inbound)


@pytest.mark.parametrize('inbound', [True, False], ids=['inbound', 'outbound'])
def test_one_bridge_needs_no_disambiguation(inbound):
    out = _nat(bridge_count=1, inbound=inbound)
    assert '-m physdev' in out
    assert '-i br0' not in out
    assert '-o br0' not in out


@pytest.mark.parametrize(
    ('inbound', 'expected'),
    [(True, '-i br0'), (False, '-o br0')],
    ids=['inbound', 'outbound'],
)
def test_two_bridges_make_the_nat_rule_name_the_bridge(inbound, expected):
    out = _nat(bridge_count=2, inbound=inbound)
    assert out.startswith(expected), out
    assert '-m physdev' in out


@pytest.mark.parametrize(
    ('inbound', 'expected'),
    [(True, '-i br0'), (False, '-o br0')],
    ids=['inbound', 'outbound'],
)
def test_the_policy_printer_says_the_same_thing(inbound, expected):
    """The two printers have to agree about which packets they concern."""
    printer = PrintRule()
    printer.compiler = _Compiler(bridge_count=2)
    printer.version = DEFAULT_IPTABLES_VERSION
    port = _bridge_port()
    out = printer._print_bridge_port(_rule(port), port, port.name, inbound)
    assert out.startswith(expected), out
    assert '-m physdev' in out
