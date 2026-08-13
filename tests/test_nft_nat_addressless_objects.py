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

"""The nftables NAT printer's answer for an object that carries no address.

The two branches of ``_print_addr`` that answer with an empty string are
the ones for an Interface and for a Host, and neither type derives from
Address - ``get_address`` is defined on Address alone.  Asking the objects
for their address again while composing the diagnostic therefore raised
AttributeError in the middle of the message it was meant to produce.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Host, Interface, IPv4
from firewallfabrik.platforms.nftables._nat_print_rule import NATPrintRule_nft


class _Compiler:
    def __init__(self) -> None:
        self.ipv6_policy = False
        self.address_tables: dict = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.errors.append(msg)

    def warning(self, _rule, msg: str = '') -> None:
        self.warnings.append(msg)


def _rule() -> CompRule:
    return CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0 (NAT)',
        comment='',
        options={},
        negations={},
        action=None,
    )


def _printer():
    printer = NATPrintRule_nft()
    printer.compiler = _Compiler()
    return printer


def _addressless_interface(name='eth0'):
    iface = Interface()
    iface.name = name
    iface.addresses = []
    return iface


def _addressless_host(name='host-without-address'):
    host = Host()
    host.name = name
    host.interfaces = []
    return host


@pytest.mark.parametrize(
    'obj',
    [_addressless_interface(), _addressless_host()],
    ids=['interface', 'host'],
)
def test_an_addressless_object_is_reported_rather_than_raising(obj):
    printer = _printer()
    result = printer._print_addr_match(
        _rule(), [obj], 'ip saddr', 'ether saddr', negated=False
    )
    assert result is None
    said = printer.compiler.errors + printer.compiler.warnings
    assert any(obj.name in msg for msg in said), said


def test_an_object_with_an_address_still_renders():
    """The loop has to keep recording only what really gave nothing."""
    addr = IPv4()
    addr.name = 'host-a'
    addr.inet_addr_mask = {'address': '192.0.2.1', 'netmask': '255.255.255.255'}
    iface = _addressless_interface()
    iface.addresses = [addr]

    printer = _printer()
    result = printer._print_addr_match(
        _rule(), [iface], 'ip saddr', 'ether saddr', negated=False
    )
    assert result == ['ip saddr 192.0.2.1']
    assert not printer.compiler.errors
    assert not printer.compiler.warnings
