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

"""One rule, one reason, in the nftables policy printer.

``_print_addr`` says why it could not render an object and
``_print_addr_match`` used to add "Could not resolve any source addresses"
on top of it, so a rule about an interface without an address was reported
twice - the specific sentence first and the vague one after it.  The
counterpart in the NAT printer was corrected before this one.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import Interface, IPv4
from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft


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
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=None,
    )


def _printer() -> PrintRule_nft:
    printer = PrintRule_nft()
    printer.compiler = _Compiler()
    return printer


def _addressless_interface(name: str = 'eth0') -> Interface:
    iface = Interface()
    iface.name = name
    iface.addresses = []
    return iface


def test_an_interface_without_an_address_is_reported_once():
    printer = _printer()
    result = printer._print_addr_match(
        _rule(), [_addressless_interface()], 'ip saddr', ''
    )
    assert result is None
    assert printer.compiler.errors == ['Interface "eth0" has no addresses']


def test_an_element_that_says_nothing_still_gets_the_general_reason():
    """The vague sentence is the only one left when no object gave a reason.

    An Address that carries no address string is the one empty answer
    ``_print_addr`` gives without a word of its own: a match is assembled
    out of the whole element, so saying it per object would report a rule
    that still has an address to match on.
    """
    empty = IPv4()
    empty.name = 'nothing'
    empty.inet_addr_mask = {'address': '', 'netmask': ''}

    printer = _printer()
    result = printer._print_addr_match(_rule(), [empty], 'ip saddr', '')
    assert result is None
    assert printer.compiler.errors == ['Could not resolve any source addresses']


def test_an_object_with_an_address_is_not_reported_at_all():
    addr = IPv4()
    addr.name = 'host-a'
    addr.inet_addr_mask = {'address': '192.0.2.1', 'netmask': '255.255.255.255'}
    iface = _addressless_interface()
    iface.addresses = [addr]

    printer = _printer()
    result = printer._print_addr_match(_rule(), [iface], 'ip saddr', '')
    assert result == 'ip saddr 192.0.2.1'
    assert not printer.compiler.errors
    assert not printer.compiler.warnings
