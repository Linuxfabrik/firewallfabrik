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

"""An address object whose address and netmask are both zero means "any".

``PolicyCompiler_ipt::PrintRule::_printAddr`` and its NAT twin answer that
case before they look at the class of the object: they write ``0/0``.  The
routing writer writes ``default``.  And ``PolicyCompiler::checkForZeroAddr``
reports the object with the words "which is equivalent to 'any'".

Writing the bare address instead turns "the whole internet" into the single
address 0.0.0.0, so a Deny rule written against it stops nothing.  Nothing
in either generated script is refused over it, which is why no oracle that
only asks whether the commands run can see it.

The netmask is the second half of the same question: Firewall Builder
writes an IPv6 one as a bit length (``NetworkIPv6::toXML``), so reading it
as an address answers "not any" for every ``::/0`` there is.
"""

from firewallfabrik.core.objects import IPv4, IPv6, Network, NetworkIPv6
from firewallfabrik.platforms.iptables._policy_compiler import CheckForZeroAddr
from firewallfabrik.platforms.linux._routing_compiler import route_address

ZERO_V4 = '0.0.0.0'  # nosec B104
ZERO_V6 = '::'


def _obj(cls, address, netmask, name='any-object'):
    obj = cls()
    obj.name = name
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


def test_a_zero_address_with_a_zero_netmask_is_any():
    for cls, addr, mask in (
        (Network, ZERO_V4, ZERO_V4),
        (IPv4, ZERO_V4, ZERO_V4),
        (NetworkIPv6, ZERO_V6, '0'),
        (IPv6, ZERO_V6, '0'),
    ):
        assert _obj(cls, addr, mask).is_any() is True


def test_an_ipv6_netmask_is_a_bit_length():
    """``ipaddress.ip_address("0")`` raises; the netmask reader does not."""
    assert _obj(NetworkIPv6, ZERO_V6, '0').is_any() is True
    assert _obj(NetworkIPv6, '::', '64').is_any() is False
    assert _obj(IPv6, '2001:db8::', '0').is_any() is False


def test_a_real_address_is_not_any():
    assert _obj(IPv4, '192.0.2.1', '255.255.255.255').is_any() is False
    assert _obj(Network, '10.0.0.0', '255.0.0.0').is_any() is False


def test_the_routing_writer_calls_it_the_default_route():
    """Whatever class carries it - ``_printAddr`` decides on the value."""
    assert route_address(_obj(IPv4, ZERO_V4, ZERO_V4)) == 'default'
    assert route_address(_obj(Network, ZERO_V4, ZERO_V4)) == 'default'
    assert route_address(_obj(IPv6, ZERO_V6, '0')) == 'default'


def test_the_check_reports_the_object_it_was_written_for():
    """The C++ guard is on the object's *id*, not on its value.

    ``Address::isAny()`` asks ``getId() == ANY_ADDRESS_ID``.  Reading it as
    a question about the value made the first of the two branches of
    ``findZeroAddress`` unreachable, so the case the message describes was
    never reported.
    """
    zero = _obj(IPv4, ZERO_V4, ZERO_V4, name='the-internet')
    assert CheckForZeroAddr._find_zero_address([zero]) is zero

    typo = _obj(Network, '192.0.2.0', ZERO_V4, name='net-err')
    assert CheckForZeroAddr._find_zero_address([typo]) is typo

    ordinary = _obj(Network, '192.0.2.0', '255.255.255.0')
    assert CheckForZeroAddr._find_zero_address([ordinary]) is None


def test_an_ipv6_zero_network_is_reported_too():
    """The netmask is a bit length there, which the check could not read."""
    zero = _obj(NetworkIPv6, ZERO_V6, '0', name='the-internet-v6')
    assert CheckForZeroAddr._find_zero_address([zero]) is zero

    typo = _obj(NetworkIPv6, '2001:db8::', '0', name='net-err-v6')
    assert CheckForZeroAddr._find_zero_address([typo]) is typo


def _ipt_printer():
    from firewallfabrik.platforms.iptables._print_rule import PrintRule

    printer = PrintRule()
    printer.compiler = _NullCompiler()
    return printer


def _nft_printer():
    from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

    printer = PrintRule_nft()
    printer.compiler = _NullCompiler()
    return printer


class _NullCompiler:
    ipv6_policy = False

    def error(self, _rule, _msg='') -> None:
        pass

    def warning(self, _rule, _msg='') -> None:
        pass


def test_the_iptables_printer_writes_the_prefix_the_object_means():
    """`0/0`, the way `_printAddr` writes it."""
    printer = _ipt_printer()
    assert printer._print_addr_basic(_obj(IPv4, ZERO_V4, ZERO_V4)) == '0/0 '
    assert printer._print_addr_basic(_obj(Network, ZERO_V4, ZERO_V4)) == '0/0 '
    assert printer._print_addr_basic(_obj(NetworkIPv6, ZERO_V6, '0')) == '0/0 '
    # An ordinary address is untouched.
    assert printer._print_addr_basic(_obj(IPv4, '192.0.2.1', '255.255.255.255')) == (
        '192.0.2.1 '
    )


def test_the_nftables_printer_writes_the_prefix_the_object_means():
    printer = _nft_printer()
    assert printer._print_addr_basic(_obj(IPv4, ZERO_V4, ZERO_V4), None) == (
        f'{ZERO_V4}/0'
    )
    assert printer._print_addr_basic(_obj(NetworkIPv6, ZERO_V6, '0'), None) == '::/0'
    assert printer._print_addr_basic(
        _obj(IPv4, '192.0.2.1', '255.255.255.255'), None
    ) == ('192.0.2.1')
