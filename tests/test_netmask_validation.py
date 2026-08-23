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

"""A netmask an editor takes is one the compilers can read back.

The editors used to check a netmask and then store the raw text of the
field.  ``int()`` reads ``'+8'`` and the Arabic-Indic digit ``'٨'`` as 8,
so both passed the check and were written to the data file as typed -
and ``ipaddress`` refuses either of them, so both compilers dropped the
netmask without a word: a rule written for 10.0.0.0/8 was installed as a
rule about the single address 10.0.0.0.

Firewall Builder has no such gap because it stores the ``InetAddr`` it
validated (``NetworkDialog::applyChanges``), which is also why a mask
typed as a bit length ends up dotted in the file.  The rules the
editors apply are the ones fwbuilder applies, refusals included.
"""

import ipaddress
import re

import pytest

from firewallfabrik.gui.netmask import (
    NetmaskRejected,
    netmask_for_interface_address,
    netmask_for_ipv4_address,
    netmask_for_ipv6_address,
    netmask_for_network,
    netmask_for_network_ipv6,
)


def _network(mask):
    return netmask_for_network(mask, address_is_any=False)


@pytest.mark.parametrize(
    ('typed', 'stored'),
    [
        # InetAddr::init_from_string reads a value without a dot as a bit
        # length, so both spellings are the same mask and both are stored
        # dotted.
        ('8', '255.0.0.0'),
        ('255.0.0.0', '255.0.0.0'),
        ('24', '255.255.255.0'),
        ('255.255.255.0', '255.255.255.0'),
    ],
)
def test_an_ipv4_netmask_is_stored_the_way_fwbuilder_stores_it(typed, stored):
    assert netmask_for_ipv4_address(typed) == stored
    assert _network(typed) == stored


@pytest.mark.parametrize('typed', ['+8', '٨', '0x8', '8.', 'eight'])
def test_a_netmask_python_reads_but_ipaddress_cannot_is_refused(typed):
    """The class of value that passed and then vanished in the compilers."""
    for validate in (netmask_for_ipv4_address, _network):
        with pytest.raises(NetmaskRejected):
            validate(typed)


def test_every_stored_netmask_survives_the_round_trip():
    """Whatever an editor stores, ip_network() has to read back."""
    for prefix in range(33):
        stored = netmask_for_ipv4_address(str(prefix))
        assert (
            ipaddress.ip_network(f'10.0.0.0/{stored}', strict=False).prefixlen == prefix
        )


@pytest.mark.parametrize('typed', ['255.0.255.0', '255.255.0.255', '0.255.255.255'])
def test_a_netmask_with_zeroes_in_the_middle_is_refused(typed):
    """``InetAddr::isValidV4Netmask()``, in every editor that takes a mask."""
    with pytest.raises(NetmaskRejected, match='zeroes in the middle'):
        netmask_for_ipv4_address(typed)
    with pytest.raises(NetmaskRejected, match='zeroes in the middle'):
        _network(typed)
    with pytest.raises(NetmaskRejected, match='zeroes in the middle'):
        netmask_for_interface_address(typed, is_v4=True)


@pytest.mark.parametrize('typed', ['33', '129', '255.255.255.256', ''])
def test_an_ipv4_netmask_outside_the_family_is_refused(typed):
    with pytest.raises(NetmaskRejected):
        netmask_for_ipv4_address(typed)


@pytest.mark.parametrize('typed', ['0.0.0.0', ''])  # nosec B104
def test_a_network_object_refuses_a_zero_netmask(typed):
    """fwbuilder #251: such an object matches every address there is.

    An empty field is the same case: ``InetAddr("")`` is 0.0.0.0, which
    is why fwbuilder answers it with this message and not with "illegal".
    """
    with pytest.raises(NetmaskRejected, match=re.escape("netmask '0.0.0.0'")):
        _network(typed)


def test_a_network_object_refuses_a_length_of_zero():
    """The length branch of NetworkDialog::validate() has its own answer."""
    with pytest.raises(NetmaskRejected, match='Illegal netmask'):
        _network('0')


@pytest.mark.parametrize('typed', ['0', '0.0.0.0'])  # nosec B104
def test_a_zero_netmask_is_taken_for_the_any_network(typed):
    """0.0.0.0/0 is the one network object that may carry it."""
    assert netmask_for_network(typed, address_is_any=True) == '0.0.0.0'  # nosec B104


def test_a_network_object_refuses_a_length_of_32():
    """``ilen > 0 && ilen < 32`` in NetworkDialog::validate()."""
    with pytest.raises(NetmaskRejected, match='Illegal netmask'):
        _network('32')


def test_a_host_address_takes_the_length_a_network_object_refuses():
    """IPv4Dialog has no such bound, so an interface address may be a /32."""
    assert netmask_for_ipv4_address('32') == '255.255.255.255'


@pytest.mark.parametrize(
    ('typed', 'stored'), [('64', '64'), ('0', '0'), ('128', '128')]
)
def test_an_ipv6_netmask_is_stored_as_a_bit_length(typed, stored):
    """``NetworkIPv6::toXML`` writes the length, so the editors do too."""
    assert netmask_for_ipv6_address(typed) == stored


@pytest.mark.parametrize('typed', ['129', 'ffff::', '255.255.255.0', '+64', ''])
def test_an_ipv6_netmask_that_is_not_a_bit_length_is_refused(typed):
    with pytest.raises(NetmaskRejected):
        netmask_for_ipv6_address(typed)


@pytest.mark.parametrize('typed', ['0', '128'])
def test_an_ipv6_network_object_refuses_both_ends(typed):
    """``range > 0 && range < 128`` in NetworkDialogIPv6::validate()."""
    with pytest.raises(NetmaskRejected):
        netmask_for_network_ipv6(typed)


def test_an_ipv6_network_object_takes_a_prefix_between_the_ends():
    assert netmask_for_network_ipv6('64') == '64'


@pytest.mark.parametrize(
    ('typed', 'is_v4', 'stored'),
    [
        ('8', True, '255.0.0.0'),
        ('255.255.255.0', True, '255.255.255.0'),
        ('32', True, '255.255.255.255'),
        ('64', False, '64'),
    ],
)
def test_the_wizard_stores_what_the_editors_store(typed, is_v4, stored):
    """An interface address created by the wizard opens in its editor."""
    assert netmask_for_interface_address(typed, is_v4=is_v4) == stored


@pytest.mark.parametrize(
    ('typed', 'is_v4'),
    [('1.2.3.4', True), ('33', True), ('129', False), ('255.255.255.0', False)],
)
def test_the_wizard_refuses_what_the_editors_refuse(typed, is_v4):
    with pytest.raises(NetmaskRejected):
        netmask_for_interface_address(typed, is_v4=is_v4)
