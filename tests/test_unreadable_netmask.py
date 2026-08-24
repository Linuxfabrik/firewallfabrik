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

"""A netmask is read, or the rule is reported - never dropped in silence.

Both compilers used to pair address and netmask through ``ip_network()``
and swallow the raise: the netmask was left out and the address matched
alone, so a rule written for a whole network was installed as a rule
about a single host, in a script that loads without a word.  Issue #154
reached that from the editors; a data file written by another tool, by
hand, or by an older FirewallFabrik reaches it too.

The answer is one reader and one backstop.
:func:`netmask_prefix_length` takes every spelling a netmask reaches the
compilers in, so the values that mean something are compiled instead of
reported.  What is left means nothing at all, and ``VerifyAddresses``
leaves that rule out with a message naming the value.

The reader is also what found the compilers building IPv6 netmasks in
the address form themselves: an interface network came out of
``str(net.netmask)`` as ``ffff:ffff:ffff:ffff::``, which ``ip_network()``
cannot pair with an address again, so ``fe80::/64`` was installed as the
single address ``fe80::``.
"""

import ipaddress

import pytest

from firewallfabrik.compiler.processors._generic import inet_address_problem
from firewallfabrik.core.objects import (
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    max_prefix_length,
    netmask_prefix_length,
)

_FIXTURE = """name: 'unreadable netmask'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'Firewall'
        name: 'fw'
        data:
          platform: '{platform}'
          host_OS: 'linux24'
          version: ''
        options:
          accept_established: false
          configure_interfaces: false
          flush_ruleset: false
          load_modules: false
          manage_virtual_addr: false
          verify_interfaces: false
        interfaces:
          - name: 'eth0'
            addresses:
              - type: 'IPv4'
                name: 'eth0-addr'
                inet_addr_mask:
                  address: '203.0.113.1'
                  netmask: '255.255.255.0'
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
            ipv4: true
            top: true
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
                direction: 'Both'
                src:
                  - 'Library:Test Objects/Network:net-a'
      - type: 'Network'
        name: 'net-a'
        inet_addr_mask:
          address: '10.0.0.0'
          netmask: '{netmask}'
"""


def _network(address, netmask):
    obj = Network(name='net')
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


def _network6(address, netmask):
    obj = NetworkIPv6(name='net6')
    obj.inet_addr_mask = {'address': address, 'netmask': netmask}
    return obj


@pytest.mark.parametrize(
    ('address', 'netmask', 'prefix'),
    [
        # Dotted, what Network::setNetmask writes for IPv4.
        ('10.0.0.0', '255.0.0.0', 8),
        ('10.0.0.0', '0.0.0.0', 0),  # nosec B104
        ('10.0.0.0', '255.255.255.255', 32),
        # A bit length, what NetworkIPv6::toXML writes and what an older
        # file carries for IPv4 as well.
        ('10.0.0.0', '8', 8),
        ('2001:db8::', '64', 64),
        # The address form for IPv6, which ip_network() refuses and which
        # the compilers themselves used to build.
        ('2001:db8::', 'ffff:ffff:ffff:ffff::', 64),
        ('2001:db8::1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 128),
        # What came out of the editors before this release.
        ('10.0.0.0', ' 255.0.0.0 ', 8),
        ('10.0.0.0', ' 8 ', 8),
    ],
)
def test_every_spelling_a_netmask_reaches_the_compilers_in_is_read(
    address, netmask, prefix
):
    assert netmask_prefix_length(address, netmask) == prefix


@pytest.mark.parametrize(
    ('address', 'netmask'),
    [
        ('10.0.0.0', '255.0.255.0'),  # zeroes in the middle
        ('10.0.0.0', '33'),  # outside the family
        ('10.0.0.0', 'eight'),
        ('10.0.0.0', '+8'),
        ('10.0.0.0', 'ffff::'),  # an IPv6 mask on an IPv4 address
        ('2001:db8::', '255.255.255.0'),  # and the other way round
        ('10.0.0.0', ''),
        ('not-an-ip', '8'),
    ],
)
def test_a_value_that_is_no_netmask_is_no_netmask(address, netmask):
    assert netmask_prefix_length(address, netmask) is None


@pytest.mark.parametrize(
    ('address', 'expected'),
    [('10.0.0.0', 32), ('2001:db8::', 128), ('not-an-ip', None)],
)
def test_the_host_mask_of_a_family(address, expected):
    """Testing a prefix against 32 alone turns an IPv6 /32 into one host."""
    assert max_prefix_length(address) == expected


def test_the_reader_agrees_with_ip_network_wherever_ip_network_answers():
    """The reader may take more, never something else.

    A disagreement would put the verify pass and the print rules on
    different answers, which is the state this whole pass is here to end.
    """
    for prefix in range(33):
        mask = str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)
        assert netmask_prefix_length('10.0.0.0', mask) == prefix
        assert (
            ipaddress.ip_network(f'10.0.0.0/{mask}', strict=False).prefixlen == prefix
        )


@pytest.mark.parametrize(
    ('obj', 'expected'),
    [
        (_network('10.0.0.0', '255.0.0.0'), ''),
        (_network('10.0.0.0', '8'), ''),
        (_network6('2001:db8::', 'ffff:ffff:ffff:ffff::'), ''),
        (_network('10.0.0.0', ' 255.0.0.0 '), ''),
    ],
    ids=['dotted', 'length', 'ipv6-address-form', 'stray-space'],
)
def test_a_netmask_the_reader_takes_costs_no_rule(obj, expected):
    assert inet_address_problem(obj) == expected


def test_a_netmask_that_means_nothing_is_named():
    problem = inet_address_problem(_network('10.0.0.0', '255.0.255.0'))
    assert '"255.0.255.0"' in problem
    assert 'is not a netmask' in problem
    assert 'single address 10.0.0.0' in problem


def test_an_address_that_means_nothing_is_named():
    problem = inet_address_problem(_network('10.0.0.0 ', '255.0.0.0'))
    assert '"10.0.0.0 "' in problem
    assert 'is not an IP address' in problem


@pytest.mark.parametrize(
    'obj',
    [
        IPv4(name='host', inet_addr_mask={'address': '10.0.0.1', 'netmask': '32'}),
        IPv6(name='host6', inet_addr_mask={'address': '2001:db8::1', 'netmask': '128'}),
        Network(name='empty', inet_addr_mask={}),
        Network(name='no-mask', inet_addr_mask={'address': '10.0.0.0'}),
    ],
    ids=['ipv4-host', 'ipv6-host', 'no-address', 'no-netmask'],
)
def test_an_object_with_nothing_to_complain_about_is_left_alone(obj):
    assert inet_address_problem(obj) == ''


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_a_rule_on_a_netmask_that_means_nothing_is_left_out(
    platform, compile_ipt, compile_nft, tmp_path
):
    """The whole point, end to end and on both platforms.

    The script used to carry this rule as `-s 10.0.0.0` / `ip saddr
    10.0.0.0` - a rule about one host where a whole network was named -
    and said nothing about it.
    """
    fixture = tmp_path / f'{platform}.fwf'
    fixture.write_text(_FIXTURE.format(platform=platform, netmask='255.0.255.0'))
    compile_fw = compile_ipt if platform == 'iptables' else compile_nft
    script = compile_fw(fixture, 'fw', tmp_path).read_text()

    assert 'is not a netmask' in script
    rules = [line for line in script.splitlines() if not line.lstrip().startswith('#')]
    assert not [line for line in rules if '10.0.0.0' in line]


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_a_netmask_only_the_shared_reader_takes_still_compiles(
    platform, compile_ipt, compile_nft, tmp_path
):
    """A bit length on an IPv4 network is a spelling, not a defect."""
    fixture = tmp_path / f'{platform}-length.fwf'
    fixture.write_text(_FIXTURE.format(platform=platform, netmask='8'))
    compile_fw = compile_ipt if platform == 'iptables' else compile_nft
    script = compile_fw(fixture, 'fw', tmp_path).read_text()

    assert '10.0.0.0/8' in script
    assert 'is not a netmask' not in script
