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

"""IPv6 hardening: accept_redirects / accept_source_route also target IPv6.

The two hardening knobs are the only IPv4 kernel settings with an IPv6
equivalent that exists on supported kernels (RHEL 8+). They are emitted
for the IPv6 stack only when the firewall handles IPv6 and the option is
actually set. Verified for both the iptables and nftables OS
configurators since no regression fixture exercises these options.
"""

import pytest

from firewallfabrik.platforms.iptables._os_configurator import OSConfigurator_linux24
from firewallfabrik.platforms.nftables._os_configurator import OSConfigurator_nft

_V6_REDIRECTS = '/proc/sys/net/ipv6/conf/all/accept_redirects'
_V6_SOURCE_ROUTE = '/proc/sys/net/ipv6/conf/all/accept_source_route'
_V4_REDIRECTS = '/proc/sys/net/ipv4/conf/all/accept_redirects'


class _FakeFW:
    version = ''

    def __init__(self, options):
        self._options = options

    def get_option(self, key):
        return self._options.get(key)

    @property
    def interfaces(self):
        return []


def _configurator(cls, options):
    oc = cls.__new__(cls)
    oc.fw = _FakeFW(options)
    return oc


_CLASSES = [OSConfigurator_linux24, OSConfigurator_nft]
_HARDENING = {
    'linux24_accept_redirects': '0',
    'linux24_accept_source_route': '0',
}


@pytest.mark.parametrize('cls', _CLASSES)
def test_ipv4_only_emits_no_ipv6_lines(cls):
    out = _configurator(cls, _HARDENING).process_firewall_options(have_ipv6=False)
    assert _V4_REDIRECTS in out
    assert _V6_REDIRECTS not in out
    assert _V6_SOURCE_ROUTE not in out


@pytest.mark.parametrize('cls', _CLASSES)
def test_ipv6_adds_hardening_for_both_stacks(cls):
    out = _configurator(cls, _HARDENING).process_firewall_options(have_ipv6=True)
    assert _V4_REDIRECTS in out
    assert _V6_REDIRECTS in out
    assert _V6_SOURCE_ROUTE in out


@pytest.mark.parametrize('cls', _CLASSES)
def test_unset_option_emits_no_ipv6_line(cls):
    out = _configurator(cls, {}).process_firewall_options(have_ipv6=True)
    assert _V6_REDIRECTS not in out
    assert _V6_SOURCE_ROUTE not in out
