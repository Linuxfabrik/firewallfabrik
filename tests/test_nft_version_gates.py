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

"""Two nftables constructs are younger than a supported distribution.

nftables loads a ruleset in one transaction, so a construct the target
cannot parse costs the *whole* ruleset and the firewall keeps the rules it
had.  Almost everything this compiler writes is older than any nftables in
the field; these two are not, and both are reached by an ordinary rule:

* ``meta hour`` / ``meta day`` / ``meta time`` - what a Time object
  compiles to - arrived in nftables v0.9.3 (``NFT_META_TIME_HOUR`` in
  src/meta.c).  Rocky 8 ships 0.9.3, Debian 10 shipped 0.9.0.
* ``snat prefix to`` / ``dnat prefix to`` - the 1:1 network translation the
  iptables NETMAP target does - in v0.9.5 (``STMT_NAT_F_PREFIX`` in
  src/parser_bison.y).  There is no older spelling: a plain
  ``snat to <prefix>`` lets the kernel pick any address out of the range.

The release the firewall names belongs to the platform it names.  A `.fwb`
firewall set to iptables carries an *iptables* release, and this compiler
is asked to compile it all the same, so such a value has to count as none
at all - `getVersionsForPlatform` takes the platform as its argument for
that reason (fwbuilder libgui/platforms.cpp:418).
"""

import pytest

from firewallfabrik.platforms.iptables._utils import (
    DEFAULT_IPTABLES_VERSION,
    get_iptables_version,
)
from firewallfabrik.platforms.nftables._utils import (
    DEFAULT_NFTABLES_VERSION,
    NFT_NETMAP_FIRST_RELEASE,
    NFT_TIME_FIRST_RELEASE,
    get_nftables_version,
    nft_feature_available,
)


class _Firewall:
    def __init__(self, platform, version):
        self.platform = platform
        self.version = version


class _Compiler:
    def __init__(self, fw):
        self.fw = fw


@pytest.mark.parametrize(
    ('version', 'available'),
    [
        ('', True),
        ('0.9.0', False),
        ('0.9.3', True),
        ('0.9.5', True),
        ('1.1.6', True),
    ],
)
def test_the_time_match_needs_0_9_3(version, available):
    compiler = _Compiler(_Firewall('nftables', version))
    assert nft_feature_available(compiler, NFT_TIME_FIRST_RELEASE) is available


@pytest.mark.parametrize(
    ('version', 'available'),
    [
        ('', True),
        ('0.9.0', False),
        ('0.9.3', False),
        ('0.9.5', True),
        ('1.1.6', True),
    ],
)
def test_the_network_translation_needs_0_9_5(version, available):
    compiler = _Compiler(_Firewall('nftables', version))
    assert nft_feature_available(compiler, NFT_NETMAP_FIRST_RELEASE) is available


def test_an_unpinned_firewall_gets_the_newest():
    assert get_nftables_version(_Firewall('nftables', '')) == DEFAULT_NFTABLES_VERSION
    assert get_iptables_version(_Firewall('iptables', '')) == DEFAULT_IPTABLES_VERSION


@pytest.mark.parametrize('version', ['lt_1.2.6', 'ge_1.2.6', '1.2.9', '1.4.3'])
def test_an_iptables_release_says_nothing_about_nftables(version):
    """Read as an nftables release it is below every gate there is, and
    every firewall of the audit corpus is compiled for both platforms."""
    fw = _Firewall('iptables', version)
    assert get_nftables_version(fw) == DEFAULT_NFTABLES_VERSION
    assert nft_feature_available(_Compiler(fw), NFT_NETMAP_FIRST_RELEASE)


@pytest.mark.parametrize('version', ['0.9.0', '0.9.3', '0.9.5'])
def test_an_nftables_release_says_nothing_about_iptables(version):
    """The mirror: read as an iptables release it is below every gate,
    so every version-gated match would silently disappear."""
    assert get_iptables_version(_Firewall('nftables', version)) == (
        DEFAULT_IPTABLES_VERSION
    )
