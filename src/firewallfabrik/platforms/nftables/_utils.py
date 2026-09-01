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

"""The nftables release a firewall is compiled for, and what needs which.

Almost everything this compiler writes is older than any nftables a
supported distribution ships.  Two constructs are not, and both are
reached by an ordinary rule rather than by an exotic option - which is
what makes the release worth asking about at all.  nftables loads a
ruleset in one transaction, so a construct the target cannot parse costs
the *whole* ruleset and the firewall keeps the rules it had.
"""

from __future__ import annotations

from firewallfabrik.platforms.iptables._utils import version_compare

__all__ = [
    'DEFAULT_NFTABLES_VERSION',
    'NFT_IP_OPTION_FIRST_RELEASE',
    'NFT_NETMAP_FIRST_RELEASE',
    'NFT_TIME_FIRST_RELEASE',
    'get_nftables_version',
    'nft_feature_available',
    'version_compare',
]

# Release assumed for a firewall that pins none.  The same convention the
# iptables side uses: without a pinned release the target is whatever
# nftables the machine runs, and assuming the oldest known release would
# take away constructs every current distribution can parse.
DEFAULT_NFTABLES_VERSION = '1.1'

# `ip option <name> exists`, which an IP Service matching a source-route,
# record-route or router-alert option compiles to.  Matching an IPv4 header
# option needs the exthdr expression to know the IPv4 operation
# (`NFT_EXTHDR_OP_IPV4`), which the kernel gained in Linux 5.3 and nftables
# in v0.9.2 (src/ipopt.c, "exthdr: add support for matching IPv4 options",
# 2019-07-03).  `ip hdrlength > 5`, which "match any IP option" compiles to,
# is an ordinary header field and needs none of it.
NFT_IP_OPTION_FIRST_RELEASE = '0.9.2'

# `meta hour`, `meta day` and `meta time`, which a rule carrying a Time
# object compiles to.  The kernel gained the three in Linux 5.4 and
# nftables in v0.9.3 (`NFT_META_TIME_HOUR` in src/meta.c, 2019-08-29).
NFT_TIME_FIRST_RELEASE = '0.9.3'

# `snat prefix to` / `dnat prefix to`, the 1:1 network translation the
# iptables NETMAP target does.  A plain `snat to <prefix>` is a different
# rule - it lets the kernel pick any address out of the range - so there
# is no older spelling to fall back on.  nftables v0.9.5
# (`STMT_NAT_F_PREFIX` in src/parser_bison.y, 2020-04-24).
NFT_NETMAP_FIRST_RELEASE = '0.9.5'


def get_nftables_version(fw) -> str:
    """Return the nftables release a firewall is compiled for.

    The release belongs to the platform the firewall names, which is what
    `getVersionsForPlatform` says by taking the platform as its argument
    (fwbuilder libgui/platforms.cpp:418): `lt_1.2.6` on a firewall set to
    iptables is an iptables release and says nothing about nftables.  This
    compiler is asked to compile such a firewall all the same - the CLI
    takes the platform from the command it was called as, and every
    firewall of the audit corpus is compiled for both - so a version
    written for the other platform counts as none at all.
    """
    if getattr(fw, 'platform', '') != 'nftables':
        return DEFAULT_NFTABLES_VERSION
    return getattr(fw, 'version', '') or DEFAULT_NFTABLES_VERSION


def nft_feature_available(compiler, first_release: str) -> bool:
    """Whether the release the firewall names can parse a construct."""
    return version_compare(get_nftables_version(compiler.fw), first_release) >= 0
