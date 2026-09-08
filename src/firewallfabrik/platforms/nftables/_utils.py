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
supported distribution ships.  A few constructs are not, and they are
reached by an ordinary rule rather than by an exotic option - which is
what makes the release worth asking about at all.  nftables loads a
ruleset in one transaction, so a construct the target cannot parse costs
the *whole* ruleset and the firewall keeps the rules it had.

One of them is not reached by a rule at all: the name of a standard chain
priority sits on the first line of every base chain, so a release that
cannot read it refuses every ruleset this compiler writes.
"""

from __future__ import annotations

from firewallfabrik.platforms.iptables._utils import version_compare

__all__ = [
    'DEFAULT_NFTABLES_VERSION',
    'NFT_DYNAMIC_SET_FIRST_RELEASE',
    'NFT_INET_ROUTE_CHAIN_FIRST_RELEASE',
    'NFT_IP_OPTION_FIRST_RELEASE',
    'NFT_NETMAP_FIRST_RELEASE',
    'NFT_STANDARD_PRIORITIES',
    'NFT_SYMBOLIC_PRIORITY_FIRST_RELEASE',
    'NFT_TIME_FIRST_RELEASE',
    'get_nftables_version',
    'nft_chain_priority',
    'nft_feature_available',
    'nft_mangle_chain_type',
    'version_compare',
]

# Release assumed for a firewall that pins none.  The same convention the
# iptables side uses: without a pinned release the target is whatever
# nftables the machine runs, and assuming the oldest known release would
# take away constructs every current distribution can parse.
DEFAULT_NFTABLES_VERSION = '1.1'

# `flags dynamic` on a set declaration, which a rule limiting concurrent
# connections per source needs: the set holds one element per address and
# the rule creates them as it sees them, and the flag is what tells the
# kernel to pick a set backend that allows that.  nftables v0.9.1
# ("src: add dynamic flag and use it", 2018-06-11); the token does not
# exist in v0.9.0's scanner, so the ruleset does not parse there at all.
NFT_DYNAMIC_SET_FIRST_RELEASE = '0.9.1'

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

# The name of a standard chain priority - `priority filter` rather than
# `priority 0`.  nftables v0.9.1 ("src: Set/print standard chain prios
# with textual names", c8a0e8c9, 2018-08-03); before it the grammar reads
# a priority as `NUM | DASH NUM` and nothing else (src/parser_bison.y,
# `prio_spec`), so the name is a syntax error on the very first line of
# every base chain.
NFT_SYMBOLIC_PRIORITY_FIRST_RELEASE = '0.9.1'

# What each of those names stands for, taken from nftables' own table
# (`std_prios` in src/rule.c) and the kernel constants behind it
# (`NF_IP_PRI_*` in include/uapi/linux/netfilter_ipv4.h).  The ip, ip6
# and inet families share these numbers; the bridge family does not, and
# this compiler writes no bridge table.
NFT_STANDARD_PRIORITIES = {
    'dstnat': -100,
    'filter': 0,
    'mangle': -150,
    'srcnat': 100,
}

# A `type route` chain in an `inet` table.  The chain type itself is as
# old as nftables - the ip and ip6 families have had it since the kernel
# gained nf_tables - but the inet family got it only in Linux 5.2
# ("netfilter: nf_tables: merge route type into core", c1deb065cf3b), and
# an older kernel answers the chain with EOPNOTSUPP, which costs the whole
# ruleset rather than the chain.  The release named here is the first
# nftables after that kernel (v0.9.2, 2019-08-27; Linux 5.2 is
# 2019-07-07), the same proxy `NFT_IP_OPTION_FIRST_RELEASE` and
# `NFT_TIME_FIRST_RELEASE` use for a kernel feature.
NFT_INET_ROUTE_CHAIN_FIRST_RELEASE = '0.9.2'

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


def nft_mangle_chain_type(fw, family: str, chain: str) -> str:
    """The chain type the mangle table's *chain* has to be declared with.

    Only the output hook has an answer other than "filter", and it is the
    one thing an iptables mangle table does that a plain filter chain does
    not: `ipt_mangle_out` remembers the source, the destination, the ToS
    byte and the packet mark, and asks `ip_route_me_harder` for a new
    route whenever the chain changed one of them
    (linux/net/ipv4/netfilter/iptable_mangle.c).  That is what makes a Tag
    rule in the output chain steer locally generated traffic at all.

    nftables says it with the chain *type*: `nf_route_table_hook4` does
    exactly the same comparison and reroute
    (linux/net/netfilter/nft_chain_route.c), and `type filter` does none
    of it - the mark is set, the packet takes the route it already had,
    and nothing anywhere says so.

    The inet family is the exception, and only for a release old enough
    to name a kernel that has no inet route chain: there the mangle output
    chain stays a filter chain, because a chain type the kernel refuses
    costs the whole ruleset and not the reroute.
    """
    if chain != 'output':
        return 'filter'
    if family == 'inet' and not (
        version_compare(get_nftables_version(fw), NFT_INET_ROUTE_CHAIN_FIRST_RELEASE)
        >= 0
    ):
        return 'filter'
    return 'route'


def nft_chain_priority(fw, name: str) -> str:
    """Spell a standard chain priority the way the target release reads it.

    The name is the readable form and what every current nftables prints
    back, so it is kept wherever the release understands it.  Older ones
    take the number, and there is no third answer: a ruleset loads in one
    transaction, so a base chain the target cannot parse costs the whole
    ruleset and the firewall keeps the rules it had.
    """
    if (
        version_compare(get_nftables_version(fw), NFT_SYMBOLIC_PRIORITY_FIRST_RELEASE)
        >= 0
    ):
        return name
    return str(NFT_STANDARD_PRIORITIES[name])
