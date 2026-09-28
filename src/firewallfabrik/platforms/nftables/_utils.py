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

from firewallfabrik.platforms._versions import newest
from firewallfabrik.platforms.iptables._utils import version_compare

__all__ = [
    'DEFAULT_NFTABLES_VERSION',
    'NFT_CONNLIMIT_SET_FIRST_RELEASE',
    'NFT_DYNAMIC_SET_FIRST_RELEASE',
    'NFT_FLAG_MASK_FIRST_RELEASE',
    'NFT_INET_ROUTE_CHAIN_FIRST_RELEASE',
    'NFT_IP_OPTION_FIRST_RELEASE',
    'NFT_NAT_PRIORITY_ANY_HOOK_FIRST_RELEASE',
    'NFT_NETMAP_FIRST_RELEASE',
    'NFT_RATE_PER_KEY_FIRST_RELEASE',
    'NFT_REJECT_CODE_FIRST_RELEASE',
    'NFT_STANDARD_PRIORITIES',
    'NFT_SYMBOLIC_PRIORITY_FIRST_RELEASE',
    'NFT_TIME_FIRST_RELEASE',
    'get_nftables_version',
    'nft_chain_priority',
    'nft_feature_available',
    'nft_mangle_chain_type',
    'nft_tcp_flags',
    'version_compare',
]

# Release assumed for a firewall that pins none: the top entry of the
# editor's list (platforms/_versions.py), the one range that is open
# upwards.  The same convention the iptables side uses, and derived from
# the list rather than written twice, so that a gate added above it moves
# both together.  The driver warns about a firewall that pins none.
DEFAULT_NFTABLES_VERSION = newest('nftables')[0]

# `flags dynamic` on a set declaration, which a rule limiting concurrent
# connections per source needs: the set holds one element per address and
# the rule creates them as it sees them, and the flag is what tells the
# kernel to pick a set backend that allows that.  nftables v0.9.1
# ("src: add dynamic flag and use it", 2018-06-11); the token does not
# exist in v0.9.0's scanner, so the ruleset does not parse there at all.
NFT_DYNAMIC_SET_FIRST_RELEASE = '0.9.1'

# `ct count` inside a set, which a per-source connection limit compiles
# to.  It needs the set declared `flags dynamic`, so it cannot come before
# NFT_DYNAMIC_SET_FIRST_RELEASE, and mainline Linux has taken it since
# 4.18 ("netfilter: nf_tables: add connlimit support", 290180e2448c).
# RHEL 8 got the set element expressions only with kernel build
# 4.18.0-359 ("nf_tables: add elements with stateful expressions" and its
# series, in the kernel changelog), which RHEL 8.6 ships; RHEL 8.0 to 8.5
# answer it with EOPNOTSUPP and therefore take the 0.9.0 entry.
NFT_CONNLIMIT_SET_FIRST_RELEASE = '0.9.1'

# A rate limit kept per key, which is a `limit` inside a set the rule
# updates - declared `flags dynamic,timeout`, so again not before
# NFT_DYNAMIC_SET_FIRST_RELEASE.  The kernel side is the same set element
# expression support as for `ct count`, with the same RHEL 8 history.
NFT_RATE_PER_KEY_FIRST_RELEASE = '0.9.1'

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

# The `<value> / <mask>` notation for a flag match - `tcp flags syn /
# syn,rst,ack` - which reads as the iptables `--tcp-flags` it translates.
# nftables v0.9.9 ("parser_bison: add shortcut syntax for matching flags
# without binary operations", c3d57114, 2021-05-13); before it the slash is
# a syntax error, and the bitwise form every release parses has to be
# written out: `tcp flags & (syn | rst | ack) == syn`.
NFT_FLAG_MASK_FIRST_RELEASE = '0.9.9'

# `reject with icmp host-unreachable`, the code without the `type` keyword
# in front of it.  nftables v1.0.0 ("src: promote 'reject with icmp CODE'
# syntax", 08d2f049, 2021-07-26); before it the grammar wants `icmp type
# <code>`, which every later release still parses (src/parser_bison.y,
# `reject_opts`).
NFT_REJECT_CODE_FIRST_RELEASE = '1.0.0'

# The name of a NAT priority on the hook the other half of NAT uses:
# `priority dstnat` on the output hook, `priority srcnat` on the input hook.
# nftables v1.0.9 ("rule: allow src/dstnat prios in input and output",
# 8beafab7, 2023-07-28); before it `std_prio_lookup` accepts `dstnat` on
# prerouting and `srcnat` on postrouting alone and answers "invalid
# priority expression value in this context" everywhere else.
NFT_NAT_PRIORITY_ANY_HOOK_FIRST_RELEASE = '1.0.9'

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


def nft_chain_priority(fw, name: str, hook: str = '') -> str:
    """Spell a standard chain priority the way the target release reads it.

    The name is the readable form and what every current nftables prints
    back, so it is kept wherever the release understands it.  Older ones
    take the number, and there is no third answer: a ruleset loads in one
    transaction, so a base chain the target cannot parse costs the whole
    ruleset and the firewall keeps the rules it had.
    """
    release = get_nftables_version(fw)
    unusual_nat_hook = (name, hook) in (('dstnat', 'output'), ('srcnat', 'input'))
    if version_compare(release, NFT_SYMBOLIC_PRIORITY_FIRST_RELEASE) >= 0 and (
        not unusual_nat_hook
        or version_compare(release, NFT_NAT_PRIORITY_ANY_HOOK_FIRST_RELEASE) >= 0
    ):
        return name
    return str(NFT_STANDARD_PRIORITIES[name])


def nft_tcp_flags(fw, values: list[str], mask: list[str], negated: bool = False) -> str:
    """Match the TCP flags in *mask* against *values*, in the target's spelling.

    Both spellings compare the same bits; the slash one is what current
    nftables prints back and what iptables-translate writes, so it is kept
    wherever the release parses it.  *fw* may be None for "the newest".
    """
    release = get_nftables_version(fw) if fw is not None else DEFAULT_NFTABLES_VERSION
    if version_compare(release, NFT_FLAG_MASK_FIRST_RELEASE) >= 0:
        operator = '!= ' if negated else ''
        return f'tcp flags {operator}{",".join(values)} / {",".join(mask)}'
    operator = '!=' if negated else '=='
    return f'tcp flags & ({" | ".join(mask)}) {operator} {" | ".join(values)}'
