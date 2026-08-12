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

"""Names of nftables objects.

Tables, chains, sets and counters are named by an identifier of the nft
grammar, and the grammar takes a bare identifier only: ``identifier :
STRING | LAST`` (netfilter nftables ``src/parser_bison.y``) has no quoted
alternative, so a name that does not lex as ``string`` cannot be rescued by
quoting it.  Every user-chosen name reaching a declaration has to go through
:func:`nft_object_name` first, because ``nft -f`` refuses the *whole* ruleset
over one bad name, not just the rule that carries it.
"""

import re

# The kernel bounds an object name by NFT_NAME_MAXLEN (netfilter
# linux/include/uapi/linux/netfilter/nf_tables.h).
NFT_NAME_MAXLEN = 255

# Every keyword of the nft scanner is a token of its own, so it can never
# stand in for the `string` production an identifier is made of.  The list
# below is every literal of netfilter nftables `src/scanner.l` that nft
# v1.1.6 refuses as the name of a table, chain, set or counter:
#
#   printf 'table inet t {\n chain %s { }\n}\n' "$k" | unshare -rn nft --check -f -
#
# The list is only the trigger for the rename, never the rename itself: not
# one nft keyword contains an underscore, because `_` is reserved to the
# first-character class of `string`.  A name that ends in `_` therefore
# cannot collide with any nft keyword, present or future, which is what
# keeps the rename correct even if this list falls behind.
NFT_KEYWORDS = frozenset(
    {
        '-',
        '.',
        'accept',
        'add',
        'ah',
        'all',
        'and',
        'arp',
        'auto-merge',
        'bridge',
        'bytes',
        'cgroup',
        'chain',
        'comment',
        'comp',
        'constant',
        'continue',
        'counter',
        'cpu',
        'create',
        'ct',
        'day',
        'dccp',
        'define',
        'delete',
        'describe',
        'destroy',
        'device',
        'devices',
        'dnat',
        'drop',
        'dst',
        'dup',
        'dynamic',
        'ecn',
        'element',
        'elements',
        'eq',
        'esp',
        'ether',
        'exists',
        'expires',
        'export',
        'exthdr',
        'fib',
        'flags',
        'flow',
        'flowtable',
        'flush',
        'frag',
        'fwd',
        'gc-interval',
        'ge',
        'geneve',
        'get',
        'goto',
        'gre',
        'gretap',
        'gt',
        'handle',
        'hbh',
        'hook',
        'hour',
        'ibriport',
        'ibrname',
        'icmp',
        'icmpv6',
        'igmp',
        'iif',
        'iifgroup',
        'iifname',
        'iiftype',
        'import',
        'include',
        'index',
        'inet',
        'insert',
        'interval',
        'ip',
        'ip6',
        'ipsec',
        'jhash',
        'jump',
        'le',
        'limit',
        'list',
        'log',
        'lshift',
        'lt',
        'map',
        'mark',
        'masquerade',
        'meta',
        'meter',
        'mh',
        'missing',
        'monitor',
        'name',
        'ne',
        'netdev',
        'nftrace',
        'not',
        'notrack',
        'numgen',
        'obriport',
        'obrname',
        'offload',
        'oif',
        'oifgroup',
        'oifname',
        'oiftype',
        'or',
        'osf',
        'packets',
        'pkttype',
        'policy',
        'position',
        'priority',
        'queue',
        'quota',
        'random',
        'redefine',
        'redirect',
        'reject',
        'rename',
        'replace',
        'reset',
        'return',
        'rshift',
        'rt',
        'rt0',
        'rt2',
        'rtclassid',
        'rule',
        'ruleset',
        'sctp',
        'secmark',
        'set',
        'size',
        'skgid',
        'skuid',
        'snat',
        'socket',
        'srh',
        'symhash',
        'synproxy',
        'table',
        'tcp',
        'th',
        'time',
        'timeout',
        'tproxy',
        'tunnel',
        'type',
        'typeof',
        'udp',
        'udplite',
        'undefine',
        'update',
        'vlan',
        'vmap',
        'vni',
        'vxlan',
        'xor',
        'xt',
    }
)

# The scanner's `string` production is
# `({letter}|[_.])({letter}|{digit}|[/\-_\.])*`, so "/" would be legal as
# well.  It is left out on purpose: a name is spliced into a shell script
# next to file paths, where a slash reads as one.
_NFT_ILLEGAL_CHARS_RE = re.compile(r'[^A-Za-z0-9_.\-]')

# Used when a name sanitises down to nothing at all.
_FALLBACK_NAME = '_unnamed'

# The chain names the compiler gives the hooked chains of its own tables.
# nftables has no objection to them, but the compiler is competing with
# itself here: a branch rule set named after one of them would be merged
# into the hooked chain, so its rules would run on all traffic, and the
# jump into it is one the kernel refuses outright - `nf_tables_api.c`
# answers -EOPNOTSUPP for a jump to a base chain
# (`if (nft_is_base_chain(chain))`), which throws away the whole ruleset.
NFT_HOOKED_CHAIN_NAMES = frozenset(
    {
        'forward',
        'input',
        'output',
        'postrouting',
        'prerouting',
    }
)


def is_valid_nft_identifier(name: str) -> bool:
    """Return whether *name* can name an nftables object as it is.

    True exactly when :func:`nft_object_name` would hand the name back
    unchanged, so the two can never disagree about what needs repairing.
    """
    return bool(name) and nft_object_name(name) == name


def nft_object_name(name: str) -> str:
    """Return a name nftables accepts for the object called *name*.

    Four things can make a name unusable, and all four are repaired here
    rather than reported, because the alternative is a ruleset that does not
    load at all:

    * a character outside the identifier alphabet becomes an underscore;
    * a first character that is not a letter, an underscore or a dot gets an
      underscore in front - a DNS name such as "6bone.net" would otherwise
      lex as a number, and a leading "-" is outside the first-character
      class as well;
    * a name longer than the kernel's limit is cut;
    * a name that collides with an nft keyword, or with one of the hooked
      chain names the compiler gives its own tables, gets an underscore
      appended.

    The suffix goes at the end so the name still reads and sorts next to the
    one the admin typed, and it is the load-bearing part: neither an nft
    keyword nor a hooked chain name contains an underscore, so the
    transform stays correct even if either list rots.
    """
    result = _NFT_ILLEGAL_CHARS_RE.sub('_', name)
    if not result:
        return _FALLBACK_NAME
    if not (result[0].isalpha() or result[0] in '_.'):
        result = f'_{result}'
    result = result[:NFT_NAME_MAXLEN]
    if result in NFT_KEYWORDS or result in NFT_HOOKED_CHAIN_NAMES:
        result = f'{result}_'
    return result


def nft_quote(text: str) -> str:
    """Return *text* as an nftables quoted string.

    The scanner reads a quoted string as ``\\"[^"]*\\"`` (netfilter nftables
    ``src/scanner.l``), so it knows no escape at all and one quotation mark
    inside the text ends it early, taking the rest of the ruleset with it.
    A quotation mark therefore becomes an apostrophe, the same substitution
    :func:`firewallfabrik.platforms.linux._netfilter.sanitize_log_prefix`
    makes for a log prefix.
    """
    return '"{}"'.format(text.replace('"', "'"))


def nft_set_reference_name(obj, ipv6: bool) -> str | None:
    """Return the named set an address object is rendered as, or None.

    Three kinds of object have no address at compile time and are matched
    through a set the activation script fills in: a run-time address table,
    a run-time DNS name and a dynamic interface.  The print rules derive
    the name here so that a processor that has to reason about those sets -
    two of them cannot share one rule, because the matches of one rule are
    ANDed - agrees with what is finally written out.
    """
    from firewallfabrik.core.objects import (
        DNSName,
        Interface,
        is_run_time_address_table,
    )

    suffix = '_v6' if ipv6 else ''
    if is_run_time_address_table(obj) or isinstance(obj, DNSName):
        return nft_object_name(obj.name) + suffix
    if isinstance(obj, Interface) and obj.is_dynamic():
        return nft_object_name(f'i_{obj.name}') + suffix
    return None
