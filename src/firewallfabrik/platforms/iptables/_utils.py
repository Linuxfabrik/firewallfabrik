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

"""IPTables utility functions.

Corresponds to fwbuilder's iptlib/ipt_utils.py.
"""

from __future__ import annotations

import re

from firewallfabrik.core.objects import (
    Address,
    AddressTable,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    PhysAddress,
    TagService,
    UserService,
    is_run_time_address_table,
)
from firewallfabrik.driver._interface_properties import (
    get_interface_var_name,
)

__all__ = ['get_interface_var_name']

# Version assumed for a firewall object that does not pin an iptables
# version.  The compiler adapts its output to the target version in a
# number of places (extrapositioned negation since 1.4.3, ``-m conntrack``
# since 1.4.4, ``-w`` since 1.4.20, ``-m set`` since 1.4.1.1).  Without a
# pinned version the target is whatever iptables the host runs, which for
# every currently supported distribution is 1.8.x.  Assuming the oldest
# known release instead would emit forms that current iptables rejects,
# such as the intrapositioned ``-s ! 192.0.2.0/24``.
DEFAULT_IPTABLES_VERSION = '1.8'

# The release a match first shipped in, per address family (IPv4, IPv6).
# Several of these started out as IPv4-only extensions and only reached
# ip6tables later, either through a libip6t_ file of their own or when
# netfilter merged the two extension trees into ``libxt_``, which is why
# the two columns differ.  Reproduce with, in the netfilter iptables
# checkout:
#
#   c=$(git log --all --format=%H --diff-filter=A -- extensions/libxt_tos.c \
#         | tail -1)
#   git tag --contains $c | grep -E '^v1\.[0-9]' | sort -V | head -1
#
# tos:     libipt_tos.c v1.0.0-alpha, libxt_tos.c v1.4.1
# dscp:    libipt_dscp.c v1.2.6,      libxt_dscp.c v1.4.0
# set:     libipt_set.c v1.3.0,       libxt_set.c v1.4.9
# iprange: libipt_iprange.c v1.2.9,   libxt_iprange.c v1.4.1
# time:    libipt_time.c v1.2.2,      libxt_time.c v1.4.0
#
# An IPv4 column of ``0`` means the match predates every target Firewall
# Builder can express, so it is never gated for IPv4.  The oldest entry of
# its version list is "1.2.5 or earlier", stored as ``lt_1.2.6``, and
# version_compare reads that as 0.2.6 on purpose (see there): a real
# release number in this column would then rank above it and take the
# match away from the one target that certainly has it.
#
# tests/test_ipt_version_gates.py re-derives the IPv6 column of every row
# from that history, so a new row is checked rather than trusted.
MATCH_FIRST_RELEASE = {
    'dscp': ('1.2.6', '1.4.0'),
    'iprange': ('1.2.9', '1.4.1'),
    'set': ('1.3.0', '1.4.9'),
    'time': ('0', '1.4.0'),
    'tos': ('0', '1.4.1'),
}


def match_available(compiler, rule, version: str, match: str) -> bool:
    """Report whether the pinned iptables knows *match*, for this family.

    Several matches reached ip6tables later than iptables, because they
    only became family neutral when netfilter merged the two extension
    trees.  A binary that predates the merge answers "Couldn't load
    match", which stops the activation script with the built-in policies
    already set to DROP, so the rule is reported and left out instead.

    Shared by the policy and the NAT printers: both emit matches out of
    MATCH_FIRST_RELEASE, and a gate only half the output goes through is
    no gate.
    """
    ipv6 = bool(getattr(compiler, 'ipv6_policy', False))
    first = MATCH_FIRST_RELEASE[match][ipv6]
    if version_compare(version, first) >= 0:
        return True
    tool = 'ip6tables' if ipv6 else 'iptables'
    compiler.error(
        rule,
        f'{tool} before {first} has no "{match}" match; the rule is left out',
    )
    return False


# The same question for the targets the compiler writes, derived the same
# way.  A target that reached ip6tables late costs more than a match does:
# ip6tables answers "Couldn't load target", which stops the activation
# script with the built-in policies already set to DROP.
#
# CLASSIFY: libipt_CLASSIFY.c v1.2.8, libxt_CLASSIFY.c v1.4.0 -- there
#           never was a libip6t_ file, so the merge is the cut-off.
# CONNMARK: libipt_CONNMARK.c v1.2.6, libip6t_CONNMARK.c v1.3.5.
#
# Not listed, and why: TCPMSS is gated where it is emitted (the mangle
# compiler knows the forwarding option it hangs on), NFLOG in the log
# printer, the NAT targets through IP6TABLES_NAT_FIRST_RELEASE, and LOG,
# MARK and REJECT are older than every release Firewall Builder can pin.
TARGET_FIRST_RELEASE = {
    'CLASSIFY': ('1.2.8', '1.4.0'),
    'CONNMARK': ('1.2.6', '1.3.5'),
}


def get_iptables_version(fw) -> str:
    """Return the iptables version a firewall is compiled for."""
    return fw.version or DEFAULT_IPTABLES_VERSION


# Address types that stand for exactly one ``-s`` / ``-d`` argument, and can
# therefore be negated with iptables' own ``!``.
_SINGLE_ADDRESS_TYPES = (IPv4, IPv6, Network, NetworkIPv6)


def single_negation_qualifies(compiler, obj) -> bool:
    """Return whether *obj* alone can be negated with one ``!``.

    The C++ test is ``countInetAddresses(true) == 1``, and only IPv4,
    IPv6, Network and NetworkIPv6 answer 1 (fwbuilder
    libfwbuilder/fwbuilder/Address.cpp returns 0 by default).  An
    AddressRange is deliberately not one of them: below iptables 1.2.11 -
    and, in a NAT rule, always - it is written out as the networks
    covering it, and one ``!`` per network negates each of them rather
    than the range, which matches nearly everything.

    Shared by the policy and the NAT pipelines: they ask the same question
    about the same objects, and the NAT half having its own, looser answer
    is what turned a negated range in a NAT rule into its own opposite.
    """
    # A run-time address table matched through ipset is a single set name,
    # so `-m set ! --match-set` says it exactly.  Without ipset the rule is
    # written once per address in the file, where one `!` per address would
    # again negate each of them separately.
    if is_run_time_address_table(obj):
        return bool(getattr(compiler, 'using_ipset', False))
    if isinstance(obj, TagService | UserService):
        # `-m mark` and `-m owner` both take the `!`.
        return True
    return isinstance(obj, _SINGLE_ADDRESS_TYPES) and not compiler.complex_match(
        obj, compiler.fw
    )


# The ipv4options match is not part of netfilter iptables.  It came from
# patch-o-matic, was carried in the tree as extensions/libipt_ipv4options.c
# until "Move extensions for pom patches to individual patchlets"
# (29f91845) took it out, and the first release without it is v1.3.8.  It
# lives on in xtables-addons, where it grew the --flags / --any spelling
# Firewall Builder gates on 1.4.3.  Both spellings are therefore emitted as
# written, because an administrator who set the option means it - but a
# stock iptables answers "Couldn't load match", which stops the activation
# script, so saying where the match comes from is worth a warning.
IPV4OPTIONS_LAST_RELEASE = '1.3.7'
IPV4OPTIONS_NOTE = (
    'The "ipv4options" match left netfilter iptables after '
    f'{IPV4OPTIONS_LAST_RELEASE} and is only available from xtables-addons; '
    'the firewall needs that package installed or the rule will not load'
)


def ipv4_options_match(data: dict, version: str) -> tuple[str, str]:
    """Return the ``-m ipv4options`` match for *data*, plus a problem with it.

    The two spellings are the two releases of the module: the one carried
    in iptables until 1.3.7 takes an option per flag, the one in
    xtables-addons takes a comma-separated ``--flags`` list.  Firewall
    Builder tells them apart by the iptables version, at 1.4.3.

    The older spelling refuses ``--ssrr`` next to ``--lsrr``
    ("Can't specify --ssrr with --lsrr", the last in-tree
    extensions/libipt_ipv4options.c), so that combination yields no match
    and a problem to report; the newer one takes both in one list.

    Returns ``(match, problem)``.  An empty *match* with a non-empty
    *problem* means the caller must not emit the rule as it stands.
    """

    def is_set(key: str) -> bool:
        return str(data.get(key)) == 'True'

    modern = version_compare(version, '1.4.3') >= 0

    if is_set('any_opt'):
        return ('-m ipv4options --any' if modern else '-m ipv4options --any-opt'), (
            IPV4OPTIONS_NOTE
        )

    if modern:
        names = {
            'lsrr': 'lsrr',
            'rr': 'record-route',
            'rtralt': 'router-alert',
            'ssrr': 'ssrr',
            'ts': 'timestamp',
        }
        options = [name for key, name in names.items() if is_set(key)]
        if not options:
            return '', ''
        return f'-m ipv4options --flags {",".join(options)}', IPV4OPTIONS_NOTE

    if is_set('lsrr') and is_set('ssrr'):
        return '', (
            'The "ipv4options" match of this iptables release cannot ask for '
            'loose and strict source routing at once; it answers "Can\'t '
            'specify --ssrr with --lsrr"'
        )

    names = {
        'lsrr': '--lsrr',
        'rr': '--rr',
        'rtralt': '--ra',
        'ssrr': '--ssrr',
        'ts': '--ts',
    }
    options = [name for key, name in names.items() if is_set(key)]
    if not options:
        return '', ''
    return '-m ipv4options ' + ' '.join(options), IPV4OPTIONS_NOTE


def version_compare(v1: str, v2: str) -> int:
    """Compare two iptables version strings. Returns -1, 0, or 1.

    Ports fwbuilder's ``XMLTools::version_compare``. Two properties of it
    matter here:

    * A component is read with C ``atoi`` semantics, so one that does not
      begin with a digit counts as 0. Firewall Builder's version list is
      not purely numeric: "1.2.5 or earlier" is stored as ``lt_1.2.6`` and
      "1.2.6 to 1.2.8" as ``ge_1.2.6`` (libgui/platforms.cpp). Dropping the
      non-numeric component instead would turn ``lt_1.2.6`` into ``2.6``,
      which outranks every real iptables release, and the compiler would
      then emit modern syntax for the oldest targets there are.
    * A missing trailing component counts as 0, so ``1.2.3`` equals
      ``1.2.3.0``.
    """

    def _atoi(part: str) -> int:
        match = re.match(r'[+-]?\d+', part.strip())
        return int(match.group()) if match else 0

    parts1 = [_atoi(p) for p in v1.split('.')] if v1 else [0]
    parts2 = [_atoi(p) for p in v2.split('.')] if v2 else [0]
    width = max(len(parts1), len(parts2))
    parts1 += [0] * (width - len(parts1))
    parts2 += [0] * (width - len(parts2))
    for a, b in zip(parts1, parts2, strict=True):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


# Seconds the generated script waits for the xtables lock.  A bare "-w"
# makes iptables block indefinitely (xtables_lock() only arms the alarm
# for a positive wait), which would stall an unattended rollout instead
# of failing; with no "-w" at all iptables gives up on the first lock
# collision.  Waiting a few seconds and then aborting with a clear
# message is the useful behaviour for a deployment script.  The bounded
# form needs iptables 1.6.0; older releases only understand a bare "-w".
IPTABLES_LOCK_WAIT_SECONDS = 5


def get_wait_option(version: str) -> str:
    """Return the xtables lock option, empty when the version lacks it."""
    if version_compare(version, '1.6.0') >= 0:
        return f'-w {IPTABLES_LOCK_WAIT_SECONDS}'
    if version_compare(version, '1.4.20') >= 0:
        return '-w'
    return ''


# iptables refuses a chain or target name of XT_EXTENSION_MAXNAMELEN
# characters or more (include/linux/netfilter/x_tables.h, checked in
# xshared.c), so 28 characters is the longest name that loads.  fwbuilder
# only rejects names longer than 30 and lets two unloadable lengths pass.
MAX_CHAIN_NAME_LENGTH = 28


# Every name iptables can load as a target, which is therefore a name no
# chain may have: `assert_valid_chain_name` asks
# `xtables_find_target(name, XTF_TRY_LOAD)` and refuses the name when it
# answers ("chain name may not clash with target name").
#
# The list is the extension files of the netfilter iptables tree whose name
# after the `libxt_` / `libipt_` / `libip6t_` prefix is upper case, plus the
# four verdicts the standard target provides:
#
#   ls extensions/ | grep -E '^lib(xt|ipt|ip6t)_[A-Z]' \
#     | sed -E 's/^lib(xt|ipt|ip6t)_//; s/\.[a-z]+$//' | sort -u
#
# `NAT` is the one file that names no target of its own - it holds the
# shared parser of SNAT and DNAT - and is left out; every other name was
# offered to iptables 1.8.11 and ip6tables 1.8.11 one by one.  Which of the
# two refuses a given name differs (`HL`, `DNPT` and `SNPT` are IPv6-only,
# `TTL` and `ECN` IPv4-only), and a dual-stack firewall creates its chains
# in both rulesets, so a name refused by either belongs here.
IPTABLES_TARGET_NAMES = frozenset(
    {
        'ACCEPT',
        'AUDIT',
        'CHECKSUM',
        'CLASSIFY',
        'CLUSTERIP',
        'CONNMARK',
        'CONNSECMARK',
        'CT',
        'DNAT',
        'DNPT',
        'DROP',
        'DSCP',
        'ECN',
        'HL',
        'HMARK',
        'IDLETIMER',
        'LED',
        'LOG',
        'MARK',
        'MASQUERADE',
        'NETMAP',
        'NFLOG',
        'NFQUEUE',
        'NOTRACK',
        'QUEUE',
        'RATEEST',
        'REDIRECT',
        'REJECT',
        'RETURN',
        'SECMARK',
        'SET',
        'SNAT',
        'SNPT',
        'SYNPROXY',
        'TCPMSS',
        'TCPOPTSTRIP',
        'TEE',
        'TOS',
        'TPROXY',
        'TRACE',
        'TTL',
        'ULOG',
    }
)


def _chain_name_problem(chain: str) -> str:
    """Return why iptables would refuse *chain*, or an empty string.

    Ports ``assert_valid_chain_name`` (netfilter iptables/xshared.c), which
    iptables applies to every ``-N`` and every ``-j`` naming a chain.  The
    compiler's own chains never reach the target-name test: the built-in
    chains, the temporary chains and the rule chains are named by the
    compiler, and a target it emits is recognised before the name is treated
    as a chain.  What does reach it is the name of a rule set or a branch,
    which the administrator chose.
    """
    if chain in IPTABLES_TARGET_NAMES:
        return (
            'is the name of an iptables target, and a chain may not have one '
            '("chain name may not clash with target name")'
        )
    if len(chain) > MAX_CHAIN_NAME_LENGTH:
        return (
            f'is longer than {MAX_CHAIN_NAME_LENGTH} characters, iptables '
            'refuses to create it'
        )
    if chain[:1] in ('-', '!'):
        return f'starts with "{chain[0]}", which iptables reads as an option'
    if any(char.isspace() for char in chain):
        return 'contains whitespace, which iptables does not allow in a chain name'
    return ''


def check_chain_name(compiler, chain: str, already_reported: set[str]) -> None:
    """Report chain names iptables would refuse, once per name."""
    if chain in already_reported:
        return
    if getattr(compiler, 'muted_now', False):
        # See check_interface_name: reporting once must not be spent on a
        # pass whose messages are thrown away.
        return
    problem = _chain_name_problem(chain)
    if not problem:
        return
    already_reported.add(chain)
    compiler.error(
        f'Chain name "{chain}" {problem}. Rename the rule set or branch it '
        'is generated from.',
    )


def get_address_table_var_name(at: AddressTable) -> str:
    """Generate a shell variable name for an address table."""
    name = at.name
    var_name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    return f'at_{var_name}'


# ipset stores a set name in a field of IPSET_MAXNAMELEN bytes (32, see
# include/linux/netfilter/ipset/ip_set.h in the netfilter ipset tree), so 31
# characters is the longest name that can be created.  fwbuilder only
# replaces the characters that would break the shell command around the name.
IPSET_MAX_NAME_LENGTH = 31


def normalize_set_name(name: str, ipv6: bool = False) -> str:
    """Normalize an ipset set name (max 31 chars, valid chars only).

    A set carries one address family, so an address table used by both
    rulesets needs one set per family; the IPv6 one gets a ``_v6`` suffix,
    the same way the interface address variables are named.
    """
    result = re.sub(r'[ +*!#|]', '_', name)
    suffix = '_v6' if ipv6 else ''
    if len(result) + len(suffix) > IPSET_MAX_NAME_LENGTH:
        result = result[: IPSET_MAX_NAME_LENGTH - len(suffix)]
    return result + suffix


def expand_interface_with_phys_address(
    iface: Interface,
    addr_obj: Address,
) -> tuple[Address | None, PhysAddress | None]:
    """Find the MAC address associated with an interface address.

    Returns (addr, phys_addr) tuple where phys_addr is the MAC address
    if found, None otherwise.
    """
    phys_addr = None
    for a in iface.addresses:
        if isinstance(a, PhysAddress):
            phys_addr = a
            break

    return addr_obj, phys_addr
