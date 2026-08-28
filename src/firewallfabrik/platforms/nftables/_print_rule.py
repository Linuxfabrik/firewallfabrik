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

"""PrintRule_nft: nftables rule syntax generation from compiled CompRules.

Generates nft rule statements for the `nft -f` batch format.
Unlike iptables, nftables rules are expressed as:

    ip saddr 10.0.0.0/8 tcp dport { 22, 80, 443 } accept

This module handles filter (policy) rules. NAT rules are handled
separately in _nat_print_rule.py.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from typing import TYPE_CHECKING, ClassVar, cast

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._interval_helpers import (
    DOW_NAMES_FULL,
    date_problem,
    is_any_interval,
    parse_interval_data,
    parse_interval_dates,
)
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core._options import option_is_true
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    CustomService,
    Direction,
    DNSName,
    Host,
    ICMP6Service,
    ICMPService,
    Interface,
    IPService,
    Network,
    NetworkIPv6,
    PhysAddress,
    PolicyAction,
    TagService,
    TCPService,
    UDPService,
    UserService,
    get_address_table_source,
    is_run_time_address_table,
    is_valid_dscp,
    is_valid_packet_mark,
    is_valid_user_id,
    max_prefix_length,
    netmask_prefix_length,
    normalize_mac_address,
    packet_mark_clear_mask,
    range_to_cidr,
)
from firewallfabrik.platforms.linux._netfilter import (
    ANY_INTERFACE,
    check_interface_name,
    get_log_copy_range,
    get_log_netlink_group,
    get_log_queue_threshold,
    get_mac_only_address,
    get_tag_value,
    has_ip_options,
    is_valid_traffic_class,
    normalize_hashlimit_mode,
    normalize_rate_unit,
    reject_type_token,
    sanitize_log_prefix,
)
from firewallfabrik.platforms.nftables._identifiers import (
    nft_object_name,
    nft_quote,
    nft_set_reference_name,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.nftables._policy_compiler import PolicyCompiler_nft


# A data-dict value may be a Python bool or the string a data file
# carries, on a line of its own if that is how the file was written.
_is_true = option_is_true


def _as_iface_set(names: list[str]) -> str:
    """Render one interface name as it is, several as an anonymous set."""
    quoted = [nft_quote(name) for name in names]
    if len(quoted) == 1:
        return quoted[0]
    return '{ ' + ', '.join(quoted) + ' }'


def print_fragment_match(ipv6: bool) -> str:
    """Return the nftables match for "this is a fragment".

    iptables expresses it as ``-f`` for IPv4 and ``-m frag --fragmore`` for
    IPv6.  The nftables spellings are the ones ``iptables-translate`` /
    ``ip6tables-translate`` produce (netfilter
    ``extensions/libxt_tcp.txlate`` and ``extensions/libip6t_frag.txlate``).
    """
    if ipv6:
        return 'frag more-fragments 1'
    return 'ip frag-off & 0x1fff != 0'


# Targets that only write a log message and let the packet fall through to
# the next rule.
LOG_TARGETS = frozenset({'LOG', 'NFLOG', 'ULOG'})

# Rule option holding the protocols a negated service element does *not*
# name, set by `AddOtherProtocolsForNegatedService` on the extra rule it
# adds.  See that processor for why the extra rule exists.
OTHER_PROTOCOLS_OPTION = 'nft_other_protocols'


def other_protocols_for(services: list, ipv6: bool) -> list[str]:
    """Return the protocols a negated service element does *not* name.

    An empty list means the element needs no second rule, either because
    its negation already applies to every packet or because this compiler
    cannot say what the element leaves out.  See
    ``AddOtherProtocolsForNegatedService`` for the whole reasoning; the
    cases are:

    * a service naming nothing but its protocol ("All TCP"), whose
      negation is already ``meta l4proto != tcp`` and complete;
    * a Tag, User or Custom service, which constrains no protocol at all
      (and whose ``!=`` therefore already applies to every packet) or
      carries platform text this compiler cannot read;
    * an IP service, which the printers invert as a whole.
    """
    if not services:
        return []

    names: set[str] = set()
    for srv in services:
        if isinstance(srv, (TCPService, UDPService)):
            if srv.is_any():
                return []
            names.add(srv.get_protocol_name())
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            codes = getattr(srv, 'codes', None) or srv.data or {}
            # This runs long before `VerifyIcmpTypes` leaves the rule out
            # over a stored type that is not a number, so it has to answer
            # rather than raise: "cannot say what the element leaves out"
            # is the right answer for a value nobody can read anyway.
            try:
                icmp_type = int(codes.get('type', -1) or -1)
            except (TypeError, ValueError):
                return []
            if icmp_type < 0:
                return []
            names.add('ipv6-icmp' if ipv6 else 'icmp')
        else:
            return []
    return sorted(name for name in names if name)


# The largest burst a rate limit can carry.  It travels in a 32-bit netlink
# attribute in both directions (netfilter nftables src/netlink_linearize.c
# writes NFTNL_EXPR_LIMIT_BURST with nftnl_expr_set_u32, the kernel reads it
# with nla_get_be32 in net/netfilter/nft_limit.c), and neither end reports a
# larger number - it is cut to its low 32 bits.  This is not the 10000 of
# the iptables limit match.
MAX_NFT_LIMIT_BURST = 2**32 - 1

# The longest log prefix the kernel carries, for a netlink group as well as
# for plain logging: NF_LOG_PREFIXLEN is 128 and holds the terminator
# (netfilter linux/include/uapi/linux/netfilter/nf_log.h,
# net/netfilter/nft_log.c).  nft answers a longer one with "log prefix is
# too long" and refuses the whole ruleset over it.
MAX_NFT_LOG_PREFIX = 127


# IPv4 option flags of an IPService mapped to the nftables option keyword.
# nftables knows lsrr, rr, ssrr and ra (see the ip_option_type rule in the
# netfilter nftables parser, src/parser_bison.y).  fwbuilder's "timestamp"
# option has no nftables keyword.
_IP_OPTION_KEYWORDS = {
    'lsrr': 'lsrr',
    'rr': 'rr',
    'rtralt': 'ra',
    'ssrr': 'ssrr',
}


def print_ip_option_matches(data: dict) -> tuple[list[str], list[str]]:
    """Return the nftables IPv4-option matches of an IPService.

    Mirrors the ``-m ipv4options`` match the iptables print rules emit.
    Returns the list of match expressions and the list of requested options
    nftables cannot express, so the caller can report them.

    ``any_opt`` ("match any IP option") becomes ``ip hdrlength > 5``: an IPv4
    header carries options exactly when it is longer than the 5 words of the
    fixed header.
    """
    if _is_true(data.get('any_opt')):
        return (['ip hdrlength > 5'], [])

    matches = []
    for flag, keyword in sorted(_IP_OPTION_KEYWORDS.items()):
        if _is_true(data.get(flag)):
            matches.append(f'ip option {keyword} exists')
    unsupported = ['timestamp'] if _is_true(data.get('ts')) else []
    return (matches, unsupported)


def print_mark_set(tag_code: str) -> str:
    """Return the nftables statement for an iptables ``--set-mark value[/mask]``.

    A bare value is assigned directly (``meta mark set 0x10``).  A masked
    value keeps the bits outside the mask, which nftables spells out as the
    bitwise expression ``meta mark set mark and <~mask> xor <value>``.

    The mask ``--set-mark`` clears is **value | mask**, not the mask alone -
    that is exactly what separates it from ``--set-xmark`` (netfilter
    ``extensions/libxt_MARK.c``, ``mark_tg_parse``: ``O_SET_MARK`` assigns
    ``info->mask = cb->val.mark | cb->val.mask`` where ``O_SET_XMARK``
    assigns ``cb->val.mask``).  For ``0x40/0x32`` netfilter's own translator
    therefore emits ``mark and 0xffffff8d xor 0x40``
    (``extensions/libxt_MARK.txlate``, read together with
    ``mark_tg_xlate``), and a packet that already carries bit ``0x40`` comes
    out of both rules with the bit set.
    """
    value = tag_code.partition('/')[0].strip()
    clear = packet_mark_clear_mask(tag_code)
    if clear is None:
        return f'meta mark set {value}'
    keep = (~clear) & 0xFFFFFFFF
    return f'meta mark set mark and {keep:#010x} xor {value}'


def print_connmark(connmark_arg: str) -> str:
    """Return the nftables statement for an iptables CONNMARK operation.

    ``--save-mark`` copies the packet mark onto the connection and
    ``--restore-mark`` copies it back; nftables says the same thing by
    assigning one to the other (netfilter
    ``extensions/libxt_CONNMARK.txlate``).
    """
    arg = connmark_arg.strip()
    if arg == '--save-mark':
        return 'ct mark set mark'
    if arg == '--restore-mark':
        return 'meta mark set ct mark'
    return ''


def print_priority_set(classify_str: str) -> str:
    """Return the nftables statement for an iptables ``--set-class major:minor``.

    nftables takes the same ``major:minor`` handle and names the two
    extremes: ``0:0`` is ``none`` and ``ffff:ffff`` is ``root`` (netfilter
    ``extensions/libxt_CLASSIFY.txlate``).
    """
    handle = classify_str.strip()
    major, sep, minor = handle.partition(':')
    if not sep:
        return f'meta priority set {handle}'
    try:
        major_val = int(major, 16)
        minor_val = int(minor, 16)
    except ValueError:
        return f'meta priority set {handle}'
    if major_val == 0 and minor_val == 0:
        return 'meta priority set none'
    if major_val == 0xFFFF and minor_val == 0xFFFF:
        return 'meta priority set root'
    return f'meta priority set {handle}'


def print_pair_clause(
    ip_keyword: str,
    ether_keyword: str,
    pairs: list[tuple[str, str]],
    neg: str,
) -> str:
    """Return the match for MAC/address pairs that belong together.

    An object that names both is matched on both at once.  A single pair
    is two matches side by side; several pairs need a set over the
    concatenation of the two headers, because two plain sets would match
    every combination of the addresses instead of the pairs the
    administrator configured.

    Shared with the NAT printer: it renders the same objects, and letting
    the two drift is how a NAT rule ends up translating for a host the
    policy would not have accepted.
    """
    pairs = list(dict.fromkeys(pairs))
    if len(pairs) == 1:
        mac, addr = pairs[0]
        return f'{ether_keyword} {neg}{mac} {ip_keyword} {neg}{addr}'
    elements = ', '.join(f'{mac} . {addr}' for mac, addr in pairs)
    return f'{ether_keyword} . {ip_keyword} {neg}{{ {elements} }}'


def print_mark_match(tag_code: str, negated: bool) -> str:
    """Return the nftables match for an iptables ``--mark value[/mask]``.

    A bare value compares directly (``meta mark 0x1``).  A masked value
    has to be spelled out as a bitwise test, because nftables reads the
    slash of ``meta mark 0x1/0xff`` as a prefix length and rejects it.
    The bitwise form is what ``iptables-translate`` produces for the same
    match (netfilter ``extensions/libxt_mark.txlate``).
    """
    op = '!=' if negated else '=='
    value, sep, mask = tag_code.partition('/')
    value = value.strip()
    if not sep:
        return f'meta mark {"!= " if negated else ""}{value}'
    return f'meta mark and {mask.strip()} {op} {value}'


# Every reject type iptables accepts after `--reject-with`, mapped to the
# code name nftables uses for the same ICMP message.  The iptables names are
# the primary spellings and the aliases of `reject_table` (netfilter
# extensions/libipt_REJECT.c and libip6t_REJECT.c); the nftables names are
# `icmp_code_tbl` and `icmpv6_code_tbl` (netfilter nftables
# src/datatype.c), which is also what `iptables-translate` produces
# (extensions/libipt_REJECT.txlate, libip6t_REJECT.txlate).  IPv6 has six
# codes and no equivalent of the IPv4 net/host/protocol distinction, so
# those three collapse onto addr-unreachable and port-unreachable the way
# the kernel does.
_REJECT_CODE_IPV4 = {
    'admin-prohib': 'admin-prohibited',
    'host-prohib': 'host-prohibited',
    'host-unreach': 'host-unreachable',
    'icmp-admin-prohibited': 'admin-prohibited',
    'icmp-host-prohibited': 'host-prohibited',
    'icmp-host-unreachable': 'host-unreachable',
    'icmp-net-prohibited': 'net-prohibited',
    'icmp-net-unreachable': 'net-unreachable',
    'icmp-port-unreachable': 'port-unreachable',
    'icmp-proto-unreachable': 'prot-unreachable',
    'net-prohib': 'net-prohibited',
    'net-unreach': 'net-unreachable',
    'port-unreach': 'port-unreachable',
    'proto-unreach': 'prot-unreachable',
}
_REJECT_CODE_IPV6 = {
    'addr-unreach': 'addr-unreachable',
    'adm-prohibited': 'admin-prohibited',
    'icmp6-addr-unreachable': 'addr-unreachable',
    'icmp6-adm-prohibited': 'admin-prohibited',
    'icmp6-no-route': 'no-route',
    'icmp6-policy-fail': 'policy-fail',
    'icmp6-port-unreachable': 'port-unreachable',
    'icmp6-reject-route': 'reject-route',
    'no-route': 'no-route',
    'policy-fail': 'policy-fail',
    'port-unreach': 'port-unreachable',
    'reject-route': 'reject-route',
}

# The payload-match keywords that tell nftables which address family a rule
# belongs to.  Only these carry a family dependency into an `inet` table
# (netfilter nftables src/proto.c); see PrintRule_nft._needs_family_qualifier.
_FAMILY_ANCHORING_KEYWORDS = frozenset({'icmp', 'icmpv6', 'ip', 'ip6'})

# ICMP and ICMPv6 type numbers mapped to the keywords nftables accepts
# (netfilter nftables src/proto.c, icmp_type_tbl / icmpv6_type_tbl).
_ICMP_TYPE_NAMES = {
    0: 'echo-reply',
    3: 'destination-unreachable',
    4: 'source-quench',
    5: 'redirect',
    8: 'echo-request',
    9: 'router-advertisement',
    10: 'router-solicitation',
    11: 'time-exceeded',
    12: 'parameter-problem',
    13: 'timestamp-request',
    14: 'timestamp-reply',
    15: 'info-request',
    16: 'info-reply',
    17: 'address-mask-request',
    18: 'address-mask-reply',
}

_ICMPV6_TYPE_NAMES = {
    1: 'destination-unreachable',
    2: 'packet-too-big',
    3: 'time-exceeded',
    4: 'parameter-problem',
    128: 'echo-request',
    129: 'echo-reply',
    130: 'mld-listener-query',
    131: 'mld-listener-report',
    132: 'mld-listener-done',
    133: 'nd-router-solicit',
    134: 'nd-router-advert',
    135: 'nd-neighbor-solicit',
    136: 'nd-neighbor-advert',
    137: 'nd-redirect',
    138: 'router-renumbering',
    141: 'ind-neighbor-solicit',
    142: 'ind-neighbor-advert',
    143: 'mld2-listener-report',
}


def print_icmp_service(srv, ipv6: bool, negated: bool = False) -> str:
    """Return the nftables match for an ICMP / ICMPv6 service.

    A service that names no type matches the protocol as a whole; one
    that names a type and a code matches both, the way iptables'
    ``--icmp-type type/code`` does.
    """
    codes = getattr(srv, 'codes', None) or srv.data or {}
    raw_type = codes.get('type', -1)
    raw_code = codes.get('code', -1)
    icmp_type = -1 if raw_type is None else int(raw_type)
    icmp_code = -1 if raw_code is None else int(raw_code)

    proto = 'icmpv6' if ipv6 else 'icmp'
    type_names = _ICMPV6_TYPE_NAMES if ipv6 else _ICMP_TYPE_NAMES
    type_str = type_names.get(icmp_type, str(icmp_type))
    op = '!= ' if negated else ''

    if icmp_type < 0:
        # `meta l4proto` resolves its argument through getprotobyname(),
        # so it needs the /etc/protocols name `ipv6-icmp` (58); the bare
        # `icmpv6` keyword only exists as the payload-match protocol below.
        l4proto = 'ipv6-icmp' if ipv6 else 'icmp'
        return f'meta l4proto {op}{l4proto}'
    if icmp_code < 0:
        return f'{proto} type {op}{type_str}'
    if negated:
        # iptables negates the type/code pair as a whole. Negating both
        # halves separately would mean something else, so match the
        # concatenation of the two fields against a one-element set.
        return f'{proto} type . {proto} code != {{ {type_str} . {icmp_code} }}'
    return f'{proto} type {type_str} {proto} code {icmp_code}'


def indent_comment_block(block: str) -> str:
    """Put a block of ready-made comment lines into a chain block.

    ``get_errors_for_rule`` already prefixes every message with the comment
    marker, so only the indent is missing - and it is missing on every line
    but the first, because a rule with more than one message comes back as
    one string with newlines in it.  Adding the marker again here is what
    produced the "# #" every reported rule used to carry.
    """
    return ''.join(f'        {line}\n' for line in block.splitlines())


def tcp_flags_match_nft(srv, negated: bool = False) -> str:
    """Format TCP flag inspection for nftables.

    The service decides which flags go into the MASK and which into the
    COMP (``TCPService.tcp_flag_match``), so both back ends match the same
    packets.  nftables writes ``tcp flags <value> / <mask>`` with the value
    before the slash and the mask after, the reverse order of iptables'
    ``--tcp-flags MASK COMP`` (see nftables doc/data-types.txt and
    tests/py/inet/tcp.t).

    Shared with the NAT print rule: a NAT rule whose service names a flag
    combination translates every TCP packet without it.
    """
    mask_names, comp_names = srv.tcp_flag_match()
    if not mask_names:
        return ''
    mask_pipe = ' | '.join(mask_names)
    if negated:
        comp_pipe = ' | '.join(comp_names) if comp_names else '0x0'
        return f'tcp flags & ({mask_pipe}) != {comp_pipe}'
    if not comp_names:
        # COMP is empty (iptables "NONE"): none of the inspected flags set.
        return f'tcp flags & ({mask_pipe}) == 0x0'
    if len(mask_names) == 1:
        # nft rejects the `tcp flags <value> / <mask>` form when the mask
        # is a single symbolic flag (e.g. `tcp flags syn / syn`, which
        # iptables-translate itself emits for `--tcp-flags SYN SYN`).
        # Emit the always-valid bitwise form instead; COMP is a subset of
        # the single-flag MASK, so it is that same flag.
        comp_pipe = ' | '.join(comp_names)
        return f'tcp flags & ({mask_pipe}) == {comp_pipe}'
    return f'tcp flags {",".join(comp_names)} / {",".join(mask_names)}'


# The last second a signed 32-bit time stamp can name, 2038-01-19 03:14:07
# UTC.  iptables-translate fills it in for a rule that names only a start
# date, because `meta time` is one range and cannot be half open
# (netfilter extensions/libxt_time.txlate).
_LAST_SIGNED_32BIT_SECOND = 2147483647


class PrintRule_nft(PolicyRuleProcessor):
    """Generates nftables rule statements from compiled policy rules.

    This is the final processor in the policy pipeline that converts
    the internal CompRule representation to nft rule syntax.
    """

    def __init__(self, name: str = 'generate nftables rules') -> None:
        super().__init__(name)
        # Track per-chain: rules go to separate chain blocks, so label
        # dedup must be independent per chain.
        self._chain_labels: dict[str, str] = {}
        self.reported_long_ifaces: set[str] = set()

    def initialize(self) -> None:
        """Initialize after compiler context is set."""
        pass

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        chain = rule.ipt_chain or 'forward'

        # Build the rule first: one the compiler cannot express comes back
        # empty, and then not even its label belongs in the ruleset.
        cmd = self._build_rule(rule)
        if not cmd:
            return True

        label_str = self._print_rule_label(rule, chain)

        text = ''
        if label_str:
            text += label_str
        text += cmd

        # Write to per-chain collection if available (nftables),
        # otherwise to the output stream (fallback).
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        if hasattr(nft_comp, 'chain_rules') and chain in nft_comp.chain_rules:
            nft_comp.chain_rules[chain].append(text)
        else:
            nft_comp.output.write(text)
        return True

    def policy_rule_to_string(self, rule: CompRule) -> str:
        """Generate rule string for dedup."""
        return self._build_rule(rule)

    def _build_rule(self, rule: CompRule) -> str:
        """Build the nftables text of one compiled rule.

        Normally one line. A logged rule of a firewall that rate-limits its
        log messages needs two, because the limit applies to the log message
        and not to the traffic: one rate-limited log rule and one rule that
        carries the verdict, the same pair the iptables compiler emits.

        A rule that carries a rate limit of its own is the exception, and it
        stays on one line.  nftables has no temporary chain to hang the
        shared match on, so both lines would carry the connection limit or
        the meter - and both are stateful: a packet crossing the log line
        and then the verdict line is counted twice, so half the traffic the
        rule is meant to stop passes it.  iptables does not have the problem
        because the match sits on the rule that jumps into the pair's chain
        and is evaluated once.
        """
        # The second rule of a negated service element says nothing about
        # the rule the first has not already said, so the message block
        # stays on the first one - the same answer the log split below
        # gives for its own pair of lines.
        with_errors = not rule.get_option(OTHER_PROTOCOLS_OPTION, None)
        if self._splits_for_log(rule):
            log_rule = rule.clone()
            log_rule.ipt_target = 'LOG'
            action_rule = rule.clone()
            action_rule.nft_log = False
            return self._build_rule_line(
                log_rule, with_errors=False
            ) + self._build_rule_line(action_rule, with_errors=with_errors)
        return self._build_rule_line(rule, with_errors=with_errors)

    def _splits_for_log(self, rule: CompRule) -> bool:
        """Return whether this rule becomes a log line and a verdict line."""
        if not rule.nft_log or self._firewall_log_limit() <= 0:
            return False
        if not self._keeps_a_rate(rule):
            return True
        self.compiler.warning(
            rule,
            'the rule keeps its own rate limit, so its log messages are '
            'limited by that and not by the log rate of the firewall; '
            'splitting the rule would count the limit twice and let half the '
            'traffic through',
        )
        return False

    @staticmethod
    def _keeps_a_rate(rule: CompRule) -> bool:
        """Return whether the rule carries a stateful rate limit of its own.

        A connection limit and a rate limit kept per source both hold state
        that one evaluation consumes, unlike the plain ``limit rate``, whose
        two halves of a split rule are two different limits anyway (the
        firewall's for the log line, the rule's for the verdict line).
        """
        for key in ('connlimit_value', 'hashlimit_value'):
            try:
                if int(rule.get_option(key, 0) or 0) > 0:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _firewall_log_limit(self) -> int:
        """Return the log rate limit configured in the firewall settings."""
        try:
            return int(self.compiler.fw.get_option('limit_value'))
        except (TypeError, ValueError):
            return 0

    def _build_rule_line(self, rule: CompRule, with_errors: bool = True) -> str:
        """Build a complete nftables rule line.

        nft rule format:
            [ip|ip6] [saddr <addr>] [daddr <addr>] [<proto> [sport/dport]] \
            [ct state new] [counter] [log ...] [<verdict>]
        """
        parts: list[str] = []

        # Protocol and service
        srv = rule.srv[0] if rule.srv and not rule.is_srv_any() else None

        # Address family prefix for matching
        af_prefix = self._get_af_prefix(rule, srv)

        # Interface matching
        iface_match = self._print_interface(rule)
        if iface_match is None:
            # The reason was reported. Emitting the rule without the match
            # would apply it to every interface.
            return ''
        if iface_match:
            parts.append(iface_match)

        # Source address
        src_match = self._print_src_addr(rule, af_prefix)
        if src_match is None:
            # None of the source objects could be rendered and the reason was
            # reported. Emitting the rule without the match would apply it to
            # every source address, which is the opposite of what it says.
            return ''
        if src_match:
            parts.append(src_match)

        # Destination address
        dst_match = self._print_dst_addr(rule, af_prefix)
        if dst_match is None:
            return ''
        if dst_match:
            parts.append(dst_match)

        # Protocol + service matching
        srv_match = self._print_service(rule, srv)
        if srv_match is None:
            # The service cannot be expressed and the reason was reported.
            # Emitting the rule without the match would apply it to every
            # protocol and port, the opposite of what it says.
            return ''
        if srv_match:
            parts.append(srv_match)

        # State matching
        state_match = self._print_state(rule)
        if state_match:
            parts.append(state_match)

        # Time matching
        time_match = self._print_time_interval(rule)
        if time_match is None:
            # A negated time nftables cannot invert; the reason was reported.
            # Emitting the rule without the match would make it apply at all
            # times, the opposite of what it says.
            return ''
        if time_match:
            parts.append(time_match)

        # Rate limiting (-m limit on iptables -> native `limit rate` on nftables)
        limit_match = self._print_limit(rule)
        if limit_match is None:
            # The rate cannot be expressed and the reason was reported.
            # Emitting the rule without it turns "drop above 20 per second"
            # into "drop".
            return ''
        if limit_match:
            parts.append(limit_match)

        connlimit_match = self._print_connlimit(rule)
        if connlimit_match is None:
            # The limit cannot be expressed and the reason was reported.
            # Emitting the rule without it would enforce a different limit
            # than the one the rule carries, without saying so.
            return ''
        if connlimit_match:
            parts.append(connlimit_match)

        hashlimit_match = self._print_hashlimit(rule)
        if hashlimit_match is None:
            # Same again for the limit kept per source, destination or port.
            return ''
        if hashlimit_match:
            parts.append(hashlimit_match)

        # Everything collected so far matches on the packet; what follows
        # only acts on it.  The address family has to be pinned down here,
        # while `parts` still holds the match half and nothing else.
        if self._needs_family_qualifier(parts):
            family = 'ipv6' if self.compiler.ipv6_policy else 'ipv4'
            parts.insert(0, f'meta nfproto {family}')

        # Logging, mangle statements and verdict
        log_match = self._print_log(rule)
        mangle_stmt = self._print_mangle_statement(rule)
        if mangle_stmt is None:
            # The mark, the traffic class or the connection mark cannot be
            # written and the reason was reported.  Without its statement
            # the rule lets the packet through unchanged, so everything
            # keyed on that mark stops working without saying so.
            return ''
        verdict = self._print_verdict(rule)
        if verdict is None:
            # The verdict cannot be built and the reason was reported.
            # Emitting the rule without one leaves a packet counter that
            # carries out none of the action the rule names.
            return ''

        # Counter: every iptables rule keeps implicit packet/byte counters, so
        # emit `counter` here (before any log or verdict, the order
        # iptables-translate uses) to give the nftables ruleset the same
        # visible hit counts. Skip it only for an otherwise empty rule.
        # An accounting rule counts into a named counter instead, so its
        # totals survive a reload and can be read back by name.
        counter_name = rule.get_option('nft_counter_name', '')
        if parts or log_match or mangle_stmt or verdict or counter_name:
            if counter_name:
                parts.append(f'counter name "{counter_name}"')
            else:
                parts.append('counter')

        if log_match:
            parts.append(log_match)

        if mangle_stmt:
            parts.append(mangle_stmt)

        if verdict:
            parts.append(verdict)

        if not parts:
            return ''

        line = '        ' + ' '.join(parts) + '\n'

        # Add error comments inline
        # get_errors_for_rule prefixes every message with the comment
        # marker already, so only the indent of the chain block is added -
        # to each line, because a rule with more than one message left all
        # but the first at column zero.
        errors = self.compiler.get_errors_for_rule(rule) if with_errors else ''
        if errors:
            line = indent_comment_block(errors) + line

        return line

    def _needs_family_qualifier(self, match_parts: list[str]) -> bool:
        """Say whether the rule has to name its address family itself.

        A dual-stack firewall gets a single ``inet`` filter table holding
        the rules of both compilation passes.  nftables ties a rule to one
        family only through an ``ip``, ``ip6``, ``icmp`` or ``icmpv6``
        payload expression (netfilter nftables ``src/proto.c``); ``meta``,
        ``ct``, ``th``, ``tcp``, ``udp`` and the interface matches say
        nothing about it.  A rule matching only ports, connection state,
        interfaces, marks or time therefore applies to both families, so an
        IPv4-only rule acts on IPv6 traffic and the other way round.
        Prefixing it with ``meta nfproto`` puts it back where it belongs.

        A table of a single family needs no qualifier: everything reaching
        an ``ip`` table is IPv4 already.
        """
        if not self.compiler.shared_inet_table:
            return False
        # Only the *leading* keyword of a clause decides this, because only
        # a payload expression carries a family.  Reading any token would
        # take `meta l4proto icmp` - which an ICMP service without a type
        # renders to - for an `icmp` payload match, and that clause is
        # family neutral: it matches an IPv6 packet whose last next-header
        # is 1 just as happily (netfilter nftables src/meta.c).
        return not any(
            part.split()[0] in _FAMILY_ANCHORING_KEYWORDS
            for part in match_parts
            if part.split()
        )

    def _get_af_prefix(self, rule: CompRule, srv) -> str:
        """Get the address family prefix (ip/ip6) for matching."""
        if self.compiler.ipv6_policy:
            return 'ip6'
        return 'ip'

    def _print_rule_label(self, rule: CompRule, chain: str = '') -> str:
        """Print rule label as nft comment.

        Tracks labels per chain since nftables rules are written to
        separate chain blocks (unlike iptables where -A CHAIN is inline).
        """
        label = rule.label
        current = self._chain_labels.get(chain, '')
        if not label or label == current:
            if label:
                self._chain_labels[chain] = label
            return ''

        res = []
        if not self.compiler.single_rule_compile_mode:
            res.append('        # ')
            res.append(f'        # Rule {label}')
            res.append('        # ')

        comment = rule.comment
        if comment:
            for line in comment.split('\n'):
                if line:
                    res.append(f'        # {line}')

        self._chain_labels[chain] = label
        if res:
            return '\n'.join(res) + '\n'
        return ''

    def _print_interface(self, rule: CompRule) -> str | None:
        """Print interface matching: iifname/oifname.

        Returns ``None`` when the interface cannot be matched at all, so the
        caller leaves the rule out instead of widening it.
        """
        if rule.iface_label == 'nil':
            return ''

        direction = rule.direction
        if direction not in (Direction.Inbound, Direction.Outbound):
            return ''

        inbound = direction == Direction.Inbound

        if rule.is_itf_any():
            return ''

        if rule.itf and rule.itf[0] is ANY_INTERFACE:
            # "Every interface of this firewall", the counterpart of the
            # iptables `-i +`.  `iifname "*"` is not the way to say it -
            # nftables answers that with "All-wildcard strings are not
            # supported" and refuses the whole ruleset - but `meta iif` is
            # 0 exactly when the packet has no incoming device
            # (``nft_meta_store_ifindex``, netfilter
            # linux/net/netfilter/nft_meta.c), so `!= 0` asks the same
            # question.
            #
            # Only where the chain does not answer it already, which is
            # narrower than on iptables: a packet in the input, forward and
            # prerouting hooks always has an incoming device and one in the
            # output, forward and postrouting hooks always has an outgoing
            # one, so the match decides nothing there.  What is left is a
            # rule about incoming traffic in postrouting - where a locally
            # generated packet has no incoming device - and a branch chain,
            # which is reached from several hooks at once.  The iptables
            # compiler writes `-i +` in all of them because fwbuilder does;
            # repeating that here would put a match that decides nothing
            # into 85 rules of the test corpus.
            answered_by_the_hook = (
                ('input', 'forward', 'prerouting')
                if inbound
                else ('output', 'forward', 'postrouting')
            )
            if rule.ipt_chain in answered_by_the_hook:
                return ''
            return 'meta iif != 0' if inbound else 'meta oif != 0'

        ifaces = [obj for obj in rule.itf if isinstance(obj, Interface) and obj.name]
        if not ifaces:
            return ''

        for iface in ifaces:
            if iface.is_bridge_port():
                # A bridged packet reaches the ip/inet hooks with the bridge
                # device as its in/out device, not the port it came in on.
                # iptables reads the port from the bridge layer with
                # `-m physdev`; nftables only exposes it as `meta ibrname` /
                # `meta obrname`, which the kernel registers for the bridge
                # family alone (net/bridge/netfilter/nft_meta_bridge.c) and
                # refuses in an ip or inet table.  Matching the parent bridge
                # instead would widen the rule to every port of that bridge,
                # so leave it out.
                self.compiler.error(
                    rule,
                    f'Rule matches on the bridge port "{iface.name}", which '
                    'nftables cannot see in a filter table; the rule is left '
                    'out',
                )
                return None

        neg = '!= ' if rule.itf_single_object_negation else ''
        # A negated element covers all of its interfaces at once; without
        # negation the rule is atomic by then and carries exactly one.
        names = [obj.name for obj in ifaces] if neg else [ifaces[0].name]
        for name in names:
            if not check_interface_name(self.compiler, name, self.reported_long_ifaces):
                return None

        # nftables uses iifname/oifname for wildcard matching
        # and iif/oif for exact interface matching.
        # Use iif/oif for loopback — index-based is faster and safe
        # (loopback is always present with a stable index).  A set of several
        # interfaces goes through the name matcher.
        is_loopback = len(names) == 1 and ifaces[0].is_loopback()
        value = _as_iface_set(names)

        if inbound:
            keyword = 'iif' if is_loopback else 'iifname'
        else:
            keyword = 'oif' if is_loopback else 'oifname'
        return f'{keyword} {neg}{value}'

    def _print_src_addr(self, rule: CompRule, af_prefix: str) -> str | None:
        """Print source address matching, None when nothing could be rendered."""
        if rule.is_src_any():
            return ''

        if not rule.src:
            return ''

        neg = '!= ' if rule.src_single_object_negation else ''
        return self._print_addr_match(rule, rule.src, f'{af_prefix} saddr', neg)

    def _print_dst_addr(self, rule: CompRule, af_prefix: str) -> str | None:
        """Print destination address matching, None when nothing was rendered."""
        if rule.is_dst_any():
            return ''

        if not rule.dst:
            return ''

        neg = '!= ' if rule.dst_single_object_negation else ''
        return self._print_addr_match(rule, rule.dst, f'{af_prefix} daddr', neg)

    def _print_addr_match(
        self, rule: CompRule, objects: list, keyword: str, neg: str
    ) -> str | None:
        """Render an address match, keeping MAC addresses apart.

        A MAC address is not part of the IP header, so it needs its own
        ``ether saddr`` / ``ether daddr`` match. This is what
        iptables-translate produces for ``-m mac --mac-source``.

        An object that carries both asks for both at once, so the two go
        into one clause: a single pair as two matches side by side, several
        pairs as a set over the concatenation of the two headers, because
        two plain sets would match every combination of the addresses
        instead of the pairs that were configured.
        """
        direction = keyword.rsplit(' ', 1)[1]
        macs = []
        addrs = []
        pairs = []
        for obj in objects:
            if isinstance(obj, CombinedAddress) and obj.has_phys_address():
                addr = self._print_addr(obj.address, rule)
                if addr:
                    pairs.append((normalize_mac_address(obj.get_phys_address()), addr))
                    continue
            mac = normalize_mac_address(get_mac_only_address(obj))
            if mac:
                macs.append(mac)
                continue
            addr = self._print_addr(obj, rule)
            if addr:
                addrs.append(addr)
        parts = []
        if pairs:
            parts.append(self._pair_clause(keyword, direction, pairs, neg))
        if macs:
            parts.append(self._match_clause(f'ether {direction}', macs, neg))
        parts.extend(self._address_clauses(rule, keyword, addrs, neg))
        if not parts:
            what = 'source' if direction == 'saddr' else 'destination'
            self.compiler.error(rule, f'Could not resolve any {what} addresses')
            return None
        return ' '.join(parts)

    def _address_clauses(
        self, rule: CompRule, keyword: str, addrs: list[str], neg: str
    ) -> list[str]:
        """Split the rendered addresses into the clauses one rule can carry.

        A reference to a named set cannot be an element of the anonymous set
        the other addresses are merged into, so it needs a clause of its
        own.  Several clauses in one rule are ANDed, which is what a negated
        element means ("none of these"); a positive element means "any of
        these" and has to become one rule per clause, which
        ``ProcessMultiAddressObjectsInRE`` takes care of before this point.
        """
        if not addrs:
            return []
        # Two objects can render to the same set: a dynamic interface named
        # in the rule and the same interface reached through the host it
        # belongs to both become "@i_<name>".  Repeating the clause would
        # test it twice for no reason.
        set_refs = list(dict.fromkeys(a for a in addrs if a.startswith('@')))
        plain = [a for a in addrs if not a.startswith('@')]
        if not set_refs:
            return [self._match_clause(keyword, plain, neg)]
        if not neg and (plain or len(set_refs) > 1):
            # Every clause of one rule has to hold at the same time, which
            # is what a negated element asks for.  A positive element asks
            # for any one of its objects, so it needs a rule per clause -
            # ProcessMultiAddressObjectsInRE splits an address table and a
            # DNS name out for that reason, but not a dynamic interface,
            # which renders as a set reference just the same.  Emitting the
            # clauses side by side asks for a packet whose address is in
            # two sets at once, which no packet is.
            self.compiler.error(
                rule,
                'An address table, a DNS name or a dynamic interface cannot '
                'be combined with another address on the same side of one '
                'nftables rule; the rule is left out',
            )
            return []
        clauses = [f'{keyword} {neg}{ref}' for ref in set_refs]
        if plain:
            clauses.append(self._match_clause(keyword, plain, neg))
        return clauses

    @staticmethod
    def _match_clause(keyword: str, values: list[str], neg: str) -> str:
        if len(values) == 1:
            return f'{keyword} {neg}{values[0]}'
        return f'{keyword} {neg}{{ {", ".join(values)} }}'

    @staticmethod
    def _pair_clause(
        keyword: str, direction: str, pairs: list[tuple[str, str]], neg: str
    ) -> str:
        return print_pair_clause(keyword, f'ether {direction}', pairs, neg)

    def _print_addr(self, obj, rule: CompRule) -> str:
        """Print an address object in nftables format."""
        if is_run_time_address_table(obj):
            # The addresses live in a file on the firewall, so the rule
            # points at a named set and the script fills that set in at
            # activation time (netfilter nftables doc/sets.txt).  A set is
            # typed, so the two address families need one set each.
            ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
            name = nft_set_reference_name(obj, ipv6)
            self.compiler.address_tables[name] = (
                get_address_table_source(obj, self.compiler.fw),
                ipv6,
                'file',
            )
            return f'@{name}'

        if isinstance(obj, DNSName):
            # A name is resolved on the firewall, and nft refuses a hostname
            # that resolves to more than one address - it rejects the whole
            # ruleset, not just the rule (netfilter nftables
            # src/datatype.c:647).  So the rule points at a set and the
            # script resolves the name into it after the ruleset is loaded,
            # which is what iptables does when it expands the name into one
            # rule per address.
            ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
            name = nft_set_reference_name(obj, ipv6)
            self.compiler.address_tables[name] = (
                (obj.data or {}).get('dnsrec') or obj.name,
                ipv6,
                'host',
            )
            return f'@{name}'

        if isinstance(obj, AddressRange):
            start = obj.get_start_address()
            end = obj.get_end_address()
            if start and end:
                if start == end:
                    return start
                # Prefer the short CIDR form when the range happens to
                # cover an exact CIDR block.
                cidr = range_to_cidr(start, end)
                if cidr:
                    return cidr
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            if obj.is_dynamic():
                # The address is only known on the firewall, so the rule
                # points at a named set that the script fills from the
                # running interface after the ruleset is loaded.  A wildcard
                # name such as "ppp*" collects the addresses of every
                # interface it matches into the same set.
                ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
                name = nft_set_reference_name(obj, ipv6)
                self.compiler.address_tables[name] = (obj.name, ipv6, 'interface')
                return f'@{name}'
            addr = self._select_af_address(getattr(obj, 'addresses', []))
            if addr is not None:
                return self._print_addr_basic(addr, rule)
            self.compiler.error(rule, f'Interface "{obj.name}" has no addresses')
            return ''

        if isinstance(obj, Host):
            host_addrs = [
                addr
                for iface in getattr(obj, 'interfaces', [])
                if not iface.is_loopback()
                for addr in getattr(iface, 'addresses', [])
                if addr.get_address()
            ]
            addr = self._select_af_address(host_addrs)
            if addr is not None:
                return addr.get_address()
            self.compiler.error(rule, f'Host "{obj.name}" has no addresses')
            return ''

        return self._print_addr_basic(obj, rule)

    def _select_af_address(self, addresses):
        """Pick the address matching the active family from a list.

        A dual-stack Interface / Host holds both an IPv4 and an IPv6
        address; rendering the first one blindly emits the wrong family in
        one of the two passes. Prefer the address of the compile target's
        family and only fall back to the first entry when none matches (so
        single-stack objects that survived the address-family filter still
        render).
        """
        # A MAC address is not an IP address of either family and must
        # never be picked as one; it is matched separately.
        addresses = [a for a in addresses if not isinstance(a, PhysAddress)]
        if not addresses:
            return None
        want_v6 = self.compiler.ipv6_policy
        for addr in addresses:
            if want_v6 and addr.is_v6():
                return addr
            if not want_v6 and addr.is_v4():
                return addr
        return addresses[0]

    def _print_addr_basic(self, obj, rule: CompRule) -> str:
        """Print basic address in CIDR notation."""
        if isinstance(obj, DNSName):
            # Runtime DNSName — use the DNS record directly as address, so nft
            # resolves it at load time. A bare hostname beginning with a digit
            # (e.g. "6bone.net") is tokenized as a number by the nft parser and
            # rejected, so quote those to force hostname interpretation.
            dnsrec = obj.get_source_name() or obj.name
            if dnsrec and dnsrec[:1].isdigit():
                return nft_quote(dnsrec)
            return dnsrec

        if not isinstance(obj, Address):
            self.compiler.error(
                rule,
                f'Cannot resolve address for object type {type(obj).__name__}',
            )
            return ''

        addr_str = obj.get_address()
        if not addr_str:
            return ''

        if isinstance(obj, (Network, NetworkIPv6)):
            mask_str = obj.get_netmask()
            if mask_str:
                # netmask_prefix_length() is the reader, not ip_network():
                # it takes every spelling a netmask reaches here in, and
                # ip_network() answers two of the three with a raise.  This
                # used to swallow that raise and print the address alone,
                # so a rule about a network came out as a rule about one
                # host, in a script that loads without a word.
                length = netmask_prefix_length(addr_str, mask_str)
                # A host mask says nothing and is left out, the way
                # fwbuilder's InetAddr::isHostMask() decides it: what
                # counts as one depends on the address family.  Testing
                # against 32 alone would strip the prefix off an IPv6
                # /32 -- the size of a provider allocation -- and turn
                # the match into a single host.
                if length is not None and length != max_prefix_length(addr_str):
                    return f'{addr_str}/{length}'

        return addr_str

    def _print_service(self, rule: CompRule, srv) -> str | None:
        """Print protocol + port/ICMP matching.

        Returns ``None`` when the service says something nftables cannot
        express.  The caller then leaves the whole rule out: emitting it
        without the match would apply it to every protocol and port, so a
        rule meant for one service would act on all traffic.  The reason is
        reported before returning.
        """
        negated = bool(rule.srv_single_object_negation)

        others = rule.get_option(OTHER_PROTOCOLS_OPTION, None)
        if others:
            # The second half of a negated service element: every protocol
            # the element does not name.  See
            # `AddOtherProtocolsForNegatedService`.
            if len(others) == 1:
                return f'meta l4proto != {others[0]}'
            return f'meta l4proto != {{ {", ".join(others)} }}'

        if rule.merged_tcp_udp:
            return self._print_merged_tcp_udp_service(rule, negated)

        if srv is None:
            return ''

        if isinstance(srv, TCPService):
            return self._print_tcp_udp_service(rule, srv, 'tcp')
        elif isinstance(srv, UDPService):
            return self._print_tcp_udp_service(rule, srv, 'udp')
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            return self._print_icmp_service(srv, negated)
        elif isinstance(srv, IPService):
            parts = []
            proto = srv.get_protocol_number()
            # Protocol number 0 is iptables' "all" wildcard, not a protocol
            # (see the "all" entry of xtables_chain_protos in the netfilter
            # source, libxtables/xtables.c), so it must not become a match.
            # nftables reads `meta l4proto 0` literally as IP protocol 0 and
            # then matches nothing.
            if proto > 0:
                parts.append(f'meta l4proto {proto}')
            data = srv.data or {}
            tos = data.get('tos', '')
            dscp = data.get('dscp', '')
            af = 'ip6' if self.compiler.ipv6_policy else 'ip'
            # A condition of the service that cannot be rendered widens the
            # rule to traffic the user did not name, so the rule is dropped.
            unrenderable = False
            if _is_true(data.get('fragm')) or _is_true(data.get('short_fragm')):
                parts.append(print_fragment_match(self.compiler.ipv6_policy))
            # An IP service can hold a ToS byte and a DiffServ code point at
            # once, and only one of them can become a match. The ToS byte
            # wins, because that is the order the iptables print rule and
            # fwbuilder use (PolicyCompiler_PrintRule.cpp:953: `if
            # (!tos.empty()) ... else if (!dscp.empty())`). Deciding it the
            # other way round here meant the same service matched the ToS
            # byte on one platform and the DiffServ field on the other.
            if tos:
                # nftables has no ToS-byte matcher: the IPv4 ToS field was
                # split into dscp + ecn, so iptables' `-m tos --tos` has no
                # nftables equivalent. Fail loudly instead of emitting an
                # `ip tos` expression that nft rejects.
                self.compiler.error(
                    rule,
                    'IP service with a ToS value is not supported by nftables; '
                    'use a DSCP value instead',
                )
                unrenderable = True
            elif dscp:
                if not is_valid_dscp(dscp):
                    # An unknown DiffServ class (e.g. "AF4") is rejected by
                    # nftables; report it instead of emitting a rule that
                    # fails to load.
                    self.compiler.error(
                        rule,
                        f'IP service has an invalid DSCP value "{dscp}"; '
                        'use a DiffServ class (for example af41) or a numeric '
                        'code point',
                    )
                    unrenderable = True
                else:
                    # nftables' dscp symbols (cs0, af11, be, ef, ...) are
                    # lowercase and resolved case-sensitively; the DiffServ
                    # class names fwbuilder stores are uppercase (BE, CS0,
                    # AF11). Numeric values (0x20) are unaffected by lower().
                    parts.append(f'{af} dscp {dscp.lower()}')
            if not self.compiler.ipv6_policy:
                # IP options are an IPv4 header feature; the iptables compiler
                # also emits `-m ipv4options` for IPv4 policies only.
                opt_matches, opt_unsupported = print_ip_option_matches(data)
                parts.extend(opt_matches)
                for name in opt_unsupported:
                    self.compiler.error(
                        rule,
                        f'IP service matching the "{name}" IP option is not '
                        'supported by nftables, which can only match the '
                        'lsrr, ssrr, rr and router-alert options',
                    )
                    unrenderable = True
            elif has_ip_options(data):
                self.compiler.error(
                    rule,
                    'IP service matching an IPv4 header option cannot be '
                    'compiled for IPv6, which has no such field; the rule is '
                    'left out of the IPv6 ruleset',
                )
                unrenderable = True
            if unrenderable:
                return None
            if negated:
                return self._negate_single_match(rule, parts, 'IP service')
            # An "any IP" service with no further conditions carries no match
            # at all, which is correct: the rule applies to every protocol.
            return ' '.join(parts)
        elif isinstance(srv, CustomService):
            nft_comp = cast('PolicyCompiler_nft', self.compiler)
            code = (srv.codes or {}).get(nft_comp.my_platform_name(), '')
            if not code:
                # VerifyCustomServices already reported the missing code.
                return None
            if negated:
                # The code fragment is opaque nftables text; there is no
                # way to invert it from here, and emitting it unchanged
                # would match exactly what the rule excludes.
                self.compiler.error(
                    rule,
                    f'Negating the custom service "{srv.name}" is not '
                    'supported by the nftables compiler; add a rule with '
                    'the inverse match instead',
                )
                return None
            return code
        elif isinstance(srv, TagService):
            tag_code = srv.get_code()
            if not tag_code:
                self.compiler.error(
                    rule, f'Tag service "{srv.name}" carries no tag to match on'
                )
                return None
            if not is_valid_packet_mark(tag_code):
                self.compiler.error(
                    rule,
                    f'Tag service "{srv.name}" carries "{tag_code}", which is '
                    'not a packet mark; it takes a number up to 4294967295, '
                    'optionally followed by a slash and a mask. The rule is '
                    'left out',
                )
                return None
            return print_mark_match(tag_code, bool(rule.srv_single_object_negation))
        elif isinstance(srv, UserService):
            uid = srv.userid or ''
            if not uid:
                self.compiler.error(
                    rule, f'User service "{srv.name}" names no user to match on'
                )
                return None
            if not is_valid_user_id(uid):
                self.compiler.error(
                    rule,
                    f'User service "{srv.name}" names "{uid}", which is not a '
                    'user name or id; letters, digits, a dot, a dash and an '
                    'underscore are. The rule is left out',
                )
                return None
            neg = '!= ' if rule.srv_single_object_negation else ''
            return f'meta skuid {neg}{uid}'

        self.compiler.error(
            rule,
            f'Service type {type(srv).__name__} not yet supported by nftables compiler',
        )
        return None

    # Every spelling a stored log level can have, mapped to the keyword
    # nftables takes.  `level_type` (netfilter nftables src/parser_bison.y)
    # is exactly `emerg alert crit err warn notice info debug audit`, and
    # LEVEL takes that production rather than a number, so anything else -
    # `panic`, `error`, `warning`, or a numeric syslog level from an
    # imported file or the "numeric log levels" setting - is a syntax error
    # that costs the whole ruleset, not just the rule.
    #
    # The names come from the iptables printer's `_LOG_LEVEL_MAP`, which is
    # the set Firewall Builder can store, plus the numbers that map names.
    _NFT_LOG_LEVELS: ClassVar[dict[str, str]] = {
        '0': 'emerg',
        '1': 'alert',
        '2': 'crit',
        '3': 'err',
        '4': 'warn',
        '5': 'notice',
        '6': 'info',
        '7': 'debug',
        'error': 'err',
        # The historical name of LOG_EMERG, which iptables still accepts
        # and maps to 0; nftables knows only `emerg`.
        'panic': 'emerg',
        'warning': 'warn',
    }

    #: What nftables itself accepts after `level`.
    _NFT_LOG_LEVEL_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {
            'alert',
            'audit',
            'crit',
            'debug',
            'emerg',
            'err',
            'info',
            'notice',
            'warn',
        }
    )

    def _print_tcp_flags(self, srv, negated: bool = False) -> str:
        """Format TCP flag inspection for nftables."""
        return tcp_flags_match_nft(srv, negated)

    def _print_tcp_udp_service(self, rule: CompRule, srv, proto: str) -> str:
        """Print TCP/UDP service matching.

        For multiple services (multiport), nftables uses sets natively:
            tcp dport { 22, 80, 443 }
        """
        parts = []

        neg = '!= ' if rule.srv_single_object_negation else ''

        # Source ports
        src_start = srv.src_range_start or 0
        src_end = srv.src_range_end or 0
        src_ports = self._format_port_range(src_start, src_end)

        # Destination ports
        dst_start = srv.dst_range_start or 0
        dst_end = srv.dst_range_end or 0

        # Handle multiport: collect all service destination ports
        if len(rule.srv) > 1:
            all_dst_ports = []
            for s in rule.srv:
                if isinstance(s, (TCPService, UDPService)):
                    ds = s.dst_range_start or 0
                    de = s.dst_range_end or 0
                    p = self._format_port_range(ds, de)
                    if p:
                        all_dst_ports.append(p)

            if src_ports:
                parts.append(f'{proto} sport {neg}{src_ports}')

            if all_dst_ports:
                if len(all_dst_ports) == 1:
                    parts.append(f'{proto} dport {neg}{all_dst_ports[0]}')
                else:
                    parts.append(f'{proto} dport {neg}{{ {", ".join(all_dst_ports)} }}')
        else:
            dst_ports = self._format_port_range(dst_start, dst_end)

            flags = ''
            if proto == 'tcp' and isinstance(srv, TCPService):
                flags = self._print_tcp_flags(
                    srv, negated=bool(rule.srv_single_object_negation)
                )

            if src_ports:
                parts.append(f'{proto} sport {neg}{src_ports}')
            if dst_ports:
                parts.append(f'{proto} dport {neg}{dst_ports}')
            if flags:
                parts.append(flags)
            if not parts:
                # Just the protocol, no ports, no flags.  The negation
                # belongs on the protocol here: it is the only thing the
                # service says, so leaving it off turns "anything but all
                # TCP" into "all TCP".  `print_icmp_service` puts it on
                # `meta l4proto` for the same reason.
                parts.append(f'meta l4proto {neg}{proto}')

        return ' '.join(parts)

    def _print_merged_tcp_udp_service(
        self, rule: CompRule, negated: bool = False
    ) -> str:
        """Print merged TCP+UDP service using transport header (th) matcher.

        Emits: meta l4proto { tcp, udp } th dport 53
        Or:    meta l4proto { tcp, udp } th dport { 53, 80 }

        A negated element inverts the port match; the protocol stays as it is,
        because the rule is about those ports, not about TCP and UDP as such.
        """
        neg = '!= ' if negated else ''
        parts = ['meta l4proto { tcp, udp }']

        # Collect unique port ranges from all TCP/UDP services
        src_ports: list[str] = []
        dst_ports: list[str] = []
        seen_src: set[tuple[int, int]] = set()
        seen_dst: set[tuple[int, int]] = set()

        for s in rule.srv:
            if not isinstance(s, (TCPService, UDPService)):
                continue
            src_key = (s.src_range_start or 0, s.src_range_end or 0)
            dst_key = (s.dst_range_start or 0, s.dst_range_end or 0)
            if src_key not in seen_src:
                seen_src.add(src_key)
                p = self._format_port_range(src_key[0], src_key[1])
                if p:
                    src_ports.append(p)
            if dst_key not in seen_dst:
                seen_dst.add(dst_key)
                p = self._format_port_range(dst_key[0], dst_key[1])
                if p:
                    dst_ports.append(p)

        if src_ports:
            if len(src_ports) == 1:
                parts.append(f'th sport {neg}{src_ports[0]}')
            else:
                parts.append(f'th sport {neg}{{ {", ".join(src_ports)} }}')

        if dst_ports:
            if len(dst_ports) == 1:
                parts.append(f'th dport {neg}{dst_ports[0]}')
            else:
                parts.append(f'th dport {neg}{{ {", ".join(dst_ports)} }}')

        return ' '.join(parts)

    @staticmethod
    def _format_port_range(start: int, end: int) -> str:
        """Format a port range for nftables."""
        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return str(start)
        return f'{start}-{end}'

    def _negate_single_match(
        self, rule: CompRule, parts: list[str], what: str
    ) -> str | None:
        """Return *parts* with the match inverted, or ``None`` if it cannot be.

        A negated rule element means "not (all of these conditions)".  A
        single condition inverts by turning its comparison into ``!=``.  Two
        or more conditions would have to be inverted as a disjunction, which
        one nft rule cannot express.  ``None`` tells the caller to leave the
        rule out; the reason is reported first.
        """
        if not parts:
            # Nothing to match, so nothing to invert: the negation of
            # "matches everything" is "matches nothing".
            self.compiler.error(
                rule,
                f'Negating an unrestricted {what} leaves a rule that can '
                'never match; remove the rule instead',
            )
            return None
        if len(parts) > 1:
            self.compiler.error(
                rule,
                f'Negating a {what} with several conditions '
                f'({", ".join(parts)}) is not supported by the nftables '
                'compiler; split it into one service per condition',
            )
            # Writing the conditions out unchanged would match exactly the
            # traffic the rule excludes, so leave the rule out instead.
            return None
        match = parts[0]
        # Turn "<expr> <value>" into "<expr> != <value>"; comparisons that
        # already carry an operator (`>`, `& ... ==`) are inverted in place.
        if ' == ' in match:
            return match.replace(' == ', ' != ', 1)
        if ' exists' in match:
            return match.replace(' exists', ' missing', 1)
        if ' > ' in match:
            return match.replace(' > ', ' <= ', 1)
        if ' != ' in match:
            return match.replace(' != ', ' == ', 1)
        expr, _, value = match.rpartition(' ')
        return f'{expr} != {value}'

    def _print_icmp_service(self, srv, negated: bool = False) -> str:
        """Print ICMP type/code matching."""
        return print_icmp_service(srv, self.compiler.ipv6_policy, negated)

    def _print_connlimit(self, rule: CompRule) -> str | None:
        """Print the limit on concurrent connections per source.

        The nftables counterpart of ``-m connlimit --connlimit-above N
        [--connlimit-mask M]``, in the shape iptables-translate produces
        for it (netfilter extensions/libxt_connlimit.txlate):

            add @<set> { ip saddr and 255.255.255.0 ct count over 2 }

        The set is what makes the count per source rather than per rule: an
        element is created for each address the rule sees and carries that
        address's connection count.  ``over`` is the plain form and matches
        while the count is above the limit; the editor's "not" asks for the
        opposite, which the same expression says by leaving ``over`` out.

        Returns ``None`` when the limit cannot be expressed, so the caller
        can leave the rule out rather than enforce a different one.
        """
        try:
            limit = int(rule.get_option('connlimit_value', 0) or 0)
        except (TypeError, ValueError):
            return ''
        if limit <= 0:
            return ''

        ipv6 = bool(self.compiler.ipv6_policy)
        keyword = 'ip6 saddr' if ipv6 else 'ip saddr'
        key = keyword
        try:
            masklen = int(rule.get_option('connlimit_masklen', 0) or 0)
        except (TypeError, ValueError):
            masklen = 0
        full = 128 if ipv6 else 32
        if masklen > full:
            # There is no such prefix in this family, so there is no group to
            # count by.  Falling through would count per single address, i.e.
            # enforce a limit other than the one the rule carries, and say
            # nothing about it.  iptables answers the same input by leaving
            # the rule out (`a connection limit groups by at most N bits`),
            # and one policy must not mean two different limits.
            self.compiler.error(
                rule,
                f'a connection limit groups by at most {full} bits here, '
                f'not {masklen}; the rule is left out',
            )
            return None
        if 0 < masklen < full:
            mask = ipaddress.ip_network(
                f'::/{masklen}' if ipv6 else f'0.0.0.0/{masklen}'
            )
            key = f'{keyword} and {mask.netmask}'

        # One set per rule, so the counts of two rules do not mix.  The
        # rule set name is part of it because every rule set numbers its
        # rules from zero.
        rule_set = self.compiler.get_rule_set_name()
        suffix = '_v6' if ipv6 else ''
        set_name = nft_object_name(f'connlimit_{rule_set}_{rule.position}') + suffix
        self.compiler.register_dynamic_set(
            set_name, 'ipv6_addr' if ipv6 else 'ipv4_addr'
        )
        over = '' if rule.get_option('connlimit_above_not', False) else 'over '
        return f'add @{set_name} {{ {key} ct count {over}{limit} }}'

    #: What each hashlimit mode keys on, as an nftables expression.  The
    #: port halves are read out of the generic transport header rather than
    #: out of ``tcp`` or ``udp``: a rule listing both protocols is compiled
    #: into one rule matching ``meta l4proto { tcp, udp }``, and naming
    #: either of them in the key makes nftables answer "conflicting
    #: protocols specified" and refuse the whole ruleset.
    _HASHLIMIT_KEYS: ClassVar[dict[str, str]] = {
        'srcip': 'saddr',
        'dstip': 'daddr',
        'srcport': 'sport',
        'dstport': 'dport',
    }

    #: How long a unit of the rate is, which is also how long an entry of
    #: the hash table lives when the rule names no idle time (netfilter
    #: extensions/libxt_hashlimit.c, parse_rate fills `mult`).
    _RATE_UNIT_SECONDS: ClassVar[dict[str, int]] = {
        'second': 1,
        'minute': 60,
        'hour': 60 * 60,
        'day': 24 * 60 * 60,
    }

    def _rate_unit(self, rule: CompRule) -> str | None:
        """Return the unit of the rate as nftables spells it, or ``None``.

        iptables takes any prefix of a unit name, so an imported file can
        carry `/sec` or `/min`; nftables knows the full word alone and
        answers anything else with a syntax error, which costs the whole
        ruleset.  A suffix that names no unit at all leaves the rule out:
        falling back to a default would enforce a rate the rule does not
        say, and per second is sixty times what a rule written per minute
        asks for.  The iptables printer answers it the same way.
        """
        suffix = str(rule.get_option('hashlimit_suffix', '') or '')
        unit = normalize_rate_unit(suffix)
        if unit is None:
            self.compiler.error(
                rule,
                f'"{suffix.strip()}" is not a unit a rate can be given in; '
                'the rule is left out',
            )
            return None
        return unit

    def _print_hashlimit(self, rule: CompRule) -> str | None:
        """Print the rate limit kept per source, destination or port.

        The nftables counterpart of ``-m hashlimit``, in the shape
        iptables-translate produces for it (netfilter
        extensions/libxt_hashlimit.txlate):

            meter <name> { ip saddr timeout 60s limit rate 1/hour }

        A meter is a set keyed on what the mode names, holding a rate limit
        per element, which is what makes the limit per source rather than
        per rule.  The keys are concatenated with ``.`` when the mode names
        more than one, and the whole match is left out when it names none:
        without a key there is nothing to keep the buckets apart, and a
        plain ``limit rate`` would cap the rule as a whole, which is a
        different rule from the one the editor shows.

        ``None`` means the caller has to leave the rule out: a rate the
        rule cannot carry is a condition it loses, and a rule that keeps
        its action without its condition says the opposite of what it says.
        """
        try:
            limit = int(rule.get_option('hashlimit_value', 0) or 0)
        except (TypeError, ValueError):
            return ''
        if limit <= 0:
            return ''

        if rule.get_option('hashlimit_dstlimit', False):
            # The option asks for the "dstlimit" match, which netfilter
            # dropped from iptables after 1.3.7 and which nftables never
            # had; the iptables printer says the same about it.  What the
            # rule means is a rate limit kept per key, which is what a
            # meter is, so the rule is compiled and the option named.
            self.compiler.warning(
                rule,
                'The "dstlimit" variant of the rate limit names an iptables '
                'match nftables never had; the rule is compiled as the rate '
                'limit kept per key that replaced it',
            )

        modes = [
            mode
            for mode in ('srcip', 'dstip', 'srcport', 'dstport')
            if mode in self._hashlimit_modes(rule)
        ]
        rate = self._hashlimit_rate(rule, limit)
        if rate is None:
            # The rate cannot be written and the reason was reported.
            return None

        if not modes:
            # iptables takes `-m hashlimit` without a mode - only the name
            # is mandatory in the current revision, and the real tool
            # accepts it - and the hash table then has a single bucket,
            # which is a rate limit for the rule as a whole.  That is a
            # plain `limit rate` here, with no meter to key it by.
            return rate

        af = 'ip6' if self.compiler.ipv6_policy else 'ip'
        has_ports = self._hashlimit_has_ports(rule)
        keys = []
        for mode in modes:
            field = self._HASHLIMIT_KEYS[mode]
            if mode.endswith('port'):
                if not has_ports:
                    # The kernel reads the ports only for the protocols that
                    # have them (net/netfilter/xt_hashlimit.c asks
                    # proto_ports_offset) and leaves the field at zero
                    # otherwise, so the port half of the key contributes
                    # nothing.  Leaving it out says the same and keeps the
                    # rule away from bytes that are not a port.
                    continue
                keys.append(f'th {field}')
            else:
                keys.append(f'{af} {field}')
        if not keys:
            # Every key the mode named was a port and the rule has none, so
            # the whole key is the zero the kernel writes: one bucket for
            # the rule, which is a plain `limit rate`.  Returning nothing
            # here would leave the rule with no limit at all.
            return rate

        key = ' . '.join(keys)
        parts = [key]

        # --hashlimit-htable-max bounds how many sources the table holds.
        # A meter's implicit set takes the same bound as `size`, and
        # without one it grows until the set is full and stops limiting
        # anything it has not seen yet.  The sibling option
        # --hashlimit-htable-size counts hash buckets, which is an
        # implementation detail of the iptables match and has no meaning
        # here.
        try:
            entries = int(rule.get_option('hashlimit_max', 0) or 0)
        except (TypeError, ValueError):
            entries = 0
        size = f' size {entries}' if entries > 0 else ''

        try:
            expire = int(rule.get_option('hashlimit_expire', 0) or 0)
        except (TypeError, ValueError):
            expire = 0
        if expire <= 0:
            # An entry always expires on iptables: with no idle time given,
            # hashlimit_mt_check fills it in from the unit of the rate
            # (netfilter extensions/libxt_hashlimit.c, `expire = mult *
            # 1000`), and the kernel refuses a zero
            # (net/netfilter/xt_hashlimit.c).  A meter without a timeout
            # never drops an entry, so it grows until the set is full and
            # the rule stops limiting the sources it has not seen yet.
            # _hashlimit_rate has already read the unit and left the rule
            # out if it could not, so this call cannot report a second time.
            expire = self._RATE_UNIT_SECONDS.get(self._rate_unit(rule), 1) * 1000
        # iptables counts the idle time of a bucket in milliseconds,
        # nftables in seconds (libxt_hashlimit.txlate rounds the same way).
        timeout = f'timeout {max(1, expire // 1000)}s'
        parts.append(timeout)

        parts.append(rate)

        name = self._meter_name(rule)
        if not self._meter_fits(rule, name, key, timeout, size, rate):
            # Emitting the rule anyway is worse than leaving it out.  The
            # set is created with the key type of the first rule that named
            # it, and nftables takes the second rule without a word: a
            # `tcp dport` written into an `ipv4_addr` set becomes an
            # address, sharing its buckets with the source addresses of the
            # first rule, so neither rule limits what it says it limits.
            # Verified by loading such a ruleset in a network namespace.
            return None
        return f'meter {name}{size} {{ {" ".join(parts)} }}'

    def _meter_fits(
        self,
        rule: CompRule,
        name: str,
        key: str,
        timeout: str,
        size: str,
        rate: str,
    ) -> bool:
        """Report whether this rule's meter agrees with the one already there.

        A meter is a typed set, so every rule naming one has to agree on
        the type of its key, on whether its elements time out and on how
        many of them it holds.  Those three are answered with an error,
        because the ruleset either does not load at all or counts something
        other than what the rule says.

        The rate is answered with a warning, the way the iptables side
        answers the same question about a shared hash table: nftables takes
        two rates on one meter without a word, and the rate that applies to
        a given source is the one of whichever rule saw it first (see
        `PolicyCompiler_nft.register_meter`).  So the ruleset loads and the
        second rule silently limits at the first one's rate.

        Registering it while the compiler is muted would claim the name for
        a rule `Optimize3` is only rehearsing and may then drop, and the
        next rule would be reported against a meter no rule declares - the
        same reason the iptables `_check_hashlimit_table` returns early
        there.
        """
        if getattr(self.compiler, 'muted_now', False):
            return True
        shape_fits, rate_agrees = self.compiler.register_meter(
            name, key, timeout, size, rate
        )
        if not shape_fits:
            self.compiler.error(
                rule,
                f'the rate limit table "{name}" is already in use by another '
                'rule that keys it differently, expires its entries '
                'differently or holds a different number of them; give one '
                'of the two its own name. The rule is left out',
            )
            return False
        if not rate_agrees:
            self.compiler.warning(
                rule,
                f'the rate limit table "{name}" is already in use by another '
                'rule with a different rate; the kernel keeps the rate of '
                'the first one for every source both rules see',
            )
        return True

    def _meter_name(self, rule: CompRule) -> str:
        """Return the name of the meter this rule's rate limit counts in.

        A meter is a typed set, so an IPv4 and an IPv6 rule cannot share
        one: the address of the second would be stored into the type of the
        first, which for an IPv6 address in an ``ipv4_addr`` set means its
        first four bytes, sharing buckets with IPv4.  nftables says nothing
        about it.  The family therefore belongs in the name, exactly as it
        does for the set behind a per-source connection limit.

        The name the editor leaves empty is the rule's position, and every
        rule set numbers its rules from zero, so the rule set belongs in it
        too.
        """
        name = str(rule.get_option('hashlimit_name', '') or '').strip()
        if not name:
            name = f'htable_{self.compiler.get_rule_set_name()}_{rule.position}'
        if self.compiler.ipv6_policy:
            name += '_v6'
        return nft_object_name(name)

    def _hashlimit_rate(self, rule: CompRule, limit: int) -> str | None:
        """Return the `limit rate ...` half of a hashlimit.

        The rate is a ceiling, not a floor.  The iptables side writes
        ``--hashlimit <n>``, which is the old spelling of
        ``--hashlimit-upto`` (netfilter extensions/libxt_hashlimit.c binds
        both to ``O_UPTO``), so the rule matches while the traffic stays
        *below* the rate.  nftables says that with a plain ``limit rate``;
        ``limit rate over`` is the opposite (``NFT_LIMIT_F_INV``) and
        belongs to ``--hashlimit-above``, which the editor cannot ask for.
        The gold shows both mappings side by side
        (extensions/libxt_hashlimit.txlate).
        """
        unit = self._rate_unit(rule)
        if unit is None:
            return None
        rate = f'limit rate {limit}/{unit}'
        try:
            burst = int(rule.get_option('hashlimit_burst', 0) or 0)
        except (TypeError, ValueError):
            burst = 0
        if burst > 0:
            if not self._burst_fits(rule, burst):
                return None
            rate += f' burst {burst} packets'
        return rate

    def _burst_fits(self, rule: CompRule, burst: int) -> bool:
        """Report whether nftables can carry *burst*, reporting if it cannot.

        The burst travels in a 32-bit netlink attribute
        (``nftnl_expr_set_u32(NFTNL_EXPR_LIMIT_BURST)`` in netfilter
        nftables src/netlink_linearize.c, read back with ``nla_get_be32``
        in the kernel's net/netfilter/nft_limit.c), and neither side
        complains about a larger number: it is simply cut to its low 32
        bits.  A burst of exactly 2^32 therefore arrives as zero, which the
        kernel replaces with ``NFT_LIMIT_PKT_BURST_DEFAULT``, five - the
        rule then bursts five packets where it was written for four
        billion.  Verified against nft 1.1.6 in a network namespace.
        """
        if burst <= MAX_NFT_LIMIT_BURST:
            return True
        self.compiler.error(
            rule,
            f'Rate limit burst {burst} is out of range; nftables carries 0 to '
            f'{MAX_NFT_LIMIT_BURST} and cuts anything larger down without '
            'saying so; the rule is left out',
        )
        return False

    def _hashlimit_modes(self, rule: CompRule) -> set[str]:
        """Return the modes the rule asks the rate limit to key on.

        Firewall Builder stored one comma-separated string in v2.1 and four
        booleans from v3 on, and the GUI writes the booleans under a third
        spelling, so all three are read.
        """
        stored = str(rule.get_option('hashlimit_mode', '') or '').strip()
        if stored:
            return {
                normalize_hashlimit_mode(mode)
                for mode in stored.split(',')
                if mode.strip()
            }
        return {
            mode
            for mode in ('srcip', 'dstip', 'srcport', 'dstport')
            if rule.get_option(f'hashlimit_mode_{mode}', False)
            or rule.get_option(f'hashlimit_{mode}', False)
        }

    @staticmethod
    def _hashlimit_has_ports(rule: CompRule) -> bool:
        """Report whether the rule's service carries a port at all.

        Only the protocols the kernel knows ports for can be keyed on one
        (net/netfilter/xt_hashlimit.c asks ``proto_ports_offset``); for any
        other the port half of the key stays zero.
        """
        return any(isinstance(srv, (TCPService, UDPService)) for srv in rule.srv)

    def _print_limit(self, rule: CompRule) -> str | None:
        """Print native nftables rate limiting, or ``None`` on failure.

        Mirrors the iptables ``-m limit --limit N/unit --limit-burst B``
        match. iptables-translate maps this to nftables' native
        ``limit rate N/unit burst B packets`` form (see the netfilter
        ``libxt_limit.txlate`` gold output), so a rule that carries a rate
        limit produces the same effect on both backends. The stored
        iptables takes any prefix of a unit name, so a stored ``/sec`` is
        valid there and a syntax error here, which costs the whole ruleset;
        the suffix is therefore written out to the full word nftables
        knows.

        ``None`` means the caller has to leave the rule out.  A rate limit
        is a condition like any other, and a rule that keeps its action and
        loses the condition does the opposite of what it says: "drop above
        20 per second" becomes "drop".  Falling back to a default unit is
        the same mistake in slower motion - per second is sixty times what
        a rule written per minute asks for.
        """
        negated = False
        if rule.ipt_target in LOG_TARGETS:
            # fwbuilder applies the limit configured in the firewall settings
            # to log rules and the limit configured on the rule itself to
            # every other rule (PolicyCompiler_PrintRule.cpp:271).
            limit_val = self.compiler.fw.get_option('limit_value')
            limit_suffix = self.compiler.fw.get_option('limit_suffix')
            burst = 0
        else:
            limit_val = rule.get_option('limit_value', -1)
            limit_suffix = rule.get_option('limit_suffix', '')
            burst = rule.get_option('limit_burst', 0)
            negated = bool(rule.get_option('limit_value_not', False))

        try:
            limit_val = int(limit_val)
        except (ValueError, TypeError):
            limit_val = -1
        if limit_val <= 0:
            return ''

        unit = normalize_rate_unit(str(limit_suffix or ''))
        if unit is None:
            self.compiler.error(
                rule,
                f'"{str(limit_suffix).strip()}" is not a unit a rate can be '
                'given in; the rule is left out',
            )
            return None
        limit_suffix = f'/{unit}'
        try:
            burst = int(burst)
        except (ValueError, TypeError):
            burst = 0
        if burst > 0 and not self._burst_fits(rule, burst):
            return None

        # "over" is nftables' inverted rate limit: the statement matches once
        # the rate has been exceeded (netfilter nftables src/parser_bison.y
        # maps it to NFT_LIMIT_F_INV, tests/py/any/limit.t).  iptables has no
        # such form and reports the rule instead.
        mode = 'over ' if negated else ''
        result = f'limit rate {mode}{limit_val}{limit_suffix}'
        if burst > 0:
            result += f' burst {burst} packets'
        return result

    def _print_state(self, rule: CompRule) -> str:
        """Print connection tracking state matching."""
        stateless = rule.get_option('stateless', False)
        force_state = rule.force_state_check

        if not stateless or force_state:
            return 'ct state new'
        return ''

    @staticmethod
    def _hour_literal(seconds: int, kerneltz: bool) -> str:
        """Render a time of day for ``meta hour``.

        A bare number goes into the rule as the seconds since UTC midnight
        the kernel compares against, which is what iptables' time match does
        without ``--kerneltz``.  With ``--kerneltz`` the times are local, and
        an ``"HH:MM:SS"`` literal is what nft converts from the timezone of
        the host loading the ruleset (hour_type_parse, netfilter nftables
        src/meta.c).
        """
        if not kerneltz:
            return str(seconds)
        hours, rest = divmod(seconds, 3600)
        minutes, secs = divmod(rest, 60)
        return f'"{hours:02d}:{minutes:02d}:{secs:02d}"'

    def _print_hour_range(self, start: int, stop: int, kerneltz: bool) -> str:
        """Return the ``meta hour`` match for a time window, or an empty string.

        A window that runs past midnight (22:00 to 06:00) is the interesting
        case: iptables matches it, because the time match compares the two
        ends the other way round once the start is behind the stop
        (net/netfilter/xt_time.c: time_mt).  nftables has no such rule, and
        ``meta hour 79200-21600`` asks for a value that is at once above the
        larger and below the smaller bound, so it matches nothing.  Saying it
        as the times *outside* the gap keeps the iptables meaning: the match
        holds unless the time falls strictly between the stop and the start.
        """
        if start < stop:
            return (
                f'meta hour {self._hour_literal(start, kerneltz)}'
                f'-{self._hour_literal(stop, kerneltz)}'
            )
        # An empty gap leaves nothing to exclude, so the window covers the
        # whole day and needs no match at all.  Equal ends are that case too:
        # iptables never rejects a packet on them.
        if start - stop < 2:
            return ''
        return (
            f'meta hour != {self._hour_literal(stop + 1, kerneltz)}'
            f'-{self._hour_literal(start - 1, kerneltz)}'
        )

    @staticmethod
    def _invert_time_match(match: str) -> str:
        """Turn a single ``meta hour`` / ``meta day`` match into its opposite."""
        if ' != ' in match:
            return match.replace(' != ', ' ', 1)
        keyword, _, value = match.partition(' ')
        # `meta hour`/`meta day` is two words, so the value starts after them.
        head, _, rest = value.partition(' ')
        return f'{keyword} {head} != {rest}'

    def _print_time_range(
        self, rule: CompRule, data: dict, interval, kerneltz: bool
    ) -> str | None:
        """Return the ``meta time`` match for an Interval's calendar window.

        An empty string means the Interval pins no date.  ``None`` means a
        date nftables refuses, which costs the whole ruleset, so the caller
        leaves the rule out.

        ``meta time`` is one range and iptables lets either end stand
        alone, so a missing end becomes the end of what a signed 32-bit
        time stamp can hold - the same bounds ``iptables-translate`` fills
        in (netfilter extensions/libxt_time.txlate).

        The two spellings the range is written in are the same choice
        ``_hour_literal`` makes.  Without ``--kerneltz`` iptables compares
        the packet's UTC stamp against a bound it read as UTC, so the bound
        goes out as the plain number of seconds nftables reads with
        ``strtoul``.  With ``--kerneltz`` the comparison is in local time,
        which is what nftables does with a quoted date: it subtracts the
        loading host's offset from the literal (netfilter nftables
        src/meta.c: parse_iso_date).
        """
        start, stop = parse_interval_dates(data)
        if start is None and stop is None:
            return ''

        bounds = []
        for date, fallback in ((start, 0), (stop, _LAST_SIGNED_32BIT_SECOND)):
            if date is None:
                bounds.append(self._time_literal(fallback, kerneltz))
                continue
            problem = date_problem(date)
            if problem:
                self.compiler.error(
                    rule,
                    f'Time object "{interval.name}" names a date nftables '
                    f'refuses: {problem}. The rule is left out',
                )
                return None
            bounds.append(date.iso(' ') if kerneltz else str(date.epoch()))
        return f'meta time {bounds[0]}-{bounds[1]}'

    @staticmethod
    def _time_literal(epoch: int, kerneltz: bool) -> str:
        """Render a point in time for ``meta time``, in the spelling in use."""
        if not kerneltz:
            return str(epoch)
        moment = datetime.datetime.fromtimestamp(epoch, tz=datetime.UTC)
        return f'"{moment.strftime("%Y-%m-%d %H:%M:%S")}"'

    def _print_time_interval(self, rule: CompRule) -> str | None:
        """Print nftables time/weekday matching.

        Uses ``meta hour`` for time-of-day and ``meta day`` for weekday
        constraints.

        A negated interval is the opposite of everything the interval says at
        once.  When the interval boils down to a single condition that is one
        ``!=``; when it names both a time of day and a set of weekdays, the
        opposite is "outside those hours *or* on another day", and no single
        nftables rule holds a disjunction, so the rule is reported and left
        out rather than written as something else.
        """
        if not rule.when:
            return ''

        interval = rule.when[0]
        data = interval.data or {}
        negated = bool(rule.get_neg('when'))

        if is_any_interval(data):
            if negated:
                # "Never" - the rule can never match, so writing it would
                # only be misleading.
                self.compiler.error(
                    rule,
                    'The time is negated but covers the whole week, so the '
                    'rule can never match',
                )
                return None
            return ''

        start_h, start_m, end_h, end_m, days = parse_interval_data(data)

        kerneltz = bool(self.compiler.fw.get_option('use_kerneltz'))

        parts = []
        date_match = self._print_time_range(rule, data, interval, kerneltz)
        if date_match is None:
            return None
        if date_match:
            # A calendar window carries its own start and stop time, and
            # iptables drops the daily window as soon as one of the two
            # dates is there (fwbuilder
            # iptlib/PolicyCompiler_PrintRule.cpp: use_timestart_timestop).
            # Writing both would narrow the rule to the hours of the last
            # day and make the two platforms disagree.
            parts.append(date_match)
        else:
            hour_match = self._print_hour_range(
                start_h * 3600 + start_m * 60,
                end_h * 3600 + end_m * 60,
                kerneltz,
            )
            if hour_match:
                parts.append(hour_match)

        if sorted(days) != list(range(7)):
            day_names = ', '.join(f'"{DOW_NAMES_FULL[d]}"' for d in days)
            parts.append(f'meta day {{ {day_names} }}')
            if not kerneltz:
                # `meta day` always takes the kernel timezone into account:
                # nft_meta_weekday() subtracts sys_tz.tz_minuteswest, the
                # very adjustment xt_time only makes for --kerneltz
                # (net/netfilter/nft_meta.c, net/netfilter/xt_time.c).  So
                # the weekday cannot be matched in UTC, and a rule left at
                # the iptables default of UTC shifts by the kernel's offset.
                self.compiler.warning(
                    rule,
                    'nftables always matches the weekday in the kernel '
                    'timezone; turn on "use kernel timezone" so iptables '
                    'agrees',
                )

        if negated:
            if len(parts) == 1:
                return self._invert_time_match(parts[0])
            if not parts:
                # Every hour of every day, negated: the rule never matches.
                self.compiler.error(
                    rule,
                    'The time is negated but covers the whole week, so the '
                    'rule can never match',
                )
                return None
            self.compiler.error(
                rule,
                'A negated time that names both a time of day and a weekday '
                'needs two rules to say "outside those hours or on another '
                'day", which nftables cannot express in one; the rule is '
                'left out',
            )
            return None

        return ' '.join(parts)

    def _print_log(self, rule: CompRule) -> str:
        """Print log expression.

        In nftables, log is an inline statement, not a separate target.
        It can be combined with a verdict: `log prefix "..." accept`

        Handles two cases:
        - ipt_target == 'LOG': standalone log rule (Continue action)
        - nft_log flag: inline log before verdict (e.g. `log prefix "..." accept`)

        When ``use_NFLOG`` is enabled, generates ``log group N`` instead of
        plain ``log``, which routes packets via netlink to a userspace
        logging daemon (ulogd2, rsyslog, syslog-ng).
        """
        if rule.ipt_target != 'LOG' and not rule.nft_log:
            return ''

        use_nflog = self.compiler.fw.get_option('use_NFLOG')

        parts = ['log']

        if use_nflog:
            try:
                nlgroup = int(get_log_netlink_group(self.compiler, rule))
            except (TypeError, ValueError):
                nlgroup = 1
            parts.append(f'group {nlgroup}')

            # The copy range and the queue threshold are part of the log
            # statement, exactly like iptables' `--nflog-range` /
            # `--nflog-threshold` (netfilter extensions/libxt_NFLOG.c maps
            # them to `snaplen` and `queue-threshold`). Same thresholds as
            # the iptables print rule so both platforms emit or omit them
            # together.
            cprange = get_log_copy_range(self.compiler, rule)
            if cprange > 0:
                parts.append(f'snaplen {cprange}')

            qthreshold = get_log_queue_threshold(self.compiler, rule)
            if qthreshold > 1:
                parts.append(f'queue-threshold {qthreshold}')

        log_prefix = self._get_log_prefix(rule)
        if log_prefix:
            parts.append(f'prefix "{log_prefix}"')

        if not use_nflog:
            log_level = rule.get_option('log_level', '')
            if not log_level:
                log_level = self.compiler.fw.get_option('log_level')
            if log_level:
                # nftables uses the abbreviated syslog level keywords
                # (see nftables src/statement.c: syslog_level[]), so map the
                # spellings iptables accepts to what nft parses.
                log_level = self._NFT_LOG_LEVELS.get(
                    str(log_level).strip().lower(), log_level
                )
                if log_level == 'audit':
                    # `log level audit` is a different facility, not a
                    # severity, and nftables refuses every other option
                    # next to it ("log level audit doesn't support any
                    # further options", src/evaluate.c) - which costs the
                    # whole ruleset.  The rule keeps its prefix and its
                    # flags and logs at the default severity.
                    self.compiler.warning(
                        rule,
                        'nftables cannot combine the "audit" log level with a '
                        'prefix or with log flags; the rule logs at the '
                        'default level instead',
                    )
                elif log_level in self._NFT_LOG_LEVEL_KEYWORDS:
                    parts.append(f'level {log_level}')
                else:
                    # Emitting it anyway is a syntax error, and nft answers
                    # one of those by throwing away the whole ruleset, so
                    # the firewall would keep every rule it has.
                    self.compiler.warning(
                        rule,
                        f'nftables has no log level "{log_level}"; the rule '
                        f'logs at the default level instead',
                    )

        # Optional log flags (per-rule overrides firewall-level default).
        # Each flag becomes its own `flags <category> <flag>` clause; nftables
        # accepts them in any order at the end of the log statement.
        fw_opt = self.compiler.fw.get_option
        flags = []
        if rule.get_option('log_tcp_seq', False) or fw_opt('log_tcp_seq'):
            flags.append('flags tcp sequence')
        if rule.get_option('log_tcp_opt', False) or fw_opt('log_tcp_opt'):
            flags.append('flags tcp options')
        if rule.get_option('log_ip_opt', False) or fw_opt('log_ip_opt'):
            flags.append('flags ip options')

        if flags and use_nflog:
            # nftables refuses a log statement that carries both (evaluate.c:
            # "flags and group are mutually exclusive"), and iptables' NFLOG
            # target has no counterpart to the LOG flags either. Drop them so
            # the ruleset loads; the daemon behind the group logs the whole
            # packet anyway.
            self.compiler.warning(
                rule,
                'the TCP/IP log options do not apply to netlink logging and '
                'are left out of the generated rule',
            )
        elif flags:
            parts.extend(flags)

        return ' '.join(parts)

    def _get_log_prefix(self, rule: CompRule) -> str:
        """Get log prefix, expanding macros."""
        log_prefix = rule.get_option('log_prefix', '')
        if not log_prefix:
            log_prefix = self.compiler.fw.get_option('log_prefix')
        if not log_prefix:
            return ''

        log_prefix = str(log_prefix)

        action = rule.stored_action.upper()
        pos = str(rule.position)
        chain = rule.ipt_chain or ''

        iface_name = ''
        if rule.itf:
            obj = rule.itf[0]
            if isinstance(obj, Interface):
                iface_name = obj.name
        if not iface_name or iface_name == 'Any':
            iface_name = 'global'

        ruleset_name = 'Policy'
        if self.compiler.source_ruleset:
            ruleset_name = self.compiler.source_ruleset.name

        result = log_prefix.replace('%N', pos)
        result = result.replace('%A', action)
        result = result.replace('%I', iface_name)
        result = result.replace('%C', chain)
        result = result.replace('%R', ruleset_name)
        cleaned = sanitize_log_prefix(result)
        if cleaned != result:
            self.compiler.warning(
                rule,
                f'Log prefix "{result}" holds a character the generated ruleset '
                f'cannot pass on and was written as "{cleaned}"',
            )
        result = cleaned
        # The kernel takes a log prefix of up to NF_LOG_PREFIXLEN - 1 = 127
        # characters, for a netlink group as well as for plain logging
        # (netfilter linux/include/uapi/linux/netfilter/nf_log.h and
        # net/netfilter/nft_log.c). This is not the 29-character limit of
        # iptables' LOG target nor the 63 of its NFLOG target.  Cutting it
        # is what keeps the ruleset loadable - nft answers a longer one
        # with "log prefix is too long" and refuses all of it - but a log
        # parser reading the fields behind the cut has to be told, the way
        # the iptables printer says it.
        if len(result) > MAX_NFT_LOG_PREFIX:
            self.compiler.warning(
                rule,
                f'Log prefix "{result}" is longer than the '
                f'{MAX_NFT_LOG_PREFIX} characters nftables can carry and has '
                'been truncated',
            )
            result = result[:MAX_NFT_LOG_PREFIX]
        return result

    def _print_mangle_statement(self, rule: CompRule) -> str | None:
        """Print the statement of a tagging or classifying rule, or ``None``.

        These are the nftables counterparts of the iptables MARK and
        CLASSIFY targets (netfilter ``extensions/libxt_MARK.txlate`` and
        ``libxt_CLASSIFY.txlate``).  Unlike a verdict they let the packet
        carry on to the next rule, so they are printed in front of it.

        ``None`` means the caller has to leave the rule out.  Setting the
        mark, the traffic class or the connection mark is the whole point
        of such a rule: without its statement it matches, counts and lets
        the packet through unchanged, so every rule and every routing
        decision keyed on that mark sees traffic the policy says is
        marked and finds it is not.  The iptables ``_print_target`` returns
        None in the same three cases.
        """
        parts = []

        if rule.get_option('tagging', False):
            tag_value = get_tag_value(self.compiler, rule)
            if not tag_value:
                self.compiler.error(
                    rule,
                    'tagging rule has no Tag Service to take the mark from; '
                    'the rule is left out',
                )
                return None
            if not is_valid_packet_mark(tag_value):
                # The mark is free text from the Tag Service editor and
                # reaches the command as a bare shell word.
                self.compiler.error(
                    rule,
                    f'"{tag_value}" is not a packet mark; it takes a number '
                    'up to 4294967295, optionally followed by a slash and a '
                    'mask. The rule is left out',
                )
                return None
            parts.append(print_mark_set(tag_value))

        if rule.get_option('classification', False):
            classify_str = rule.get_option('classify_str', '')
            if not classify_str:
                self.compiler.error(
                    rule,
                    'classification rule has no traffic class to set; '
                    'the rule is left out',
                )
                return None
            if not is_valid_traffic_class(classify_str):
                # nftables takes a bare number here where the CLASSIFY
                # target refuses one, and the two then mean different
                # handles for the same policy, so the rule is reported on
                # both platforms rather than compiled into a difference.
                self.compiler.error(
                    rule,
                    f'"{classify_str}" is not a traffic class; it takes two '
                    'hexadecimal numbers separated by a colon, such as 1:11. '
                    'The rule is left out',
                )
                return None
            parts.append(print_priority_set(classify_str))

        if rule.ipt_target == 'CONNMARK':
            connmark = print_connmark(rule.get_option('CONNMARK_arg', ''))
            if not connmark:
                self.compiler.error(
                    rule,
                    'a rule marking the connection says nothing about what to '
                    'do with the mark; the rule is left out',
                )
                return None
            parts.append(connmark)

        return ' '.join(parts)

    def _print_verdict(self, rule: CompRule) -> str | None:
        """Print the nftables verdict, or ``None`` if it cannot be built.

        An empty string is a verdict of its own: ``.CONTINUE``, a LOG rule
        and a connection-marking rule all deliberately end without one, and
        the packet goes on to the next rule.  A branch whose chain does not
        exist, a Custom action and an action nftables has no verdict for
        therefore have to answer ``None``, or the rule goes out with every
        one of its matches, a ``counter`` and nothing else - which counts
        the packets and leaves the decision to whatever rule comes next,
        while the activation reports success.  The iptables
        ``_print_target`` answers the same question the same way.
        """
        target = rule.ipt_target

        # LOG target is printed via _print_log, CONNMARK via
        # _print_mangle_statement; neither ends the rule with a verdict.
        if target in ('LOG', 'CONNMARK'):
            return ''

        # Handle iptables target names mapped to nftables verdicts
        verdict_map = {
            'ACCEPT': 'accept',
            'DROP': 'drop',
            # The iptables QUEUE target hands the packet to userspace on
            # queue number 0 (net/ipv4/netfilter/ip_tables.c turns its
            # standard-target verdict into a bare NF_QUEUE), which is what a
            # plain `queue` means in nftables as well.
            'QUEUE': 'queue',
            'REJECT': 'reject',
            'RETURN': 'return',
        }

        if target:
            if target == '.CONTINUE':
                return ''
            if target.startswith('.'):
                # `.CUSTOM` is the only other pseudo target, and DecideOnTarget
                # has already reported that its free-form iptables text has no
                # meaning here.  The rule keeps nothing that would carry out
                # its action.
                return None
            verdict = verdict_map.get(target)
            if verdict:
                if verdict == 'reject':
                    return self._print_reject(rule)
                return verdict
            # A branch rule set has a regular chain of its own, so the jump
            # is exactly what the rule means.  Any other name is a chain no
            # part of this ruleset declares - branching back into the top
            # rule set, for one, whose chains are hooked and cannot be
            # jumped to.  nftables refuses the whole ruleset over such a
            # jump, so the rule is reported and left out.
            nft_comp = cast('PolicyCompiler_nft', self.compiler)
            if target not in getattr(nft_comp, 'branch_chains', set()):
                self.compiler.error(
                    rule,
                    f'Rule branches to "{target}", which is not a rule set '
                    'nftables can jump to; the rule is left out',
                )
                return None
            return f'jump {target}'

        # Fall back to action
        action_map = {
            PolicyAction.Accept: 'accept',
            PolicyAction.Deny: 'drop',
            PolicyAction.Pipe: 'queue',
            PolicyAction.Reject: 'reject',
            PolicyAction.Return: 'return',
            PolicyAction.Continue: '',
        }

        # An action with no target and no entry here is one DecideOnTarget
        # has already reported: Branch without a rule set, Modify, Scrub,
        # Skip.  There is no verdict to fall back on, so the rule goes.
        action = rule.action
        if not isinstance(action, PolicyAction) or action not in action_map:
            return None
        verdict = action_map[action]
        if verdict == 'reject':
            return self._print_reject(rule)
        return verdict

    def _print_reject(self, rule: CompRule) -> str:
        """Print ``reject`` with the correct reject type for the family.

        nftables' reject syntax is family-specific:
          * IPv4 policies use ``icmp <name>`` (e.g. ``icmp port-unreachable``)
          * IPv6 policies use ``icmpv6 <name>`` (e.g. ``icmpv6 port-unreachable``)
        A ``reject with icmp <name>`` line inside an ``ip6`` or ``inet``
        table that applies to IPv6 traffic is rejected by ``nft -f`` as
        invalid, so the family is selected from ``ipv6_policy`` here.
        """
        action_on_reject = rule.get_option('action_on_reject', '')

        if not action_on_reject:
            return 'reject'

        is_ipv6 = getattr(self.compiler, 'ipv6_policy', False)
        icmp_kw = 'icmpv6' if is_ipv6 else 'icmp'

        token = reject_type_token(action_on_reject, is_ipv6)

        if token == 'tcp-reset':  # nosec B105
            return 'reject with tcp reset'

        table = _REJECT_CODE_IPV6 if is_ipv6 else _REJECT_CODE_IPV4
        code = table.get(token)
        if code:
            return f'reject with {icmp_kw} {code}'

        self.compiler.warning(
            rule,
            f'Unknown reject type "{action_on_reject}", falling back to generic reject',
        )
        return 'reject'


# ═══════════════════════════════════════════════════════════════════
# Post-processing optimization: merge consecutive rules into sets
# ═══════════════════════════════════════════════════════════════════

# Matches "ip saddr <addr>" or "ip6 saddr <addr>" anywhere in a rule line.
# The pattern uses search(), so it finds the first occurrence in the line.
# Group 1: "ip saddr " or "ip6 saddr " (with optional "!= ")
# Group 2: address family ("ip" or "ip6")
# Group 3: optional negation ("!= " or empty)
# Group 4: the address value (single addr, CIDR, range, or { set })
# Group 5: the rest of the rule after the address
_SADDR_RE = re.compile(
    r'((ip6?) saddr (!= )?)'  # af + saddr + optional negation
    r'(\{[^}]+\}|[^\s]+)'  # address: set or single value
    r'(.*)$',  # suffix: rest of the rule
)

# Same pattern for daddr.
_DADDR_RE = re.compile(
    r'((ip6?) daddr (!= )?)'
    r'(\{[^}]+\}|[^\s]+)'
    r'(.*)$',
)


def _split_entry(entry: str) -> tuple[str, str]:
    """Split a chain_rules entry into (comments, rule_line).

    Each entry may contain comment lines (starting with ``#``) followed
    by exactly one rule line, or may contain only a rule line.  Error
    comment lines (``# Error: ...``) immediately preceding a rule are
    kept attached to the rule via the comments portion.

    Returns ``('', '')`` if the entry contains no rule line.
    """
    lines = entry.split('\n')
    # Find the last non-empty, non-comment line — that is the rule.
    rule_idx = -1
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith('#'):
            rule_idx = i
            break

    if rule_idx < 0:
        return ('', '')

    comment_lines = lines[:rule_idx]
    rule_line = lines[rule_idx]
    # Trailing lines after the rule (usually just an empty string from
    # the final newline) are discarded — we reconstruct the newline on
    # output.
    comments = '\n'.join(comment_lines) + '\n' if comment_lines else ''
    return (comments, rule_line)


def _inside_braces(line: str, index: int) -> bool:
    """Report whether *index* sits inside a ``{ ... }`` group of *line*."""
    return line.count('{', 0, index) > line.count('}', 0, index)


def _parse_addr(
    rule_line: str,
) -> tuple[str, str, str, str] | None:
    """Try to extract an address field from a rule line.

    Returns ``(prefix, addr, suffix, field)`` where *field* is
    ``'saddr'`` or ``'daddr'``, or ``None`` if no address field is
    found.

    *prefix* and *suffix* together form the "signature" of the rule —
    everything except the varying address.  Two rules can be merged if
    their prefix, suffix, and field are identical.
    """
    for pattern, field in ((_SADDR_RE, 'saddr'), (_DADDR_RE, 'daddr')):
        m = pattern.search(rule_line)
        if m:
            if _inside_braces(rule_line, m.start()):
                # A rate limit or a connection limit carries its key inside
                # `{ ... }`, and the key names the same header field:
                # `add @s { ip saddr ct count over 10 }`.  That is not the
                # rule's address match, and merging two of these would put
                # a set inside the braces, which is a syntax error.  The
                # other side of the rule may still hold a real one.
                continue
            before_match = rule_line[: m.start()]
            prefix = before_match + m.group(1)
            addr = m.group(4)
            suffix = m.group(5)
            if addr.lstrip().startswith('@'):
                # A reference to a named set is not a value an anonymous
                # set can hold; nftables rejects `{ @set, addr }`.
                return None
            return (prefix, addr, suffix, field)
    return None


def _addrs_from_value(value: str) -> list[str]:
    """Extract individual addresses from a value that may be a set.

    ``"10.0.0.1"`` -> ``["10.0.0.1"]``
    ``"{ 10.0.0.1, 10.0.0.2 }"`` -> ``["10.0.0.1", "10.0.0.2"]``
    """
    value = value.strip()
    if value.startswith('{') and value.endswith('}'):
        inner = value[1:-1]
        return [a.strip() for a in inner.split(',') if a.strip()]
    return [value]


def _build_addr_value(addrs: list[str]) -> str:
    """Build an address value, using set syntax if multiple."""
    if len(addrs) == 1:
        return addrs[0]
    return '{ ' + ', '.join(addrs) + ' }'


def optimize_chain_rules(chain_rules: dict[str, list[str]]) -> None:
    """Merge consecutive rules that differ only in source or destination address.

    Operates in-place on the per-chain rule lists produced by
    :class:`PrintRule_nft`.  Two adjacent entries are merged when their
    rule lines are structurally identical except for the ``ip saddr`` or
    ``ip daddr`` value.  The merged rule uses nftables anonymous set
    syntax: ``ip saddr { addr1, addr2 } ...``.

    Rules are never merged across different comment blocks (i.e. across
    different original firewall rules).  Only entries whose rule lines
    share the same "signature" (everything except the address value) are
    candidates.
    """
    for chain, entries in chain_rules.items():
        chain_rules[chain] = _optimize_entries(entries)


def _optimize_entries(entries: list[str]) -> list[str]:
    """Merge consecutive entries that differ only in one address field."""
    if len(entries) <= 1:
        return entries

    result: list[str] = []
    i = 0

    while i < len(entries):
        comments_i, rule_i = _split_entry(entries[i])
        parsed_i = _parse_addr(rule_i) if rule_i else None

        if parsed_i is None:
            # Not a mergeable rule — emit as-is.
            result.append(entries[i])
            i += 1
            continue

        prefix_i, addr_i, suffix_i, field_i = parsed_i
        signature = (prefix_i, suffix_i, field_i)
        merged_addrs = list(_addrs_from_value(addr_i))
        merged_comments = comments_i

        # Look ahead for consecutive entries with the same signature.
        # Stop at comment boundaries — a non-empty comment block marks
        # a new original firewall rule and must not be merged.
        j = i + 1
        while j < len(entries):
            comments_j, rule_j = _split_entry(entries[j])
            if not rule_j:
                break

            # A comment block signals a different original rule.
            if comments_j:
                break

            parsed_j = _parse_addr(rule_j)
            if parsed_j is None:
                break

            prefix_j, addr_j, suffix_j, field_j = parsed_j
            if (prefix_j, suffix_j, field_j) != signature:
                break

            # Same signature, same original rule — collect addresses.
            merged_addrs.extend(_addrs_from_value(addr_j))
            j += 1

        # Build the merged entry.
        addr_value = _build_addr_value(merged_addrs)
        merged_rule = f'{prefix_i}{addr_value}{suffix_i}'
        merged_text = merged_comments + merged_rule + '\n'
        result.append(merged_text)
        i = j

    return result
