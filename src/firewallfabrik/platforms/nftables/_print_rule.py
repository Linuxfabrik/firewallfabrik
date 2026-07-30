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

import ipaddress
import re
import uuid
from typing import TYPE_CHECKING, ClassVar, cast

from firewallfabrik.compiler._interval_helpers import (
    DOW_NAMES_FULL,
    is_any_interval,
    parse_interval_data,
)
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
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
    is_valid_dscp,
    range_to_cidr,
)
from firewallfabrik.platforms.linux._netfilter import interface_direction_problem

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.nftables._policy_compiler import PolicyCompiler_nft


def _is_true(val) -> bool:
    """Check a data-dict value that may be a Python bool or a string 'True'/'False'."""
    return str(val) == 'True'


def _as_iface_set(names: list[str]) -> str:
    """Render one interface name as it is, several as an anonymous set."""
    quoted = [f'"{name}"' for name in names]
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
    bitwise expression ``meta mark set mark and <~mask> xor <value>`` (the
    form ``iptables-translate`` produces for ``--set-xmark``, netfilter
    ``extensions/libxt_MARK.txlate``).
    """
    value, sep, mask = tag_code.partition('/')
    value = value.strip()
    if not sep:
        return f'meta mark set {value}'
    try:
        keep = (~int(mask.strip(), 0)) & 0xFFFFFFFF
    except ValueError:
        return f'meta mark set {value}'
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


def get_mac_only_address(obj) -> str:
    """Return the MAC of an object that has no IP address.

    A PhysAddress, or an Interface / Host whose only address is a MAC, can
    only be matched on the ethernet header.  Rendering such an object as an
    IP address produces a ruleset the packet filter refuses to load.
    """
    if isinstance(obj, PhysAddress):
        return obj.get_address() or ''
    if isinstance(obj, Interface):
        addresses = list(getattr(obj, 'addresses', []))
    elif isinstance(obj, Host):
        addresses = [
            addr
            for iface in getattr(obj, 'interfaces', [])
            if not iface.is_loopback()
            for addr in getattr(iface, 'addresses', [])
        ]
    else:
        return ''
    if any(addr.is_v4() or addr.is_v6() for addr in addresses):
        return ''
    for addr in addresses:
        if isinstance(addr, PhysAddress) and addr.get_address():
            return addr.get_address()
    return ''


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

    def initialize(self) -> None:
        """Initialize after compiler context is set."""
        pass

    def _report_impossible_interface_direction(self, rule: CompRule) -> bool:
        """Report a rule whose chain cannot see the interface it matches on.

        Returns True when the rule was reported and must not be printed.
        nftables takes ``iifname`` in postrouting and ``oifname`` in
        prerouting without complaining and then never matches the rule, so
        the mistake would go unnoticed.  Leaving the interface out instead
        would silently widen the rule to every interface.
        """
        if rule.iface_label == 'nil':
            return False
        direction = rule.direction
        if direction not in (Direction.Inbound, Direction.Outbound):
            return False
        inbound = direction == Direction.Inbound
        problem = interface_direction_problem(rule.ipt_chain, inbound)
        if not problem:
            return False
        side = 'incoming' if inbound else 'outgoing'
        self.compiler.error(
            rule,
            f'Rule matches on the {side} interface but {problem}; the rule is left out',
        )
        return True

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if self._report_impossible_interface_direction(rule):
            return True

        chain = rule.ipt_chain or 'forward'

        label_str = self._print_rule_label(rule, chain)
        cmd = self._build_rule(rule)

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
        """
        if rule.nft_log and self._firewall_log_limit() > 0:
            log_rule = rule.clone()
            log_rule.ipt_target = 'LOG'
            action_rule = rule.clone()
            action_rule.nft_log = False
            return self._build_rule_line(
                log_rule, with_errors=False
            ) + self._build_rule_line(action_rule)
        return self._build_rule_line(rule)

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
        if iface_match:
            parts.append(iface_match)

        # Source address
        src_match = self._print_src_addr(rule, af_prefix)
        if src_match:
            parts.append(src_match)

        # Destination address
        dst_match = self._print_dst_addr(rule, af_prefix)
        if dst_match:
            parts.append(dst_match)

        # Protocol + service matching
        srv_match = self._print_service(rule, srv)
        if srv_match:
            parts.append(srv_match)

        # State matching
        state_match = self._print_state(rule)
        if state_match:
            parts.append(state_match)

        # Time matching
        time_match = self._print_time_interval(rule)
        if time_match:
            parts.append(time_match)

        # Rate limiting (-m limit on iptables -> native `limit rate` on nftables)
        limit_match = self._print_limit(rule)
        if limit_match:
            parts.append(limit_match)

        # Logging, mangle statements and verdict
        log_match = self._print_log(rule)
        mangle_stmt = self._print_mangle_statement(rule)
        verdict = self._print_verdict(rule)

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
        errors = self.compiler.get_errors_for_rule(rule) if with_errors else ''
        if errors:
            line = f'        # {errors}\n' + line

        return line

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

    def _print_interface(self, rule: CompRule) -> str:
        """Print interface matching: iifname/oifname."""
        if rule.iface_label == 'nil':
            return ''

        direction = rule.direction
        if direction not in (Direction.Inbound, Direction.Outbound):
            return ''

        inbound = direction == Direction.Inbound

        if rule.is_itf_any():
            return ''

        ifaces = [obj for obj in rule.itf if isinstance(obj, Interface) and obj.name]
        if not ifaces:
            return ''

        neg = '!= ' if rule.itf_single_object_negation else ''
        # A negated element covers all of its interfaces at once; without
        # negation the rule is atomic by then and carries exactly one.
        names = [obj.name for obj in ifaces] if neg else [ifaces[0].name]

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

    def _print_src_addr(self, rule: CompRule, af_prefix: str) -> str:
        """Print source address matching."""
        if rule.is_src_any():
            return ''

        if not rule.src:
            return ''

        neg = '!= ' if rule.src_single_object_negation else ''
        return self._print_addr_match(rule, rule.src, f'{af_prefix} saddr', neg)

    def _print_dst_addr(self, rule: CompRule, af_prefix: str) -> str:
        """Print destination address matching."""
        if rule.is_dst_any():
            return ''

        if not rule.dst:
            return ''

        neg = '!= ' if rule.dst_single_object_negation else ''
        return self._print_addr_match(rule, rule.dst, f'{af_prefix} daddr', neg)

    def _print_addr_match(
        self, rule: CompRule, objects: list, keyword: str, neg: str
    ) -> str:
        """Render an address match, keeping MAC addresses apart.

        A MAC address is not part of the IP header, so it needs its own
        ``ether saddr`` / ``ether daddr`` match. This is what
        iptables-translate produces for ``-m mac --mac-source``.
        """
        direction = keyword.rsplit(' ', 1)[1]
        macs = []
        addrs = []
        for obj in objects:
            mac = get_mac_only_address(obj)
            if mac:
                macs.append(mac)
                continue
            addr = self._print_addr(obj, rule)
            if addr:
                addrs.append(addr)
        parts = []
        if macs:
            parts.append(self._match_clause(f'ether {direction}', macs, neg))
        if addrs:
            parts.append(self._match_clause(keyword, addrs, neg))
        if not parts:
            what = 'source' if direction == 'saddr' else 'destination'
            self.compiler.error(rule, f'Could not resolve any {what} addresses')
            return ''
        return ' '.join(parts)

    @staticmethod
    def _match_clause(keyword: str, values: list[str], neg: str) -> str:
        if len(values) == 1:
            return f'{keyword} {neg}{values[0]}'
        return f'{keyword} {neg}{{ {", ".join(values)} }}'

    def _print_addr(self, obj, rule: CompRule) -> str:
        """Print an address object in nftables format."""
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
                self.compiler.error(
                    rule,
                    f'Dynamic interface address not yet supported by nftables compiler'
                    f' (interface: {obj.name})',
                )
                return ''
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
            dnsrec = (obj.data or {}).get('dnsrec', obj.name)
            if dnsrec and dnsrec[:1].isdigit():
                return f'"{dnsrec}"'
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
                try:
                    net = ipaddress.ip_network(f'{addr_str}/{mask_str}', strict=False)
                    length = net.prefixlen
                    if length != 32 and length != 128:
                        return f'{addr_str}/{length}'
                except ValueError:
                    pass

        return addr_str

    def _print_service(self, rule: CompRule, srv) -> str:
        """Print protocol + port/ICMP matching."""
        negated = bool(rule.srv_single_object_negation)

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
            if _is_true(data.get('fragm')) or _is_true(data.get('short_fragm')):
                parts.append(print_fragment_match(self.compiler.ipv6_policy))
            if dscp:
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
                else:
                    # nftables' dscp symbols (cs0, af11, be, ef, ...) are
                    # lowercase and resolved case-sensitively; the DiffServ
                    # class names fwbuilder stores are uppercase (BE, CS0,
                    # AF11). Numeric values (0x20) are unaffected by lower().
                    parts.append(f'{af} dscp {dscp.lower()}')
            elif tos:
                # nftables has no ToS-byte matcher: the IPv4 ToS field was
                # split into dscp + ecn, so iptables' `-m tos --tos` has no
                # nftables equivalent. Fail loudly instead of emitting an
                # `ip tos` expression that nft rejects.
                self.compiler.error(
                    rule,
                    'IP service with a ToS value is not supported by nftables; '
                    'use a DSCP value instead',
                )
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
            if negated:
                return self._negate_single_match(rule, parts, 'IP service')
            # An "any IP" service with no further conditions carries no match
            # at all, which is correct: the rule applies to every protocol.
            return ' '.join(parts)
        elif isinstance(srv, CustomService):
            nft_comp = cast('PolicyCompiler_nft', self.compiler)
            code = (srv.codes or {}).get(nft_comp.my_platform_name(), '')
            if code:
                if negated:
                    # The code fragment is opaque nftables text; there is no
                    # way to invert it from here.
                    self.compiler.error(
                        rule,
                        f'Negating the custom service "{srv.name}" is not '
                        'supported by the nftables compiler; add a rule with '
                        'the inverse match instead',
                    )
                return code
            return ''
        elif isinstance(srv, TagService):
            tag_code = srv.get_code()
            if tag_code:
                return print_mark_match(tag_code, bool(rule.srv_single_object_negation))
            return ''
        elif isinstance(srv, UserService):
            uid = srv.userid or ''
            if uid:
                neg = '!= ' if rule.srv_single_object_negation else ''
                return f'meta skuid {neg}{uid}'
            return ''

        self.compiler.error(
            rule,
            f'Service type {type(srv).__name__} not yet supported by nftables compiler',
        )
        return ''

    # Map iptables/syslog level names to the abbreviated keywords nftables
    # accepts. Only the two divergent spellings need mapping.
    _NFT_LOG_LEVELS: ClassVar[dict[str, str]] = {
        'error': 'err',
        'warning': 'warn',
    }

    _TCP_FLAG_ORDER: ClassVar[tuple[str, ...]] = (
        'urg',
        'ack',
        'psh',
        'rst',
        'syn',
        'fin',
    )

    def _print_tcp_flags(self, srv, negated: bool = False) -> str:
        """Format TCP flag inspection for nftables.

        Reads the ORM attributes ``tcp_flags_masks`` (which flags to
        inspect, the MASK) and ``tcp_flags`` (which of those must be set,
        the COMP). nftables writes ``tcp flags <value> / <mask>`` with the
        value before the slash and the mask after, the reverse order of
        iptables' ``--tcp-flags MASK COMP`` (see nftables doc/data-types.txt
        and tests/py/inet/tcp.t).
        """
        masks = srv.tcp_flags_masks or {}
        flags = srv.tcp_flags or {}
        mask_names = [f for f in self._TCP_FLAG_ORDER if masks.get(f)]
        if not mask_names:
            return ''
        comp_names = [f for f in self._TCP_FLAG_ORDER if flags.get(f)]
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
                # Just the protocol, no ports, no flags
                parts.append(f'meta l4proto {proto}')

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

    _ICMP_TYPE_NAMES: ClassVar[dict[int, str]] = {
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

    _ICMPV6_TYPE_NAMES: ClassVar[dict[int, str]] = {
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

    def _negate_single_match(self, rule: CompRule, parts: list[str], what: str) -> str:
        """Return *parts* with the match inverted, or report why it cannot be.

        A negated rule element means "not (all of these conditions)".  A
        single condition inverts by turning its comparison into ``!=``.  Two
        or more conditions would have to be inverted as a disjunction, which
        one nft rule cannot express.
        """
        if not parts:
            # Nothing to match, so nothing to invert: the negation of
            # "matches everything" is "matches nothing".
            self.compiler.error(
                rule,
                f'Negating an unrestricted {what} leaves a rule that can '
                'never match; remove the rule instead',
            )
            return ''
        if len(parts) > 1:
            self.compiler.error(
                rule,
                f'Negating a {what} with several conditions '
                f'({", ".join(parts)}) is not supported by the nftables '
                'compiler; split it into one service per condition',
            )
            return ' '.join(parts)
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
        codes = getattr(srv, 'codes', None) or srv.data or {}
        raw_type = codes.get('type', -1)
        raw_code = codes.get('code', -1)
        icmp_type = -1 if raw_type is None else int(raw_type)
        icmp_code = -1 if raw_code is None else int(raw_code)

        proto = 'icmpv6' if self.compiler.ipv6_policy else 'icmp'
        type_names = (
            self._ICMPV6_TYPE_NAMES
            if self.compiler.ipv6_policy
            else self._ICMP_TYPE_NAMES
        )
        type_str = type_names.get(icmp_type, str(icmp_type))
        op = '!= ' if negated else ''

        if icmp_type < 0:
            # `meta l4proto` resolves its argument through getprotobyname(),
            # so it needs the /etc/protocols name `ipv6-icmp` (58); the bare
            # `icmpv6` keyword only exists as the payload-match protocol below.
            l4proto = 'ipv6-icmp' if self.compiler.ipv6_policy else 'icmp'
            return f'meta l4proto {op}{l4proto}'
        if icmp_code < 0:
            return f'{proto} type {op}{type_str}'
        if negated:
            # iptables negates the type/code pair as a whole. Negating both
            # halves separately would mean something else, so match the
            # concatenation of the two fields against a one-element set.
            return f'{proto} type . {proto} code != {{ {type_str} . {icmp_code} }}'
        return f'{proto} type {type_str} {proto} code {icmp_code}'

    def _print_limit(self, rule: CompRule) -> str:
        """Print native nftables rate limiting.

        Mirrors the iptables ``-m limit --limit N/unit --limit-burst B``
        match. iptables-translate maps this to nftables' native
        ``limit rate N/unit burst B packets`` form (see the netfilter
        ``libxt_limit.txlate`` gold output), so a rule that carries a rate
        limit produces the same effect on both backends. The stored
        ``limit_suffix`` (``/second``, ``/minute``, ``/hour``, ``/day``) is
        already the spelling nftables expects.
        """
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

        try:
            limit_val = int(limit_val)
        except (ValueError, TypeError):
            limit_val = -1
        if limit_val <= 0:
            return ''

        limit_suffix = limit_suffix or '/second'
        try:
            burst = int(burst)
        except (ValueError, TypeError):
            burst = 0

        result = f'limit rate {limit_val}{limit_suffix}'
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

    def _print_time_interval(self, rule: CompRule) -> str:
        """Print nftables time/weekday matching.

        Uses ``meta hour`` for time-of-day and ``meta day`` for weekday
        constraints.
        """
        if not rule.when:
            return ''

        interval = rule.when[0]
        data = interval.data or {}

        if is_any_interval(data):
            return ''

        start_h, start_m, end_h, end_m, days = parse_interval_data(data)

        kerneltz = bool(self.compiler.fw.get_option('use_kerneltz'))

        parts = []
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
            if kerneltz:
                # The kernel derives the weekday from the UTC timestamp and
                # nftables has no local-timezone counterpart, so this half of
                # `--kerneltz` cannot be reproduced.
                self.compiler.warning(
                    rule,
                    'nftables matches the weekday in UTC; the "use kernel '
                    'timezone" setting only applies to the time of day',
                )

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
            nlgroup = self.compiler.fw.get_option('ulog_nlgroup')
            try:
                nlgroup = int(nlgroup)
            except (TypeError, ValueError):
                nlgroup = 1
            parts.append(f'group {nlgroup}')

            # The copy range and the queue threshold are part of the log
            # statement, exactly like iptables' `--nflog-range` /
            # `--nflog-threshold` (netfilter extensions/libxt_NFLOG.c maps
            # them to `snaplen` and `queue-threshold`). Same thresholds as
            # the iptables print rule so both platforms emit or omit them
            # together.
            cprange = self.compiler.fw.get_option('ulog_cprange')
            try:
                cprange = int(cprange)
            except (TypeError, ValueError):
                cprange = 0
            if cprange > 0:
                parts.append(f'snaplen {cprange}')

            qthreshold = self.compiler.fw.get_option('ulog_qthreshold')
            try:
                qthreshold = int(qthreshold)
            except (TypeError, ValueError):
                qthreshold = 1
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
                # spellings iptables accepts to what nft parses. Levels not in
                # the map (alert, crit, debug, emerg, info, notice) are already
                # valid nft keywords and pass through unchanged.
                log_level = self._NFT_LOG_LEVELS.get(log_level, log_level)
                parts.append(f'level {log_level}')

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
        # The kernel takes a log prefix of up to NF_LOG_PREFIXLEN - 1 = 127
        # characters, for a netlink group as well as for plain logging
        # (netfilter linux/include/uapi/linux/netfilter/nf_log.h and
        # net/netfilter/nft_log.c). This is not the 29-character limit of
        # iptables' LOG target nor the 63 of its NFLOG target.
        return result[:127]

    def _get_tag_value(self, rule: CompRule) -> str:
        """Return the mark of the Tag Service a tagging rule refers to.

        Ports fwbuilder's ``PolicyRule::getTagValue()``: the rule options
        name the Tag Service, the service carries the mark.
        """
        tag_id = rule.get_option('tagobject_id', '')
        if not tag_id:
            return ''
        try:
            tag_obj = self.compiler.session.get(TagService, uuid.UUID(str(tag_id)))
        except (AttributeError, ValueError):
            return ''
        return tag_obj.get_code() if tag_obj else ''

    def _print_mangle_statement(self, rule: CompRule) -> str:
        """Print the statement of a tagging or classifying rule.

        These are the nftables counterparts of the iptables MARK and
        CLASSIFY targets (netfilter ``extensions/libxt_MARK.txlate`` and
        ``libxt_CLASSIFY.txlate``).  Unlike a verdict they let the packet
        carry on to the next rule, so they are printed in front of it.
        """
        parts = []

        if rule.get_option('tagging', False):
            tag_value = self._get_tag_value(rule)
            if tag_value:
                parts.append(print_mark_set(tag_value))
            else:
                self.compiler.error(
                    rule, 'tagging rule has no Tag Service to take the mark from'
                )

        if rule.get_option('classification', False):
            classify_str = rule.get_option('classify_str', '')
            if classify_str:
                parts.append(print_priority_set(classify_str))
            else:
                self.compiler.error(
                    rule, 'classification rule has no traffic class to set'
                )

        if rule.ipt_target == 'CONNMARK':
            connmark = print_connmark(rule.get_option('CONNMARK_arg', ''))
            if connmark:
                parts.append(connmark)
            else:
                self.compiler.error(
                    rule, 'connection mark rule has no operation to perform'
                )

        return ' '.join(parts)

    def _print_verdict(self, rule: CompRule) -> str:
        """Print the nftables verdict."""
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
            if target.startswith('.'):
                return ''
            verdict = verdict_map.get(target)
            if verdict:
                if verdict == 'reject':
                    return self._print_reject(rule)
                return verdict
            # Custom chain jump
            self.compiler.warning(
                rule,
                f'Custom chain jump not yet supported by nftables compiler: {target}',
            )
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

        action = rule.action
        verdict = action_map.get(action, '') if isinstance(action, PolicyAction) else ''
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

        s = action_on_reject.lower()

        if 'tcp' in s and ('rst' in s or 'reset' in s):
            return 'reject with tcp reset'

        if 'icmp' in s or 'unreachable' in s or 'prohibited' in s:
            if is_ipv6:
                # IPv6: only addr-/port-unreachable and adm-prohibited
                # are meaningful.  "net" and "host" map to
                # addr-unreachable; "proto" (unreachable) has no exact
                # IPv6 equivalent and is closest to port-unreachable.
                if 'unreachable' in s:
                    if 'net' in s or 'host' in s or 'addr' in s:
                        return f'reject with {icmp_kw} addr-unreachable'
                    if 'port' in s or 'proto' in s:
                        return f'reject with {icmp_kw} port-unreachable'
                    return f'reject with {icmp_kw} addr-unreachable'
                if 'prohibited' in s:
                    return f'reject with {icmp_kw} admin-prohibited'
            else:
                if 'unreachable' in s:
                    if 'net' in s:
                        return f'reject with {icmp_kw} net-unreachable'
                    if 'host' in s:
                        return f'reject with {icmp_kw} host-unreachable'
                    if 'port' in s:
                        return f'reject with {icmp_kw} port-unreachable'
                    if 'proto' in s:
                        return f'reject with {icmp_kw} prot-unreachable'
                    return f'reject with {icmp_kw} host-unreachable'
                if 'prohibited' in s:
                    if 'net' in s:
                        return f'reject with {icmp_kw} net-prohibited'
                    if 'host' in s:
                        return f'reject with {icmp_kw} host-prohibited'
                    if 'admin' in s:
                        return f'reject with {icmp_kw} admin-prohibited'

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
            before_match = rule_line[: m.start()]
            prefix = before_match + m.group(1)
            addr = m.group(4)
            suffix = m.group(5)
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
