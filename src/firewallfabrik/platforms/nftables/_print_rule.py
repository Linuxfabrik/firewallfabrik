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
from typing import TYPE_CHECKING

from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    Direction,
    Host,
    ICMP6Service,
    ICMPService,
    Interface,
    IPService,
    Network,
    NetworkIPv6,
    PolicyAction,
    TCPService,
    UDPService,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule


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

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        chain = rule.ipt_chain or 'forward'

        label_str = self._print_rule_label(rule, chain)
        cmd = self._build_rule(rule)

        text = ''
        if label_str:
            text += label_str
        text += cmd

        # Write to per-chain collection if available (nftables),
        # otherwise to the output stream (fallback).
        if hasattr(self.compiler, 'chain_rules') and chain in self.compiler.chain_rules:
            self.compiler.chain_rules[chain].append(text)
        else:
            self.compiler.output.write(text)
        return True

    def policy_rule_to_string(self, rule: CompRule) -> str:
        """Generate rule string for dedup."""
        return self._build_rule(rule)

    def _build_rule(self, rule: CompRule) -> str:
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

        # Logging
        log_match = self._print_log(rule)
        if log_match:
            parts.append(log_match)

        # Verdict/target
        verdict = self._print_verdict(rule)
        if verdict:
            parts.append(verdict)

        if not parts:
            return ''

        line = '        ' + ' '.join(parts) + '\n'

        # Add error comments inline
        errors = self.compiler.get_errors_for_rule(rule)
        if errors:
            line = f'        # {errors}\n' + line

        return line

    def _get_af_prefix(self, rule: CompRule, srv) -> str:
        """Get the address family prefix (ip/ip6) for matching."""
        if self.compiler and self.compiler.ipv6_policy:
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
        if not self.compiler or not self.compiler.single_rule_compile_mode:
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
        if rule._extra.get('.iface') == 'nil':
            return ''

        if rule.is_itf_any():
            return ''

        iface_obj = rule.itf[0] if rule.itf else None
        if iface_obj is None or not isinstance(iface_obj, Interface):
            return ''

        iface_name = iface_obj.name
        if not iface_name:
            return ''

        # nftables uses iifname/oifname for wildcard matching
        # and iif/oif for exact interface matching.
        # Use iif/oif for loopback — index-based is faster and safe
        # (loopback is always present with a stable index).
        neg = '!= ' if rule._extra.get('itf_single_object_negation') else ''
        is_loopback = iface_obj.is_loopback()

        direction = rule.direction
        if direction == Direction.Inbound:
            keyword = 'iif' if is_loopback else 'iifname'
            return f'{keyword} {neg}"{iface_name}"'
        elif direction == Direction.Outbound:
            keyword = 'oif' if is_loopback else 'oifname'
            return f'{keyword} {neg}"{iface_name}"'

        return ''

    def _print_src_addr(self, rule: CompRule, af_prefix: str) -> str:
        """Print source address matching."""
        if rule.is_src_any():
            return ''

        if not rule.src:
            return ''

        neg = '!= ' if rule._extra.get('src_single_object_negation') else ''
        addrs = [self._print_addr(obj) for obj in rule.src]
        addrs = [a for a in addrs if a]
        if not addrs:
            return ''
        if len(addrs) == 1:
            return f'{af_prefix} saddr {neg}{addrs[0]}'
        return f'{af_prefix} saddr {neg}{{ {", ".join(addrs)} }}'

    def _print_dst_addr(self, rule: CompRule, af_prefix: str) -> str:
        """Print destination address matching."""
        if rule.is_dst_any():
            return ''

        if not rule.dst:
            return ''

        neg = '!= ' if rule._extra.get('dst_single_object_negation') else ''
        addrs = [self._print_addr(obj) for obj in rule.dst]
        addrs = [a for a in addrs if a]
        if not addrs:
            return ''
        if len(addrs) == 1:
            return f'{af_prefix} daddr {neg}{addrs[0]}'
        return f'{af_prefix} daddr {neg}{{ {", ".join(addrs)} }}'

    def _print_addr(self, obj) -> str:
        """Print an address object in nftables format."""
        if isinstance(obj, AddressRange):
            start = obj.get_start_address()
            end = obj.get_end_address()
            if start and end:
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            if obj.is_dynamic():
                # Dynamic interfaces need runtime address resolution
                # For now, skip — nftables doesn't have shell variable substitution
                return ''
            for addr in getattr(obj, 'addresses', []):
                return self._print_addr_basic(addr)
            return ''

        if isinstance(obj, Host):
            for iface in getattr(obj, 'interfaces', []):
                if iface.is_loopback():
                    continue
                for addr in getattr(iface, 'addresses', []):
                    addr_str = addr.get_address()
                    if addr_str:
                        return addr_str
            return ''

        return self._print_addr_basic(obj)

    def _print_addr_basic(self, obj) -> str:
        """Print basic address in CIDR notation."""
        if not isinstance(obj, Address):
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
        if rule._extra.get('merged_tcp_udp'):
            return self._print_merged_tcp_udp_service(rule)

        if srv is None:
            return ''

        if isinstance(srv, TCPService):
            return self._print_tcp_udp_service(rule, srv, 'tcp')
        elif isinstance(srv, UDPService):
            return self._print_tcp_udp_service(rule, srv, 'udp')
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            return self._print_icmp_service(srv)
        elif isinstance(srv, IPService):
            proto = srv.get_protocol_number()
            if proto >= 0:
                return f'meta l4proto {proto}'
        return ''

    def _print_tcp_udp_service(self, rule: CompRule, srv, proto: str) -> str:
        """Print TCP/UDP service matching.

        For multiple services (multiport), nftables uses sets natively:
            tcp dport { 22, 80, 443 }
        """
        parts = []

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
                parts.append(f'{proto} sport {src_ports}')

            if all_dst_ports:
                if len(all_dst_ports) == 1:
                    parts.append(f'{proto} dport {all_dst_ports[0]}')
                else:
                    parts.append(f'{proto} dport {{ {", ".join(all_dst_ports)} }}')
        else:
            dst_ports = self._format_port_range(dst_start, dst_end)

            if src_ports:
                parts.append(f'{proto} sport {src_ports}')
            if dst_ports:
                parts.append(f'{proto} dport {dst_ports}')
            elif not src_ports:
                # Just the protocol, no ports
                parts.append(f'meta l4proto {proto}')

        return ' '.join(parts)

    def _print_merged_tcp_udp_service(self, rule: CompRule) -> str:
        """Print merged TCP+UDP service using transport header (th) matcher.

        Emits: meta l4proto { tcp, udp } th dport 53
        Or:    meta l4proto { tcp, udp } th dport { 53, 80 }
        """
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
                parts.append(f'th sport {src_ports[0]}')
            else:
                parts.append(f'th sport {{ {", ".join(src_ports)} }}')

        if dst_ports:
            if len(dst_ports) == 1:
                parts.append(f'th dport {dst_ports[0]}')
            else:
                parts.append(f'th dport {{ {", ".join(dst_ports)} }}')

        return ' '.join(parts)

    @staticmethod
    def _format_port_range(start: int, end: int) -> str:
        """Format a port range for nftables."""
        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return str(start)
        return f'{start}-{end}'

    def _print_icmp_service(self, srv) -> str:
        """Print ICMP type/code matching."""
        data = srv.data or {}
        icmp_type = int(data.get('type', -1) or -1)
        icmp_code = int(data.get('code', -1) or -1)

        proto = 'icmpv6' if self.compiler and self.compiler.ipv6_policy else 'icmp'

        if icmp_type < 0:
            return f'meta l4proto {proto}'
        if icmp_code < 0:
            return f'{proto} type {icmp_type}'
        return f'{proto} type {icmp_type} code {icmp_code}'

    def _print_state(self, rule: CompRule) -> str:
        """Print connection tracking state matching."""
        stateless = rule.get_option('stateless', False)
        force_state = rule._extra.get('force_state_check', False)

        if not stateless or force_state:
            return 'ct state new'
        return ''

    def _print_log(self, rule: CompRule) -> str:
        """Print log expression.

        In nftables, log is an inline statement, not a separate target.
        It can be combined with a verdict: `log prefix "..." accept`

        Handles two cases:
        - ipt_target == 'LOG': standalone log rule (Continue action)
        - nft_log flag: inline log before verdict (e.g. `log prefix "..." accept`)
        """
        if rule.ipt_target != 'LOG' and not rule._extra.get('nft_log'):
            return ''

        parts = ['log']
        log_prefix = self._get_log_prefix(rule)
        if log_prefix:
            parts.append(f'prefix "{log_prefix}"')
        log_level = rule.get_option('log_level', '')
        if not log_level and self.compiler:
            log_level = self.compiler.fw.get_option('log_level', '')
        if log_level:
            parts.append(f'level {log_level}')
        return ' '.join(parts)

    def _get_log_prefix(self, rule: CompRule) -> str:
        """Get log prefix, expanding macros."""
        log_prefix = rule.get_option('log_prefix', '')
        if not log_prefix and self.compiler:
            log_prefix = self.compiler.fw.get_option('log_prefix', '')
        if not log_prefix:
            return ''

        log_prefix = str(log_prefix)

        action = (rule._extra.get('stored_action', '') or '').upper()
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
        if self.compiler and self.compiler.source_ruleset:
            ruleset_name = self.compiler.source_ruleset.name

        result = log_prefix.replace('%N', pos)
        result = result.replace('%A', action)
        result = result.replace('%I', iface_name)
        result = result.replace('%C', chain)
        result = result.replace('%R', ruleset_name)
        return result[:63]  # nftables limit

    def _print_verdict(self, rule: CompRule) -> str:
        """Print the nftables verdict."""
        target = rule.ipt_target

        # LOG target is printed via _print_log, no separate verdict
        if target == 'LOG':
            return ''

        # Handle iptables target names mapped to nftables verdicts
        verdict_map = {
            'ACCEPT': 'accept',
            'DROP': 'drop',
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
            return f'jump {target}'

        # Fall back to action
        action_map = {
            PolicyAction.Accept: 'accept',
            PolicyAction.Deny: 'drop',
            PolicyAction.Reject: 'reject',
            PolicyAction.Return: 'return',
            PolicyAction.Continue: '',
        }

        verdict = action_map.get(rule.action, '')
        if verdict == 'reject':
            return self._print_reject(rule)
        return verdict

    def _print_reject(self, rule: CompRule) -> str:
        """Print reject with specific type."""
        action_on_reject = rule.get_option('action_on_reject', '')

        if not action_on_reject:
            return 'reject'

        # Map iptables reject types to nftables
        reject_map = {
            'ICMP-unreachable': 'reject with icmp host-unreachable',
            'icmp-host-unreachable': 'reject with icmp host-unreachable',
            'icmp-net-unreachable': 'reject with icmp net-unreachable',
            'icmp-port-unreachable': 'reject with icmp port-unreachable',
            'icmp-proto-unreachable': 'reject with icmp prot-unreachable',
            'icmp-admin-prohibited': 'reject with icmp admin-prohibited',
            'tcp-reset': 'reject with tcp reset',
            'TCP-RST': 'reject with tcp reset',
        }

        return reject_map.get(action_on_reject, 'reject')
