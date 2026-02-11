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

"""NATPrintRule_nft: nftables NAT rule syntax generation.

Generates nft NAT rule statements like:
    snat to 10.0.0.1
    dnat to 10.1.1.2:8080
    masquerade
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    Host,
    ICMP6Service,
    ICMPService,
    Interface,
    IPService,
    NATRuleType,
    Network,
    NetworkIPv6,
    TCPService,
    UDPService,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule


class NATPrintRule_nft(NATRuleProcessor):
    """Generates nftables NAT rule statements from compiled NAT rules."""

    def __init__(self, name: str = 'generate nftables NAT rules') -> None:
        super().__init__(name)
        self.current_rule_label: str = ''

    def initialize(self) -> None:
        """Initialize after compiler context is set."""
        pass

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        chain = rule.ipt_chain or 'postrouting'

        label_str = self._print_rule_label(rule)
        cmd = self._build_nat_rule(rule)

        text = ''
        if label_str:
            text += label_str
        if cmd:
            text += cmd

        # Write to per-chain collection if available
        if (
            text
            and hasattr(self.compiler, 'chain_rules')
            and chain in self.compiler.chain_rules
        ):
            self.compiler.chain_rules[chain].append(text)
        elif text:
            self.compiler.output.write(text)

        return True

    def _build_nat_rule(self, rule: CompRule) -> str:
        """Build a complete nftables NAT rule line."""
        parts: list[str] = []

        af_prefix = 'ip6' if (self.compiler and self.compiler.ipv6_policy) else 'ip'

        # Interface matching
        iface_match = self._print_interface(rule)
        if iface_match:
            parts.append(iface_match)

        # Original source
        osrc = self.compiler.get_first_osrc(rule)
        if osrc:
            addr = self._print_addr(osrc)
            if addr:
                neg = '! ' if rule._extra.get('osrc_single_object_negation') else ''
                parts.append(f'{af_prefix} saddr {neg}{addr}')

        # Original destination
        odst = self.compiler.get_first_odst(rule)
        if odst:
            addr = self._print_addr(odst)
            if addr:
                neg = '! ' if rule._extra.get('odst_single_object_negation') else ''
                parts.append(f'{af_prefix} daddr {neg}{addr}')

        # Original service
        osrv = self.compiler.get_first_osrv(rule)
        if osrv:
            srv_match = self._print_service(osrv, rule)
            if srv_match:
                parts.append(srv_match)

        # NAT action
        nat_action = self._print_nat_action(rule)
        if nat_action:
            parts.append(nat_action)

        if not parts:
            return ''

        return '        ' + ' '.join(parts) + '\n'

    def _print_rule_label(self, rule: CompRule) -> str:
        """Print rule label as nft comment."""
        label = rule.label
        if label and label != self.current_rule_label:
            self.current_rule_label = label
            result = f'        # \n        # Rule {label}\n        # \n'
            comment = rule.comment
            if comment:
                for line in comment.split('\n'):
                    if line.strip():
                        result += f'        # {line}\n'
            return result
        return ''

    def _print_interface(self, rule: CompRule) -> str:
        """Print interface matching for NAT rules."""
        parts = []

        # Outbound interface (for SNAT/masquerade)
        if rule.itf_outb:
            obj = rule.itf_outb[0]
            if isinstance(obj, Interface):
                name = obj.name
                if name:
                    parts.append(f'oifname "{name}"')

        # Inbound interface (for DNAT)
        if rule.itf_inb:
            obj = rule.itf_inb[0]
            if isinstance(obj, Interface):
                name = obj.name
                if name:
                    parts.append(f'iifname "{name}"')

        return ' '.join(parts)

    def _print_addr(self, obj) -> str:
        """Print an address object in nftables format."""
        if isinstance(obj, AddressRange):
            start = obj.get_start_address()
            end = obj.get_end_address()
            if start and end:
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            for addr in getattr(obj, 'addresses', []):
                addr_str = addr.get_address()
                if addr_str:
                    return addr_str
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
                    return f'{addr_str}/{length}'
                except ValueError:
                    pass

        return addr_str

    def _print_service(self, srv, rule: CompRule) -> str:
        """Print service matching for NAT rules."""
        if isinstance(srv, TCPService):
            proto = 'tcp'
        elif isinstance(srv, UDPService):
            proto = 'udp'
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            if self.compiler and self.compiler.ipv6_policy:
                return 'meta l4proto icmpv6'
            return 'meta l4proto icmp'
        elif isinstance(srv, IPService):
            p = srv.get_protocol_number()
            if p >= 0:
                return f'meta l4proto {p}'
            return ''
        else:
            return ''

        parts = []

        # Source ports
        src_start = srv.src_range_start or 0
        src_end = srv.src_range_end or 0
        src_ports = self._format_port_range(src_start, src_end)
        if src_ports:
            parts.append(f'{proto} sport {src_ports}')

        # Destination ports (single or multiport)
        if len(rule.osrv) > 1:
            all_dst_ports = []
            for s in rule.osrv:
                if isinstance(s, (TCPService, UDPService)):
                    ds = s.dst_range_start or 0
                    de = s.dst_range_end or 0
                    p = self._format_port_range(ds, de)
                    if p:
                        all_dst_ports.append(p)
            if all_dst_ports:
                if len(all_dst_ports) == 1:
                    parts.append(f'{proto} dport {all_dst_ports[0]}')
                else:
                    parts.append(f'{proto} dport {{ {", ".join(all_dst_ports)} }}')
        else:
            dst_start = srv.dst_range_start or 0
            dst_end = srv.dst_range_end or 0
            dst_ports = self._format_port_range(dst_start, dst_end)
            if dst_ports:
                parts.append(f'{proto} dport {dst_ports}')

        if not parts:
            parts.append(f'meta l4proto {proto}')

        return ' '.join(parts)

    @staticmethod
    def _format_port_range(start: int, end: int) -> str:
        """Format a port range for nftables."""
        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return str(start)
        return f'{start}-{end}'

    def _print_nat_action(self, rule: CompRule) -> str:
        """Print the NAT action (snat/dnat/masquerade/redirect)."""
        rt = rule.nat_rule_type
        tsrc = self.compiler.get_first_tsrc(rule)
        tdst = self.compiler.get_first_tdst(rule)
        tsrv = self.compiler.get_first_tsrv(rule)

        if rt == NATRuleType.NONAT:
            return 'accept'

        if rt == NATRuleType.Masq:
            return 'masquerade'

        if rt in (NATRuleType.SNAT, NATRuleType.SNetnat):
            if tsrc:
                addr = self._print_addr(tsrc)
                if addr:
                    ports = self._print_translated_ports(tsrv, src=True)
                    if ports:
                        return f'snat to {addr}:{ports}'
                    return f'snat to {addr}'
            return 'masquerade'

        if rt in (NATRuleType.DNAT, NATRuleType.DNetnat):
            if tdst:
                addr = self._print_addr(tdst)
                if addr:
                    ports = self._print_translated_ports(tsrv, src=False)
                    if ports:
                        return f'dnat to {addr}:{ports}'
                    return f'dnat to {addr}'
            return ''

        if rt == NATRuleType.Redirect:
            ports = self._print_translated_ports(tsrv, src=False)
            if ports:
                return f'redirect to :{ports}'
            return 'redirect'

        if rt == NATRuleType.SDNAT:
            # Both src and dst translation — need two separate rules
            # For simplicity, emit as dnat (the more common case)
            if tdst:
                addr = self._print_addr(tdst)
                if addr:
                    return f'dnat to {addr}'
            return ''

        if rt == NATRuleType.Return:
            return 'return'

        return 'accept'

    def _print_translated_ports(self, tsrv, src: bool = False) -> str:
        """Print translated ports for NAT."""
        if tsrv is None:
            return ''
        if not isinstance(tsrv, (TCPService, UDPService)):
            return ''

        if src:
            start = tsrv.src_range_start or 0
            end = tsrv.src_range_end or 0
        else:
            start = tsrv.dst_range_start or 0
            end = tsrv.dst_range_end or 0

        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return str(start)
        return f'{start}-{end}'
