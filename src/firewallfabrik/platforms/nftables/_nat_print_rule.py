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
import re
from typing import TYPE_CHECKING, ClassVar, cast

from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    CustomService,
    DNSName,
    Host,
    ICMP6Service,
    ICMPService,
    Interface,
    IPService,
    NATRuleType,
    Network,
    NetworkIPv6,
    PhysAddress,
    TagService,
    TCPService,
    UDPService,
    UserService,
    get_address_table_source,
    is_run_time_address_table,
    range_to_cidr,
)
from firewallfabrik.platforms.nftables._print_rule import (
    get_mac_only_address,
    nft_set_name,
    print_fragment_match,
    print_icmp_service,
    print_ip_option_matches,
    print_mark_match,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.nftables._nat_compiler import NATCompiler_nft


def _is_true(val) -> bool:
    """Check a data-dict value that may be a Python bool or a string 'True'/'False'."""
    return str(val) == 'True'


def _as_set(values: list[str]) -> str:
    """Render one value as it is, several as an nftables anonymous set."""
    if len(values) == 1:
        return values[0]
    return '{ ' + ', '.join(values) + ' }'


class NATPrintRule_nft(NATRuleProcessor):
    """Generates nftables NAT rule statements from compiled NAT rules."""

    def __init__(self, name: str = 'generate nftables NAT rules') -> None:
        super().__init__(name)
        # Track per-chain: NAT rules go to separate chain blocks, so label
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

        chain = rule.ipt_chain or 'postrouting'

        # Build the rule first: one the compiler cannot express comes back
        # empty, and then not even its label belongs in the ruleset.
        cmd = self._build_nat_rule(rule)
        if not cmd:
            return True

        text = self._print_rule_label(rule, chain) + cmd

        # Write to per-chain collection if available
        nft_comp = cast('NATCompiler_nft', self.compiler)
        if hasattr(nft_comp, 'chain_rules') and chain in nft_comp.chain_rules:
            nft_comp.chain_rules[chain].append(text)
        else:
            nft_comp.output.write(text)

        return True

    def _build_nat_rule(self, rule: CompRule) -> str:
        """Build a complete nftables NAT rule line."""
        parts: list[str] = []
        nft_comp = cast('NATCompiler_nft', self.compiler)

        af_prefix = 'ip6' if nft_comp.ipv6_policy else 'ip'

        # Interface matching
        iface_match = self._print_interface(rule)
        if iface_match:
            parts.append(iface_match)

        # Original source
        osrc_match = self._print_addr_match(
            rule,
            rule.osrc,
            f'{af_prefix} saddr',
            'ether saddr',
            bool(rule.osrc_single_object_negation),
        )
        if osrc_match is None:
            # None of the objects could be rendered and the reason was
            # reported. Emitting the rule without the match would translate
            # every source address, not the ones the rule names.
            return ''
        parts.extend(osrc_match)

        # Original destination
        odst_match = self._print_addr_match(
            rule,
            rule.odst,
            f'{af_prefix} daddr',
            'ether daddr',
            bool(rule.odst_single_object_negation),
        )
        if odst_match is None:
            return ''
        parts.extend(odst_match)

        # Original service
        osrv = nft_comp.get_first_osrv(rule)
        if osrv:
            srv_match = self._print_service(osrv, rule)
            if srv_match is None:
                # The service cannot be expressed and the reason was
                # reported. Translating without it would take every protocol
                # and port, not the one service the rule names.
                return ''
            if srv_match:
                parts.append(srv_match)

        # NAT action, preceded by `counter` to match iptables' implicit
        # per-rule counters (iptables-translate emits `... counter snat to`).
        nat_action = self._print_nat_action(rule)
        if not nat_action:
            # No action means the rule could not be translated and an error
            # was reported.  Emitting the match alone would be a rule that
            # does nothing, so drop it.
            return ''

        l4proto_prefix = self._nat_l4proto_prefix(rule, parts)
        if l4proto_prefix:
            parts.append(l4proto_prefix)
        parts.append('counter')
        parts.append(nat_action)

        return '        ' + ' '.join(parts) + '\n'

    def _print_addr_match(
        self,
        rule: CompRule,
        objects: list,
        ip_keyword: str,
        ether_keyword: str,
        negated: bool,
    ) -> list[str] | None:
        """Render an address element, keeping MAC addresses apart.

        A negated element keeps all of its addresses in one match, because
        "not one of these" only holds when none of them matches; they are
        rendered as an anonymous set.  A MAC address is not part of the IP
        header and needs its own ``ether`` match, which is what
        iptables-translate produces for ``-m mac --mac-source``.
        """
        neg = '!= ' if negated else ''
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
            parts.append(f'{ether_keyword} {neg}{_as_set(macs)}')
        if addrs:
            # A reference to a named set cannot be an element of the
            # anonymous set the other addresses are merged into, so it gets
            # a match of its own.  Two matches in one rule are ANDed, which
            # is what a negated element means; a positive one would need a
            # rule each, which ConvertToAtomicForAddresses provides.
            set_refs = [a for a in addrs if a.startswith('@')]
            plain = [a for a in addrs if not a.startswith('@')]
            parts.extend(f'{ip_keyword} {neg}{ref}' for ref in set_refs)
            if plain:
                parts.append(f'{ip_keyword} {neg}{_as_set(plain)}')
        if objects and not parts:
            what = 'source' if 'saddr' in ip_keyword else 'destination'
            self.compiler.error(
                rule, f'Could not resolve any original {what} addresses'
            )
            return None
        return parts

    def _print_rule_label(self, rule: CompRule, chain: str) -> str:
        """Print rule label as nft comment.

        Tracks labels per chain: one NAT rule can produce a rule in the
        prerouting and one in the postrouting chain, and those go into
        separate chain blocks.  A single counter would print the label
        only in whichever chain came first and file the other rule under
        whatever label that chain saw last.
        """
        label = rule.label
        if not label or label == self._chain_labels.get(chain, ''):
            return ''
        self._chain_labels[chain] = label
        result = f'        # \n        # Rule {label}\n        # \n'
        comment = rule.comment
        if comment:
            for line in comment.split('\n'):
                if line.strip():
                    result += f'        # {line}\n'
        return result

    def _print_interface(self, rule: CompRule) -> str:
        """Print interface matching for NAT rules."""
        parts = []

        # Outbound interface (for SNAT/masquerade)
        if rule.itf_outb:
            obj = rule.itf_outb[0]
            if isinstance(obj, Interface):
                name = obj.name
                if name:
                    neg = '!= ' if rule.itf_outb_single_object_negation else ''
                    parts.append(f'oifname {neg}"{name}"')

        # Inbound interface (for DNAT)
        if rule.itf_inb:
            obj = rule.itf_inb[0]
            if isinstance(obj, Interface):
                name = obj.name
                if name:
                    neg = '!= ' if rule.itf_inb_single_object_negation else ''
                    parts.append(f'iifname {neg}"{name}"')

        return ' '.join(parts)

    def _print_addr(self, obj, rule: CompRule, for_match: bool = True) -> str:
        """Print an address object in nftables format.

        *for_match* tells the two uses apart.  A match may point at a named
        set, a translation target may not: ``snat to`` takes an address or a
        map, never a plain set reference.
        """
        if for_match and is_run_time_address_table(obj):
            # The addresses live in a file on the firewall, so the rule
            # points at a named set and the script fills that set in at
            # activation time (netfilter nftables doc/sets.txt).  A set is
            # typed, so the two address families need one set each.
            ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
            name = nft_set_name(obj.name) + ('_v6' if ipv6 else '')
            self.compiler.address_tables[name] = (
                get_address_table_source(obj),
                ipv6,
                'file',
            )
            return f'@{name}'

        if for_match and isinstance(obj, DNSName):
            # A name is resolved on the firewall, and nft refuses a hostname
            # that resolves to more than one address - it rejects the whole
            # ruleset, not just the rule (netfilter nftables
            # src/datatype.c:647).  So the rule points at a set and the
            # script resolves the name into it after the ruleset is loaded,
            # which is what iptables does when it expands the name into one
            # rule per address.
            ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
            name = nft_set_name(obj.name) + ('_v6' if ipv6 else '')
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
                cidr = range_to_cidr(start, end)
                if cidr:
                    return cidr
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            addr = self._select_af_address(getattr(obj, 'addresses', []))
            if addr is not None:
                return addr.get_address()
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
                    return f'{addr_str}/{length}'
                except ValueError:
                    pass

        return addr_str

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

    def _print_service(self, srv, rule: CompRule) -> str | None:
        """Print service matching for NAT rules.

        Returns ``None`` when the service says something nftables cannot
        express, so the caller leaves the rule out.  A NAT rule without its
        service match translates every protocol and port between the
        addresses it names, not the one service it was written for.
        """
        neg = '!= ' if rule.osrv_single_object_negation else ''

        if isinstance(srv, TCPService):
            proto = 'tcp'
        elif isinstance(srv, UDPService):
            proto = 'udp'
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            # The type and the code belong in the match: without them the
            # rule translates every ICMP packet between the addresses it
            # names, not the message types it was written for.  The
            # iptables NAT print rule emits `--icmp-type type[/code]` here.
            return print_icmp_service(srv, self.compiler.ipv6_policy, bool(neg))
        elif isinstance(srv, IPService):
            ip_parts = []
            p = srv.get_protocol_number()
            # Protocol number 0 is iptables' "all" wildcard, not a protocol;
            # `meta l4proto 0` would match IP protocol 0 and nothing else.
            if p > 0:
                ip_parts.append(f'meta l4proto {neg}{p}')
            data = srv.data or {}
            if _is_true(data.get('fragm')) or _is_true(data.get('short_fragm')):
                ip_parts.append(print_fragment_match(self.compiler.ipv6_policy))
            if not self.compiler.ipv6_policy:
                opt_matches, opt_unsupported = print_ip_option_matches(data)
                ip_parts.extend(opt_matches)
                for name in opt_unsupported:
                    self.compiler.error(
                        rule,
                        f'IP service matching the "{name}" IP option is not '
                        'supported by nftables, which can only match the '
                        'lsrr, ssrr, rr and router-alert options',
                    )
                    return None
            return ' '.join(ip_parts)
        elif isinstance(srv, CustomService):
            nft_comp = cast('NATCompiler_nft', self.compiler)
            code = (srv.codes or {}).get(nft_comp.my_platform_name(), '')
            if not code:
                # VerifyCustomServices already reported the missing code.
                return None
            if neg:
                # The code fragment is opaque nftables text; there is no
                # way to invert it from here, and emitting it unchanged
                # would translate exactly what the rule excludes.
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
            return print_mark_match(tag_code, bool(neg))
        elif isinstance(srv, UserService):
            uid = srv.userid or ''
            if not uid:
                self.compiler.error(
                    rule, f'User service "{srv.name}" names no user to match on'
                )
                return None
            return f'meta skuid {neg}{uid}'
        else:
            self.compiler.error(
                rule,
                f'Service type {type(srv).__name__} not yet'
                f' supported by nftables compiler',
            )
            return None

        parts = []

        # Source ports
        src_start = srv.src_range_start or 0
        src_end = srv.src_range_end or 0
        src_ports = self._format_port_range(src_start, src_end)
        if src_ports:
            parts.append(f'{proto} sport {neg}{src_ports}')

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
                    parts.append(f'{proto} dport {neg}{all_dst_ports[0]}')
                else:
                    parts.append(f'{proto} dport {neg}{{ {", ".join(all_dst_ports)} }}')
        else:
            dst_start = srv.dst_range_start or 0
            dst_end = srv.dst_range_end or 0
            dst_ports = self._format_port_range(dst_start, dst_end)
            if dst_ports:
                parts.append(f'{proto} dport {neg}{dst_ports}')

        if not parts:
            parts.append(f'meta l4proto {neg}{proto}')

        return ' '.join(parts)

    @staticmethod
    def _format_port_range(start: int, end: int) -> str:
        """Format a port range for nftables."""
        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return str(start)
        return f'{start}-{end}'

    @staticmethod
    def _bracket_v6_for_port(addr: str, ipv6: bool) -> str:
        """Wrap an IPv6 NAT target in square brackets before a `:port`.

        nftables (like `[addr]:port` in a URL) needs the IPv6 address
        bracketed so the trailing colon is not read as part of the address:
        `snat to [fec0::1]:80`. A range brackets each endpoint,
        `[start]-[end]:port` (see nftables tests/py/ip6/{snat,dnat}.t).
        IPv4 addresses and bracket-less forms (prefixes) are returned as-is.
        """
        if not ipv6 or ':' not in addr or '/' in addr:
            return addr
        return '-'.join(f'[{part}]' for part in addr.split('-'))

    @staticmethod
    def _nat_flags(rule: CompRule) -> str:
        """Return the trailing nftables NAT flags (` random,persistent`).

        Mirrors the iptables NAT options: `--random` -> `random`,
        `--persistent` -> `persistent`. nftables appends them after the
        action, comma-joined (see iptables-translate output and
        nftables tests/py/*/masquerade.t).
        """
        flags = []
        if rule.get_option('ipt_nat_random', False):
            flags.append('random')
        if rule.get_option('ipt_nat_persistent', False):
            flags.append('persistent')
        return f' {",".join(flags)}' if flags else ''

    def _print_nat_action(self, rule: CompRule) -> str:
        """Print the NAT action (snat/dnat/masquerade/redirect)."""
        rt = rule.nat_rule_type
        nft_comp = cast('NATCompiler_nft', self.compiler)
        tsrc = nft_comp.get_first_tsrc(rule)
        tdst = nft_comp.get_first_tdst(rule)
        tsrv = nft_comp.get_first_tsrv(rule)

        if rt == NATRuleType.NONAT:
            return 'accept'

        # Flags mirror what the iptables compiler emits per rule type:
        # MASQUERADE takes only --random; SNAT/DNAT take --random and
        # --persistent; NETMAP (SNetnat/DNetnat) and REDIRECT take none.
        random_only = ' random' if rule.get_option('ipt_nat_random', False) else ''

        if rt == NATRuleType.Masq:
            # Masquerading takes the address of the outgoing interface but
            # still accepts a source port range, which is how a translation
            # to an address only known at run time keeps its ports (netfilter
            # extensions/libipt_MASQUERADE.txlate: `masquerade to :10-20`).
            ports = self._print_translated_ports(tsrv, src=True)
            if ports:
                return f'masquerade to :{ports}{random_only}'
            return f'masquerade{random_only}'

        if rt in (NATRuleType.SNetnat, NATRuleType.DNetnat):
            return self._print_netmap_action(
                rule, tsrc if rt is NATRuleType.SNetnat else tdst, rt
            )

        if rt == NATRuleType.SNAT:
            flags = self._nat_flags(rule)
            ports = self._print_translated_ports(tsrv, src=True)
            if tsrc:
                addr = self._print_addr(tsrc, rule, for_match=False)
                if not addr:
                    # Masquerading instead would translate the traffic to the
                    # address of whatever interface it leaves by, which is not
                    # what the rule says.  DynamicInterfaceInTSrc has already
                    # turned the one case where that is the right answer into
                    # a masquerade rule.
                    self.compiler.error(
                        rule, 'SNAT rule has no translated source address'
                    )
                    return ''
                if ports:
                    addr = self._bracket_v6_for_port(addr, nft_comp.ipv6_policy)
                    return f'snat to {addr}:{ports}{flags}'
                return f'snat to {addr}{flags}'
            if ports:
                # The rule translates the source port only; the address is
                # left alone, which is `--to-source :port` on iptables.
                return f'snat to :{ports}{flags}'
            self.compiler.error(rule, 'SNAT rule has no translated source address')
            return ''

        if rt == NATRuleType.DNAT:
            if rule.get_option('nft_load_balance'):
                return self._print_load_balance_action(rule, tsrv)
            flags = self._nat_flags(rule)
            ports = self._print_translated_ports(tsrv, src=False)
            if tdst:
                addr = self._print_addr(tdst, rule, for_match=False)
                if addr:
                    if ports:
                        addr = self._bracket_v6_for_port(addr, nft_comp.ipv6_policy)
                        return f'dnat to {addr}:{ports}{flags}'
                    return f'dnat to {addr}{flags}'
            if ports:
                # The rule translates the destination port only; the address
                # is left alone, which is `--to-destination :port` on iptables.
                return f'dnat to :{ports}{flags}'
            self.compiler.error(rule, 'DNAT rule has no translated destination address')
            return ''

        if rt == NATRuleType.Redirect:
            ports = self._print_translated_ports(tsrv, src=False)
            if ports:
                return f'redirect to :{ports}'
            return 'redirect'

        if rt == NATRuleType.SDNAT:
            self.compiler.error(
                rule,
                'Simultaneous SNAT+DNAT (SDNAT) not yet supported by nftables compiler',
            )
            return ''

        if rt == NATRuleType.Return:
            return 'return'

        return 'accept'

    def _print_netmap_action(self, rule: CompRule, target, rt) -> str:
        """Print a 1:1 network translation, the iptables NETMAP target.

        NETMAP keeps the host part of the address and only rewrites the
        network part, so 10.141.11.4 becomes 192.168.2.4. In nftables that
        is the ``prefix`` form: a plain ``snat to 192.168.2.0/24`` carries no
        netmap flag and lets the kernel pick any address out of the range
        instead (netfilter nftables src/parser_bison.y sets
        NF_NAT_RANGE_NETMAP only for ``prefix to``).
        """
        verb = 'snat' if rt is NATRuleType.SNetnat else 'dnat'
        addr = self._print_addr(target, rule, for_match=False) if target else ''
        if not addr:
            side = 'source' if verb == 'snat' else 'destination'
            self.compiler.error(
                rule, f'Network translation rule has no translated {side} network'
            )
            return ''
        return f'{verb} prefix to {addr}'

    def _print_load_balance_action(self, rule: CompRule, tsrv) -> str:
        """Print a load-balanced DNAT action using ``numgen inc mod``.

        Generates nftables syntax like::

            dnat to numgen inc mod 3 map { 0 : 10.0.0.1, 1 : 10.0.0.2, 2 : 10.0.0.3 }

        When a translated service port is specified::

            dnat to numgen inc mod 2 map { 0 : 10.0.0.1 . 8080, 1 : 10.0.0.2 . 8080 }
        """
        backends: list[str] = rule.get_option('nft_lb_backends', [])
        if not backends:
            self.compiler.error(rule, 'Load balancing rule has no backend addresses')
            return ''

        count = len(backends)
        ports = self._print_translated_ports(tsrv, src=False)

        entries = []
        for idx, addr in enumerate(backends):
            if ports:
                entries.append(f'{idx} : {addr} . {ports}')
            else:
                entries.append(f'{idx} : {addr}')

        mapping = ', '.join(entries)
        return f'dnat to numgen inc mod {count} map {{ {mapping} }}'

    # A transport protocol is already constrained when the assembled match
    # carries a tcp/udp/sctp/dccp keyword, an explicit `meta l4proto`, or the
    # merged `th sport`/`th dport` matcher.
    _HAS_L4PROTO_RE: ClassVar[re.Pattern] = re.compile(
        r'\b(?:tcp|udp|sctp|dccp|udplite)\b|l4proto|\bth [sd]port\b'
    )

    def _nat_l4proto_prefix(self, rule: CompRule, existing_parts: list[str]) -> str:
        """Return a `meta l4proto <proto>` match to inject before the action.

        nftables rejects a port mapping such as ``redirect to :53`` or
        ``dnat to 10.0.0.1:80`` unless a transport-protocol match precedes
        it.  The port comes from the translated service, which also pins the
        protocol; when the rule's own match carries no tcp/udp/l4proto (for
        example a UserService REDIRECT whose only match is on the owner),
        derive the protocol from the translated service and inject it so the
        ruleset loads.  Mirrors the ``-p tcp`` / ``-p udp`` the iptables
        compiler now emits for the same rules.
        """
        nft_comp = cast('NATCompiler_nft', self.compiler)
        rt = rule.nat_rule_type
        tsrv = nft_comp.get_first_tsrv(rule)
        if rt in (NATRuleType.SNAT, NATRuleType.SNetnat):
            ports = self._print_translated_ports(tsrv, src=True)
        elif rt in (NATRuleType.Redirect, NATRuleType.DNAT, NATRuleType.DNetnat):
            ports = self._print_translated_ports(tsrv, src=False)
        else:
            ports = ''
        if not ports:
            return ''
        if self._HAS_L4PROTO_RE.search(' '.join(existing_parts)):
            return ''
        if isinstance(tsrv, TCPService):
            return 'meta l4proto tcp'
        if isinstance(tsrv, UDPService):
            return 'meta l4proto udp'
        return ''

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
