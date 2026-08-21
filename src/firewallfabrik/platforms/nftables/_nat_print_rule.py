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

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.core._options import option_is_true
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
    is_valid_packet_mark,
    is_valid_user_id,
    normalize_mac_address,
    range_to_cidr,
)
from firewallfabrik.platforms.linux._netfilter import (
    check_interface_name,
    get_mac_only_address,
)
from firewallfabrik.platforms.nftables._identifiers import nft_object_name, nft_quote
from firewallfabrik.platforms.nftables._print_rule import (
    OTHER_PROTOCOLS_OPTION,
    indent_comment_block,
    print_fragment_match,
    print_icmp_service,
    print_ip_option_matches,
    print_mark_match,
    print_pair_clause,
    tcp_flags_match_nft,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.nftables._nat_compiler import NATCompiler_nft


# A data-dict value may be a Python bool or the string a data file
# carries, on a line of its own if that is how the file was written.
_is_true = option_is_true


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
        self.reported_long_ifaces: set[str] = set()

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
        if iface_match is None:
            # The reason was reported; without the interface match the rule
            # would translate traffic of every interface.
            return ''
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
        others = rule.get_option(OTHER_PROTOCOLS_OPTION, None)
        osrv = nft_comp.get_first_osrv(rule)
        if others:
            # The second half of a negated service element: every protocol
            # the element does not name.  See
            # `AddOtherProtocolsForNegatedServiceInNAT`.
            if len(others) == 1:
                parts.append(f'meta l4proto != {others[0]}')
            else:
                parts.append(f'meta l4proto != {{ {", ".join(others)} }}')
        elif osrv:
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

        line = '        ' + ' '.join(parts) + '\n'

        # Anything reported about this rule goes into the ruleset next to
        # it, the way the policy printer writes it: a warning that only
        # reaches the compiler output is gone by the time somebody reads
        # the generated file.
        errors = self.compiler.get_errors_for_rule(rule)
        if errors:
            line = indent_comment_block(errors) + line

        return line

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

        An object that carries both - what a host with "MAC address
        matching" expands to - asks for both at once, so the two go into
        one clause, exactly as the policy printer does it.  Rendering them
        as two independent sets would translate for every combination of
        the addresses instead of the pairs that were configured.
        """
        neg = '!= ' if negated else ''
        macs = []
        addrs = []
        pairs = []
        # Which objects gave nothing, recorded as the loop goes.  Asking
        # them afterwards is not possible: `get_address` is defined on
        # Address alone, and an Interface or a Host - the two types whose
        # branches in `_print_addr` answer with an empty string - derive
        # from Base, so the question raises AttributeError in the middle of
        # the diagnostic it was meant to produce.
        gave_nothing: list[str] = []
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
            else:
                gave_nothing.append(getattr(obj, 'name', '') or str(obj))

        parts = []
        if pairs:
            parts.append(print_pair_clause(ip_keyword, ether_keyword, pairs, neg))
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
            if len(gave_nothing) == len(objects):
                # Not a compiler limit: the objects carry no address at all.
                # fwbuilder leaves them out of the ruleset, and a warning
                # says so without failing the compile.
                self.compiler.warning(
                    rule,
                    f'{", ".join(repr(n) for n in gave_nothing)} has no address, '
                    f'so the rule is left out',
                )
            else:
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
        result = ''
        if not self.compiler.single_rule_compile_mode:
            # The fragment the editor shows is the rule and nothing else,
            # which is what the policy printer does with the banner.
            result = f'        # \n        # Rule {label}\n        # \n'
        comment = rule.comment
        if comment:
            for line in comment.split('\n'):
                if line.strip():
                    result += f'        # {line}\n'
        return result

    def _print_interface(self, rule: CompRule) -> str | None:
        """Print interface matching for NAT rules.

        The name goes through ``nft_quote`` for the same reason as in the
        policy print rule: the scanner has no escape inside a quoted string
        (netfilter nftables src/scanner.l), so one quotation mark in an
        interface name would end the string early and take the rest of the
        ruleset with it.
        """
        parts = []

        # A name nftables refuses takes the whole ruleset with it, not just
        # this rule: `expr_evaluate_string` (netfilter nftables
        # src/evaluate.c) errors with "String exceeds maximum length" and
        # `nft -f` throws away the entire batch.  The policy printer has
        # honoured the answer since the check was written; here the return
        # value was dropped, so the name went out anyway.
        for element, keyword, negated in (
            (rule.itf_outb, 'oifname', rule.itf_outb_single_object_negation),
            (rule.itf_inb, 'iifname', rule.itf_inb_single_object_negation),
        ):
            if not element:
                continue
            obj = element[0]
            if not isinstance(obj, Interface) or not obj.name:
                continue
            if obj.is_bridge_port():
                # A bridged packet reaches the ip/inet hooks with the bridge
                # device as its in/out device, not the port it came in on.
                # nftables exposes the port as `meta ibrname` / `meta
                # obrname` alone, which the kernel registers for the bridge
                # family (net/bridge/netfilter/nft_meta_bridge.c) and
                # refuses in an ip table; naming the bridge instead would
                # widen the rule to every port of it.  The policy printer
                # reports the same thing.
                self.compiler.error(
                    rule,
                    f'Rule matches on the bridge port "{obj.name}", which '
                    'nftables cannot see in a NAT table; the rule is left out',
                )
                return None
            if not check_interface_name(
                self.compiler, obj.name, self.reported_long_ifaces
            ):
                return None
            neg = '!= ' if negated else ''
            parts.append(f'{keyword} {neg}{nft_quote(obj.name)}')

        return ' '.join(parts)

    def _print_addr(
        self,
        obj,
        rule: CompRule,
        for_match: bool = True,
        fold_range: bool = True,
    ) -> str:
        """Print an address object in nftables format.

        *for_match* tells the two uses apart.  A match may point at a named
        set, a translation target may not: ``snat to`` takes an address or a
        map, never a plain set reference.

        *fold_range* says whether an address range may be written as the
        prefix covering it.  The caller clears it when a ``:port`` part
        follows; see the address range branch below.
        """
        if for_match and is_run_time_address_table(obj):
            # The addresses live in a file on the firewall, so the rule
            # points at a named set and the script fills that set in at
            # activation time (netfilter nftables doc/sets.txt).  A set is
            # typed, so the two address families need one set each.
            ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
            name = nft_object_name(obj.name) + ('_v6' if ipv6 else '')
            self.compiler.address_tables[name] = (
                get_address_table_source(obj, self.compiler.fw),
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
            name = nft_object_name(obj.name) + ('_v6' if ipv6 else '')
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
                # A range whose bounds fall on a prefix boundary can be
                # written either way and means the same to nftables -- a
                # plain `snat to <prefix>` picks any address out of it, the
                # netmap flag is set only by `snat prefix to`.  But the
                # prefix form cannot carry a port: `snat to 192.0.2.0/24:80`
                # is a syntax error, and nft throws away the whole ruleset
                # over it.  The caller clears fold_range when ports follow.
                if fold_range:
                    cidr = range_to_cidr(start, end)
                    if cidr:
                        return cidr
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            if for_match and obj.is_dynamic():
                # The address is only known on the firewall, so the match
                # points at a named set the script fills from the running
                # interface, the same way the policy rules do.  A translation
                # target cannot use this: DynamicInterfaceInTSrc has already
                # turned that case into a masquerade rule.
                ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
                name = nft_object_name(f'i_{obj.name}') + ('_v6' if ipv6 else '')
                self.compiler.address_tables[name] = (obj.name, ipv6, 'interface')
                return f'@{name}'
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
            # Only the translation target reaches this: the match side is
            # handled above and points at a named set the script fills after
            # the ruleset loads.  A target cannot do that - there is no
            # `snat to @set` - so the name would have to go in literally,
            # and nft resolves it while parsing.  The moment it has a second
            # address, or DNS is not up when the firewall script runs at
            # boot, nft answers "Hostname resolves to multiple addresses" or
            # fails to resolve at all and throws away the **whole** ruleset
            # (netfilter nftables src/datatype.c).  Refusing the rule is the
            # honest answer.
            self.compiler.error(
                rule,
                f'DNS name "{obj.name}" cannot be a NAT translation target: '
                'nftables resolves it while loading the ruleset and refuses '
                'the whole ruleset when it has more than one address; use an '
                'address object instead',
            )
            return ''

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
                    # Same host-mask rule as the policy print rule, and the
                    # same one NATCompiler_PrintRule.cpp applies: a mask
                    # covering a single address is left out, and which mask
                    # that is depends on the address family.
                    if length != net.max_prefixlen:
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
                ip_parts.append(f'meta l4proto {p}')
            data = srv.data or {}
            # The policy printer reads the ToS and the DSCP of an IP
            # service; neither NAT printer does, and neither does
            # fwbuilder's (NATCompiler_PrintRule.cpp, _printIP).  A rule
            # whose command leaves the field out translates traffic the
            # editor does not show, so it is reported rather than passed on.
            if data.get('tos', '') or data.get('dscp', ''):
                self.compiler.error(
                    rule,
                    'the service of this NAT rule matches on the ToS or DSCP '
                    'field, which a NAT rule cannot express; the rule is left '
                    'out',
                )
                return None
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
            if not neg:
                return ' '.join(ip_parts)
            # A negated element means "not (all of these conditions)".  One
            # condition inverts by turning its comparison into `!=`; two
            # would have to be inverted as a disjunction, which one nft rule
            # cannot say.  Putting the `!=` on the protocol and leaving the
            # fragment and option matches positive asks for something else
            # entirely and translates traffic the rule excludes.  The policy
            # printer refuses the same shape in _negate_single_match.
            if len(ip_parts) == 1 and ip_parts[0] == f'meta l4proto {p}':
                return f'meta l4proto != {p}'
            self.compiler.error(
                rule,
                'Negating an IP service with '
                + ('several conditions' if len(ip_parts) > 1 else 'nothing to match on')
                + ' is not supported by the nftables compiler; split it into '
                'one service per condition',
            )
            return None
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
            if not is_valid_packet_mark(tag_code):
                self.compiler.error(
                    rule,
                    f'Tag service "{srv.name}" carries "{tag_code}", which is '
                    'not a packet mark; it takes a number up to 4294967295, '
                    'optionally followed by a slash and a mask. The rule is '
                    'left out',
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
            if not is_valid_user_id(uid):
                self.compiler.error(
                    rule,
                    f'User service "{srv.name}" names "{uid}", which is not a '
                    'user name or id; letters, digits, a dot, a dash and an '
                    'underscore are. The rule is left out',
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

        # A TCP service may inspect the flags, and the NAT printer never
        # wrote them out - neither does fwbuilder's.  The rule then
        # translated every TCP packet between the addresses it names, not
        # the handshake stage it was written for.  The match is legal in a
        # nat chain, so it is emitted rather than reported.
        if isinstance(srv, TCPService):
            flags = tcp_flags_match_nft(srv, bool(neg))
            if flags:
                parts.append(flags)

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

        if rt == NATRuleType.NATBranch:
            # `SplitNATBranchRule` has put the branch chain of this
            # direction into the target.  Falling through to the end of this
            # method instead would answer `accept`, which in a nat chain
            # installs a null binding for the whole connection
            # (net/netfilter/nf_nat_core.c, nf_nat_inet_fn) and makes every
            # NAT rule behind it unreachable.
            if rule.ipt_target:
                return f'jump {rule.ipt_target}'
            self.compiler.error(rule, 'NAT branching rule has no branch chain')
            return ''

        # NETMAP (SNetnat/DNetnat) and REDIRECT take no flags.
        if rt == NATRuleType.Masq:
            # Masquerading takes the address of the outgoing interface but
            # still accepts a source port range, which is how a translation
            # to an address only known at run time keeps its ports (netfilter
            # extensions/libipt_MASQUERADE.txlate: `masquerade to :10-20`).
            # Unlike the iptables MASQUERADE target, which has no such
            # option, nftables can pin a client to the same translated
            # address (netfilter nftables tests/py/ip/masquerade.t:12).
            flags = self._nat_flags(rule)
            ports = self._print_translated_ports(tsrv, src=True)
            if ports:
                return f'masquerade to :{ports}{flags}'
            return f'masquerade{flags}'

        if rt in (NATRuleType.SNetnat, NATRuleType.DNetnat):
            return self._print_netmap_action(
                rule, tsrc if rt is NATRuleType.SNetnat else tdst, rt
            )

        if rt == NATRuleType.SNAT:
            flags = self._nat_flags(rule)
            ports = self._print_translated_ports(tsrv, src=True)
            if tsrc:
                addr = self._print_addr(
                    tsrc, rule, for_match=False, fold_range=not ports
                )
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
                addr = self._print_addr(
                    tdst, rule, for_match=False, fold_range=not ports
                )
                if not addr:
                    # The reason was reported.  Falling through to the
                    # port-only form below would translate the port and
                    # leave the address alone, which is not what the rule
                    # says.
                    self.compiler.error(
                        rule, 'DNAT rule has no translated destination address'
                    )
                    return ''
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
            # `redirect` takes the same trailing flags as the other NAT
            # statements (netfilter nftables src/parser_bison.y,
            # redir_stmt_arg), and REDIRECT_opts carries `random` on the
            # iptables side, so the option is not lost on either platform.
            flags = self._nat_flags(rule)
            ports = self._print_translated_ports(tsrv, src=False)
            if ports:
                return f'redirect to :{ports}{flags}'
            return f'redirect{flags}'

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
    # carries a protocol payload expression or an `meta l4proto` equality.
    # Anything else and `nat_evaluate_transport` (netfilter nftables
    # src/evaluate.c) refuses the port mapping with "transport protocol
    # mapping is only valid after transport protocol match", which costs
    # the whole ruleset.  Each form below was offered to nft 1.1.6:
    #
    # * `tcp dport 80`, `udp dport != 53` - accepted.  A payload expression
    #   pins the protocol whether it is negated or not, because nft injects
    #   the `meta l4proto` dependency for the payload itself.
    # * `meta l4proto 6`, `meta l4proto { tcp, udp }` - accepted.
    # * `meta l4proto != 6` - refused.  The protocol context is carried
    #   forward for an equality only: `relational_expr_pctx_update` runs
    #   for OP_EQ and OP_IMPLICIT, and OP_NEQ falls through past it.
    # * `th dport 80` on its own - refused.  `th` is the generic transport
    #   header and names no protocol; the printer only ever emits it behind
    #   a `meta l4proto { tcp, udp }`, which is what makes that form legal.
    #
    # The keyword has to be the head of its own clause: a bare `\btcp\b`
    # also matches inside a set name such as `@tcp.hosts`.
    _HAS_L4PROTO_RE: ClassVar[re.Pattern] = re.compile(
        r'(?:^|\s)(?:(?:tcp|udp|sctp|dccp|udplite)\s+[sd]port|'
        r'meta\s+l4proto(?!\s+!=))\b'
    )

    def _nat_l4proto_prefix(self, rule: CompRule, existing_parts: list[str]) -> str:
        """Return a `meta l4proto <proto>` match to inject before the action.

        nftables rejects a port mapping such as ``redirect to :53``,
        ``masquerade to :1024-2048`` or ``dnat to 10.0.0.1:80`` unless a
        transport-protocol match precedes it (netfilter nftables
        src/evaluate.c: nat_evaluate_transport, "transport protocol mapping
        is only valid after transport protocol match"; the accepted forms
        are in tests/py/ip/masquerade.t).  Every rule type that can carry a
        translated port therefore has to be listed below, masquerade
        included, and no other: a network translation is written as
        ``snat prefix to``/``dnat prefix to`` and never carries a port -
        NETMAP, its iptables counterpart, has no option but ``--to``
        (netfilter extensions/libipt_NETMAP.c) - so deriving a protocol for
        it would narrow a 1:1 mapping of all traffic to one protocol.
        The port comes from the translated service, which also pins the
        protocol; when the rule's own match carries no tcp/udp/l4proto (for
        example a UserService REDIRECT whose only match is on the owner),
        derive the protocol from the translated service and inject it so the
        ruleset loads.  Mirrors the ``-p tcp`` / ``-p udp`` the iptables
        compiler now emits for the same rules.
        """
        nft_comp = cast('NATCompiler_nft', self.compiler)
        rt = rule.nat_rule_type
        tsrv = nft_comp.get_first_tsrv(rule)
        if rt in (NATRuleType.Masq, NATRuleType.SNAT):
            ports = self._print_translated_ports(tsrv, src=True)
        elif rt in (NATRuleType.Redirect, NATRuleType.DNAT):
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
