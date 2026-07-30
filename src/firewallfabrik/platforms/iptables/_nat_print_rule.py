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

"""NATPrintRule: iptables NAT command generation from compiled CompRules.

Corresponds to the NATPrintRule/NATPrintRuleIptRst/NATPrintRuleIptRstEcho
classes at the bottom of fwbuilder's iptlib/nat_compiler_ipt.py.

Generates iptables -t nat command strings (shell or iptables-restore format).
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, cast

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
    range_to_cidr,
)
from firewallfabrik.platforms.iptables._nat_compiler import STANDARD_NAT_CHAINS
from firewallfabrik.platforms.iptables._utils import (
    check_chain_name,
    get_interface_var_name,
    get_iptables_version,
    get_wait_option,
    version_compare,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.iptables._nat_compiler import NATCompiler_ipt


def _is_true(val) -> bool:
    """Check a data-dict value that may be a Python bool or a string 'True'/'False'."""
    return str(val) == 'True'


def _bracket_v6(addr_part: str) -> str:
    """Wrap an IPv6 NAT target in square brackets before a `:port`.

    iptables' NAT target parser (extensions/libxt_NAT.c: parse_to) treats a
    lone colon as a port separator, so an IPv6 target with a port must be
    bracketed: `--to-source [fec0::1]:80`. A range is wrapped as a whole,
    `[start-end]:port` (the parser splits on the dash inside the brackets).
    IPv4 addresses, which never contain a colon, are returned unchanged.
    """
    if ':' not in addr_part:
        return addr_part
    return f'[{addr_part}]'


class NATPrintRule(NATRuleProcessor):
    """Generates iptables -t nat shell commands from compiled NAT rules."""

    def __init__(self, name: str = 'generate iptables shell script') -> None:
        super().__init__(name)
        self.init: bool = True
        self.print_once_on_top: bool = True
        self.minus_n_tracker_initialized: bool = False
        self.current_rule_label: str = ''
        self.version: str = ''
        self.reported_long_chains: set[str] = set()

    def initialize(self) -> None:
        self.version = get_iptables_version(self.compiler.fw)

    def _initialize_minus_n_tracker(self) -> None:
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
        ):
            for chain in STANDARD_NAT_CHAINS:
                ipt_comp.minus_n_commands[chain] = True
        self.minus_n_tracker_initialized = True

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        chain = rule.ipt_chain
        if ipt_comp.chain_usage_counter.get(chain, 0) == 0:
            return True

        self.tmp_queue.append(rule)

        # Output rule label
        label_str = self._print_rule_label(rule)
        if label_str:
            self.compiler.output.write(label_str)

        # Create chains
        chain_create = self._create_chain(rule.ipt_chain)
        if chain_create:
            self.compiler.output.write(chain_create)
        target_create = self._create_chain(rule.ipt_target)
        if target_create:
            self.compiler.output.write(target_create)

        # Build command
        cmd = self._build_nat_command(rule)
        if cmd:
            self.compiler.output.write(cmd)

        return True

    def _build_nat_command(self, rule: CompRule) -> str:
        """Build NAT iptables command, empty when the rule cannot be expressed."""
        cmd = ''
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        cmd += self._start_rule_line()
        cmd += self._print_chain_direction_and_interface(rule)

        osrv = ipt_comp.get_first_osrv(rule)
        if osrv:
            cmd += self._print_protocol(osrv)

        # A REDIRECT / DNAT / SNAT port mapping requires `-p tcp` or
        # `-p udp`; iptables rejects `--to-ports` / `:port` without it. When
        # the rule's own service carries no protocol (for example a
        # UserService REDIRECT, whose only match is on the owner), take the
        # protocol from the translated service so the rule is valid.
        if '-p ' not in cmd:
            cmd += self._nat_l4proto_option(rule)

        cmd += self._print_multiport(rule)

        # OSrc
        osrc = ipt_comp.get_first_osrc(rule)
        if isinstance(osrc, PhysAddress):
            cmd += self._print_mac_source(osrc, rule)
        elif osrc:
            addr_str = self._print_addr(osrc)
            if addr_str:
                cmd += self._print_single_option_with_negation(
                    ' -s', rule, 'osrc', addr_str
                )

        # Src service
        if osrv:
            cmd += ' '
            cmd += self._print_src_service(rule)

        # ODst
        odst = ipt_comp.get_first_odst(rule)
        if isinstance(odst, PhysAddress):
            # The mac module only matches the source address; iptables has
            # no destination equivalent.
            self.compiler.error(
                rule,
                f'MAC address "{odst.get_address()}" cannot be used as a '
                'destination, iptables can only match the source MAC',
            )
        elif odst:
            addr_str = self._print_addr(odst)
            if addr_str:
                cmd += self._print_single_option_with_negation(
                    ' -d', rule, 'odst', addr_str
                )

        # Dst service
        cmd += ' '
        if osrv:
            cmd += self._print_dst_service(rule)

        # Target
        target = rule.ipt_target
        cmd += f'-j {target} '

        # Target-specific args
        target_args = self._print_target_args(rule)
        if target_args is None:
            # The target cannot be given the argument it insists on, so the
            # command would only make iptables stop the activation script.
            return ''
        if target_args:
            cmd += target_args

        cmd = cmd.rstrip()
        cmd += self._end_rule_line()
        return cmd

    def _print_mac_source(self, obj, rule: CompRule) -> str:
        """Print a MAC address match.

        iptables cannot match a MAC with ``-s``, it needs the mac module
        (fwbuilder does the same in NATCompiler_PrintRule.cpp).
        """
        mac = obj.get_address()
        if not mac:
            self.compiler.warning(rule, 'Empty MAC address in rule')
            mac = '00:00:00:00:00:00'
        neg = self._print_single_option_with_negation(
            ' --mac-source', rule, 'osrc', mac
        )
        return f' -m mac{neg}'

    def _print_target_args(self, rule: CompRule) -> str | None:
        """Print NAT target-specific arguments.

        Returns None when the target needs an argument the rule cannot
        supply.  SNAT, DNAT and NETMAP all refuse to load without one
        ("SNAT: option \"--to-source\" must be specified", netfilter
        extensions/libipt_SNAT.c, libxt_DNAT.c and libipt_NETMAP.c), and a
        rule iptables refuses stops the whole activation script, so the
        caller leaves such a rule out.
        """
        rt = rule.nat_rule_type
        target = rule.ipt_target
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        tsrc = ipt_comp.get_first_tsrc(rule)
        tdst = ipt_comp.get_first_tdst(rule)
        tsrv = ipt_comp.get_first_tsrv(rule)

        if rt == NATRuleType.Masq:
            if rule.get_option('ipt_nat_random', False):
                return '--random'
            return ''

        if rt == NATRuleType.SNAT and target == 'SNAT':
            parts = ['--to-source']
            addr_part = ''
            if tsrc:
                addr_part = self._print_addr(
                    tsrc, print_mask=False, print_range=True
                ).strip()
            ports = self._print_snat_ports(tsrv) if tsrv else ''
            if ports:
                parts.append(f'{_bracket_v6(addr_part)}:{ports}')
            elif addr_part:
                parts.append(addr_part)
            else:
                # `--to-source` without an argument is refused by iptables and
                # stops the activation script, so report the rule instead.
                self.compiler.error(rule, 'SNAT rule has no translated source address')
                return None
            if rule.get_option('ipt_nat_random', False):
                parts.append('--random')
            if version_compare(self.version, '1.4.3') >= 0 and rule.get_option(
                'ipt_nat_persistent', False
            ):
                parts.append('--persistent')
            return ' '.join(parts)

        if rt == NATRuleType.DNAT and target == 'DNAT':
            parts = ['--to-destination']
            addr_part = ''
            if tdst:
                addr_part = self._print_addr(
                    tdst, print_mask=False, print_range=True
                ).strip()
            ports = self._print_dnat_ports(tsrv) if tsrv else ''
            if ports:
                parts.append(f'{_bracket_v6(addr_part)}:{ports}')
            elif addr_part:
                parts.append(addr_part)
            else:
                self.compiler.error(
                    rule, 'DNAT rule has no translated destination address'
                )
                return None
            if rule.get_option('ipt_nat_random', False):
                parts.append('--random')
            if version_compare(self.version, '1.4.3') >= 0 and rule.get_option(
                'ipt_nat_persistent', False
            ):
                parts.append('--persistent')
            return ' '.join(parts)

        if target == 'NETMAP' and rt in (NATRuleType.SNetnat, NATRuleType.DNetnat):
            netmap_to = tsrc if rt == NATRuleType.SNetnat else tdst
            addr_part = self._print_addr(netmap_to).strip() if netmap_to else ''
            if addr_part:
                return f'--to {addr_part}'
            side = 'source' if rt == NATRuleType.SNetnat else 'destination'
            self.compiler.error(
                rule, f'Network translation rule has no translated {side} network'
            )
            return None

        if rt == NATRuleType.Redirect and target == 'REDIRECT':
            ports = self._print_dnat_ports(tsrv) if tsrv else ''
            if ports:
                return f'--to-ports {ports}'
            return ''

        return ''

    # -- Helpers --

    def _print_single_object_negation(self, rule: CompRule, slot: str) -> str:
        if getattr(rule, f'{slot}_single_object_negation'):
            return '! '
        return ''

    def _print_single_option_with_negation(
        self, option: str, rule: CompRule, slot: str, arg: str
    ) -> str:
        if version_compare(self.version, '1.4.3') >= 0:
            return f'{self._print_single_object_negation(rule, slot)}{option} {arg} '
        else:
            return f'{option} {self._print_single_object_negation(rule, slot)}{arg} '

    def _create_chain(self, chain: str) -> str:
        if not chain:
            return ''
        check_chain_name(self.compiler, chain, self.reported_long_chains)
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        if not self.minus_n_tracker_initialized:
            self._initialize_minus_n_tracker()

        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            opt_wait = get_wait_option(self.version)
            if opt_wait:
                opt_wait += ' '
            ipt_cmd = '$IP6TABLES' if ipt_comp.ipv6_policy else '$IPTABLES'
            result = f'{ipt_cmd} {opt_wait}-t nat -N {chain}\n'
            ipt_comp.minus_n_commands[chain] = True
            return result

        return ''

    def _start_rule_line(self) -> str:
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        ipt_cmd = '$IP6TABLES' if ipt_comp.ipv6_policy else '$IPTABLES'
        opt_wait = get_wait_option(self.version)
        if opt_wait:
            opt_wait += ' '
        return f'{ipt_cmd} {opt_wait}-t nat -A '

    def _end_rule_line(self) -> str:
        return '\n'

    def _print_rule_label(self, rule: CompRule) -> str:
        label = rule.label
        if label and label != self.current_rule_label:
            self.current_rule_label = label
            result = f'# \n# Rule {label}\n# \n'
            result += f'echo "Rule {label}"\n'
            result += '# \n'
            comment = rule.comment
            if comment:
                for line in comment.split('\n'):
                    if line.strip():
                        result += f'# {line}\n'
            return result
        return ''

    def _print_chain_direction_and_interface(self, rule: CompRule) -> str:
        parts = []

        iface_in_name = self._get_interface_name(rule.itf_inb)
        iface_out_name = self._get_interface_name(rule.itf_outb)

        if rule.nat_iface_in == 'nil':
            iface_in_name = ''
        if rule.nat_iface_out == 'nil':
            iface_out_name = ''

        parts.append(rule.ipt_chain)

        if iface_in_name:
            parts.append(
                self._print_single_option_with_negation(
                    '-i', rule, 'itf_inb', iface_in_name
                )
            )
        if iface_out_name:
            parts.append(
                self._print_single_option_with_negation(
                    '-o', rule, 'itf_outb', iface_out_name
                )
            )

        parts.append('')
        return ' '.join(parts)

    def _get_interface_name(self, itf_list: list) -> str:
        if not itf_list:
            return ''
        obj = itf_list[0]
        if not isinstance(obj, Interface):
            return ''
        name = obj.name or ''
        if name.endswith('*'):
            name = name[:-1] + '+'
        return name

    def _nat_l4proto_option(self, rule: CompRule) -> str:
        """Return `-p tcp `/`-p udp ` for a port mapping that lacks a protocol.

        REDIRECT (`--to-ports`), and DNAT/SNAT that translate a port, need an
        explicit protocol; the port comes from the translated service, which
        also pins the protocol. Mirrors the `meta l4proto` the nftables
        compiler injects for the same rules.
        """
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        rt = rule.nat_rule_type
        tsrv = ipt_comp.get_first_tsrv(rule)
        if rt in (NATRuleType.SNAT, NATRuleType.SNetnat):
            has_port = bool(self._print_snat_ports(tsrv)) if tsrv else False
        elif rt in (NATRuleType.Redirect, NATRuleType.DNAT, NATRuleType.DNetnat):
            has_port = bool(self._print_dnat_ports(tsrv)) if tsrv else False
        else:
            has_port = False
        if not has_port:
            return ''
        if isinstance(tsrv, TCPService):
            return '-p tcp -m tcp '
        if isinstance(tsrv, UDPService):
            return '-p udp -m udp '
        return ''

    def _print_protocol(self, srv) -> str:
        if isinstance(srv, CustomService):
            ipt_comp = cast('NATCompiler_ipt', self.compiler)
            code = (srv.codes or {}).get(ipt_comp.my_platform_name(), '')
            if '-p ' in code:
                return ''
            proto = srv.get_protocol_name()
            if not proto or proto == 'any':
                return ''
            # The code fragment of a custom service may use a match that
            # needs the protocol declared first, "-m tcp --tcp-flags" for
            # example.  The service carries the protocol, so emit it.
            res = f'-p {proto} '
            if proto in ('tcp', 'udp'):
                res += f'-m {proto} '
            return res
        if isinstance(srv, (TagService, UserService)):
            return ''
        if isinstance(srv, TCPService):
            return '-p tcp -m tcp '
        elif isinstance(srv, UDPService):
            return '-p udp -m udp '
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            if self.compiler.ipv6_policy:
                return '-p ipv6-icmp '
            return '-p icmp -m icmp '
        elif isinstance(srv, IPService):
            proto = srv.get_protocol_number()
            if proto >= 0:
                return f'-p {proto} '
        return ''

    def _print_multiport(self, rule: CompRule) -> str:
        if rule.ipt_multiport:
            return '-m multiport '
        return ''

    def _print_src_service(self, rule: CompRule) -> str:
        """Print source service matching for NAT rules."""
        if rule.is_osrv_any():
            return ''
        srv = rule.osrv[0] if rule.osrv else None
        if srv is None:
            return ''

        if len(rule.osrv) == 1:
            if isinstance(srv, (TCPService, UDPService)):
                ports = self._print_src_ports(srv)
                if ports:
                    return f'--sport {ports} '
        else:
            port_strs = []
            for s in rule.osrv:
                if isinstance(s, (TCPService, UDPService)):
                    p = self._print_src_ports(s)
                    if p:
                        port_strs.append(p)
            if port_strs:
                return f'--sports {",".join(port_strs)} '
        return ''

    def _print_dst_service(self, rule: CompRule) -> str:
        """Print destination service matching for NAT rules.

        Handles CustomService, TagService and UserService in addition
        to the standard TCP/UDP/ICMP/IP types (matching fwbuilder's
        NATCompiler_PrintRule::_printDestinationPort).
        """
        if rule.is_osrv_any():
            return ''
        srv = rule.osrv[0] if rule.osrv else None
        if srv is None:
            return ''

        if isinstance(srv, CustomService):
            ipt_comp = cast('NATCompiler_ipt', self.compiler)
            code = (srv.codes or {}).get(ipt_comp.my_platform_name(), '')
            if code:
                return f'{code} '
            return ''

        if isinstance(srv, TagService):
            tag_code = srv.get_code()
            if tag_code:
                return f'-m mark --mark {tag_code} '
            return ''

        if isinstance(srv, UserService):
            uid = srv.userid or ''
            if uid:
                return f'-m owner --uid-owner {uid} '
            return ''

        if len(rule.osrv) == 1:
            if isinstance(srv, (TCPService, UDPService)):
                ports = self._print_dst_ports(srv)
                if ports:
                    return f'--dport {ports} '
            elif isinstance(srv, (ICMPService, ICMP6Service)):
                icmp = self._print_icmp(srv)
                if icmp:
                    if self.compiler.ipv6_policy:
                        # ip6tables matches ICMPv6 types via the `icmp6`
                        # module and `--icmpv6-type`; `--icmp-type` is IPv4
                        # only and is rejected by ip6tables. Mirrors the
                        # policy print rule (`-p ipv6-icmp -m icmp6 ...`).
                        return f'-m icmp6 --icmpv6-type {icmp} '
                    return f'--icmp-type {icmp} '
            elif isinstance(srv, IPService):
                ip_str = self._print_ip(srv)
                if ip_str:
                    return f'{ip_str} '
        else:
            port_strs = []
            for s in rule.osrv:
                if isinstance(s, (TCPService, UDPService)):
                    p = self._print_dst_ports(s)
                    if p:
                        port_strs.append(p)
            if port_strs:
                return f'--dports {",".join(port_strs)} '
        return ''

    def _print_src_ports(self, srv) -> str:
        rs = srv.src_range_start or 0
        re_ = srv.src_range_end or 0
        return self._print_o_ports(rs, re_)

    def _print_dst_ports(self, srv) -> str:
        rs = srv.dst_range_start or 0
        re_ = srv.dst_range_end or 0
        return self._print_o_ports(rs, re_)

    def _print_snat_ports(self, srv) -> str:
        if not isinstance(srv, (TCPService, UDPService)):
            return ''
        rs = srv.src_range_start or 0
        re_ = srv.src_range_end or 0
        return self._print_t_ports(rs, re_)

    def _print_dnat_ports(self, srv) -> str:
        if not isinstance(srv, (TCPService, UDPService)):
            return ''
        rs = srv.dst_range_start or 0
        re_ = srv.dst_range_end or 0
        return self._print_t_ports(rs, re_)

    @staticmethod
    def _print_o_ports(rs: int, re_: int) -> str:
        if rs < 0:
            rs = 0
        if re_ < 0:
            re_ = 0
        if rs > 0 or re_ > 0:
            if rs == re_:
                return str(rs)
            if rs == 0 and re_ != 0:
                return f':{re_}'
            return f'{rs}:{re_}'
        return ''

    @staticmethod
    def _print_t_ports(rs: int, re_: int) -> str:
        """Print translated ports (uses '-' separator instead of ':')."""
        if rs < 0:
            rs = 0
        if re_ < 0:
            re_ = 0
        if rs > 0 or re_ > 0:
            if rs == re_:
                return str(rs)
            if rs == 0 and re_ != 0:
                return f'-{re_}'
            return f'{rs}-{re_}'
        return ''

    def _print_icmp(self, srv) -> str:
        codes = getattr(srv, 'codes', None) or srv.data or {}
        raw_type = codes.get('type', -1)
        raw_code = codes.get('code', -1)
        icmp_type = -1 if raw_type is None else int(raw_type)
        icmp_code = -1 if raw_code is None else int(raw_code)
        if icmp_type < 0:
            return ''
        if icmp_code >= 0:
            return f'{icmp_type}/{icmp_code}'
        return str(icmp_type)

    def _print_ip(self, srv) -> str:
        """Print IPService fragment and IP option matching for NAT rules.

        Matches fwbuilder PolicyCompiler_PrintRule::_printIP().
        """
        data = srv.data or {}
        parts = []
        if _is_true(data.get('fragm')) or _is_true(data.get('short_fragm')):
            parts.append('-f')
        if _is_true(data.get('any_opt')):
            if version_compare(self.version, '1.4.3') >= 0:
                parts.append('-m ipv4options --any')
            else:
                parts.append('-m ipv4options --any-opt')
        elif version_compare(self.version, '1.4.3') >= 0:
            options = []
            if _is_true(data.get('lsrr')):
                options.append('lsrr')
            if _is_true(data.get('ssrr')):
                options.append('ssrr')
            if _is_true(data.get('rr')):
                options.append('record-route')
            if _is_true(data.get('ts')):
                options.append('timestamp')
            if _is_true(data.get('rtralt')):
                options.append('router-alert')
            if options:
                parts.append(f'-m ipv4options --flags {",".join(options)}')
        else:
            options = []
            if _is_true(data.get('lsrr')):
                options.append('--lsrr')
            if _is_true(data.get('ssrr')):
                options.append('--ssrr')
            if _is_true(data.get('rr')):
                options.append('--rr')
            if _is_true(data.get('ts')):
                options.append('--ts')
            if _is_true(data.get('rtralt')):
                options.append('--ra')
            if options:
                parts.append('-m ipv4options ' + ' '.join(options))
        return ' '.join(parts)

    def _print_addr(self, obj, print_mask=True, print_range=False) -> str:
        """Print an address object in iptables format."""
        if isinstance(obj, AddressRange):
            start = obj.get_start_address()
            end = obj.get_end_address()
            if start and end:
                # NAT target (--to-source / --to-destination) only
                # accepts "ipaddr-ipaddr" syntax, not CIDR.
                if print_range:
                    return f'{start}-{end}'
                # NAT match (-s / -d): prefer the short CIDR form when
                # the range covers an exact subnet, otherwise fall
                # back to "ipaddr-ipaddr" so the caller can wrap it
                # in "-m iprange --src-range/--dst-range".
                if start == end:
                    return start
                cidr = range_to_cidr(start, end)
                if cidr:
                    return cidr
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            if obj.is_dynamic():
                ipv6 = self.compiler.ipv6_policy
                suffix = 'v6' if ipv6 else ''
                var = get_interface_var_name(obj, suffix=suffix)
                return f'${var} '
            addr = self._select_af_address(getattr(obj, 'addresses', []))
            if addr is not None:
                return addr.get_address()
            return ''

        if isinstance(obj, Host):
            # Resolve Host/Firewall to its non-loopback address matching the
            # active family (dual-stack hosts carry both).
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
            return ''

        if isinstance(obj, DNSName):
            # Runtime DNSName — use the DNS record directly as address
            return f'{(obj.data or {}).get("dnsrec", obj.name)} '

        if not isinstance(obj, Address):
            return ''

        addr_str = obj.get_address()
        if not addr_str:
            return ''

        if print_mask and isinstance(obj, (Network, NetworkIPv6)):
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

    def _declare_table(self) -> str:
        return ''

    def _commit(self) -> str:
        return ''

    def _quote(self, s: str) -> str:
        return f'"{s}"'


class NATPrintRuleIptRst(NATPrintRule):
    """NAT rules in iptables-restore format."""

    def _create_chain(self, chain: str) -> str:
        if not chain:
            return ''
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        if not self.minus_n_tracker_initialized:
            self._initialize_minus_n_tracker()

        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            if not self.compiler.single_rule_compile_mode:
                result = f':{chain} - [0:0]\n'
            else:
                result = ''
            ipt_comp.minus_n_commands[chain] = True
            return result

        return ''

    def _start_rule_line(self) -> str:
        return '-A '

    def _end_rule_line(self) -> str:
        return '\n'

    def _print_rule_label(self, rule: CompRule) -> str:
        label = rule.label
        if label and label != self.current_rule_label:
            self.current_rule_label = label
            return f'# Rule {label}\n'
        return ''

    def process_next(self) -> bool:
        if self.print_once_on_top:
            self.print_once_on_top = False
        return super().process_next()

    def _declare_table(self) -> str:
        return '*nat\n'

    def _commit(self) -> str:
        return 'COMMIT\n'

    def _quote(self, s: str) -> str:
        return f'"{s}"'


class NATPrintRuleIptRstEcho(NATPrintRuleIptRst):
    """NAT rules in iptables-restore format using echo (for variables)."""

    def _create_chain(self, chain: str) -> str:
        if not chain:
            return ''
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        if not self.minus_n_tracker_initialized:
            self._initialize_minus_n_tracker()

        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            if not self.compiler.single_rule_compile_mode:
                result = f'echo ":{chain} - [0:0]"\n'
            else:
                result = ''
            ipt_comp.minus_n_commands[chain] = True
            return result

        return ''

    def _start_rule_line(self) -> str:
        return 'echo "-A '

    def _end_rule_line(self) -> str:
        return '"\n'

    def process_next(self) -> bool:
        if self.print_once_on_top:
            self.print_once_on_top = False
        return super().process_next()

    def _declare_table(self) -> str:
        return "echo '*nat'\n"

    def _commit(self) -> str:
        return 'echo COMMIT\n'

    def _quote(self, s: str) -> str:
        return f'\\"{s}\\"'
