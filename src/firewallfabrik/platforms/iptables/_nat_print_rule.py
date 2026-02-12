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
    DNSName,
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
from firewallfabrik.platforms.iptables._nat_compiler import STANDARD_NAT_CHAINS
from firewallfabrik.platforms.iptables._utils import get_interface_var_name

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.iptables._nat_compiler import NATCompiler_ipt


def _version_compare(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""

    def _normalize(v):
        return [int(x) for x in v.split('.') if x.isdigit()]

    parts1 = _normalize(v1) if v1 else [0]
    parts2 = _normalize(v2) if v2 else [0]
    for a, b in zip(parts1, parts2, strict=False):
        if a < b:
            return -1
        if a > b:
            return 1
    if len(parts1) < len(parts2):
        return -1
    if len(parts1) > len(parts2):
        return 1
    return 0


class NATPrintRule(NATRuleProcessor):
    """Generates iptables -t nat shell commands from compiled NAT rules."""

    def __init__(self, name: str = 'generate iptables shell script') -> None:
        super().__init__(name)
        self.init: bool = True
        self.print_once_on_top: bool = True
        self.minus_n_tracker_initialized: bool = False
        self.current_rule_label: str = ''
        self.version: str = ''

    def initialize(self) -> None:
        self.version = self.compiler.fw.version or ''

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
        self.compiler.output.write(cmd)

        return True

    def _build_nat_command(self, rule: CompRule) -> str:
        """Build NAT iptables command."""
        cmd = ''
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        cmd += self._start_rule_line()
        cmd += self._print_chain_direction_and_interface(rule)

        osrv = ipt_comp.get_first_osrv(rule)
        if osrv:
            cmd += self._print_protocol(osrv)

        cmd += self._print_multiport(rule)

        # OSrc
        osrc = ipt_comp.get_first_osrc(rule)
        if osrc:
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
        if odst:
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
        if target_args:
            cmd += target_args

        cmd = cmd.rstrip()
        cmd += self._end_rule_line()
        return cmd

    def _print_target_args(self, rule: CompRule) -> str:
        """Print NAT target-specific arguments."""
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
                parts.append(f'{addr_part}:{ports}')
            elif addr_part:
                parts.append(addr_part)
            if rule.get_option('ipt_nat_random', False):
                parts.append('--random')
            if _version_compare(self.version, '1.4.3') >= 0 and rule.get_option(
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
                parts.append(f'{addr_part}:{ports}')
            elif addr_part:
                parts.append(addr_part)
            if rule.get_option('ipt_nat_random', False):
                parts.append('--random')
            if _version_compare(self.version, '1.4.3') >= 0 and rule.get_option(
                'ipt_nat_persistent', False
            ):
                parts.append('--persistent')
            return ' '.join(parts)

        if rt == NATRuleType.SNetnat and target == 'NETMAP':
            if tsrc:
                return f'--to {self._print_addr(tsrc)}'
            return ''

        if rt == NATRuleType.DNetnat and target == 'NETMAP':
            if tdst:
                return f'--to {self._print_addr(tdst)}'
            return ''

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
        if _version_compare(self.version, '1.4.3') >= 0:
            return f'{self._print_single_object_negation(rule, slot)}{option} {arg} '
        else:
            return f'{option} {self._print_single_object_negation(rule, slot)}{arg} '

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
            opt_wait = '-w ' if _version_compare(self.version, '1.4.20') >= 0 else ''
            ipt_cmd = '$IP6TABLES' if ipt_comp.ipv6_policy else '$IPTABLES'
            result = f'{ipt_cmd} {opt_wait}-t nat -N {chain}\n'
            ipt_comp.minus_n_commands[chain] = True
            return result

        return ''

    def _start_rule_line(self) -> str:
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        ipt_cmd = '$IP6TABLES' if ipt_comp.ipv6_policy else '$IPTABLES'
        opt_wait = '-w ' if _version_compare(self.version, '1.4.20') >= 0 else ''
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

    def _print_protocol(self, srv) -> str:
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
        """Print destination service matching for NAT rules."""
        if rule.is_osrv_any():
            return ''
        srv = rule.osrv[0] if rule.osrv else None
        if srv is None:
            return ''

        if len(rule.osrv) == 1:
            if isinstance(srv, (TCPService, UDPService)):
                ports = self._print_dst_ports(srv)
                if ports:
                    return f'--dport {ports} '
            elif isinstance(srv, (ICMPService, ICMP6Service)):
                icmp = self._print_icmp(srv)
                if icmp:
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
        data = srv.data or {}
        icmp_type = int(data.get('type', -1) or -1)
        if icmp_type < 0:
            return ''
        icmp_code = int(data.get('code', -1) or -1)
        if icmp_code >= 0:
            return f'{icmp_type}/{icmp_code}'
        return str(icmp_type)

    def _print_ip(self, srv) -> str:
        data = srv.data or {}
        parts = []
        if data.get('fragm') or data.get('short_fragm'):
            parts.append('-f')
        options = []
        if data.get('lsrr'):
            options.append('--lsrr')
        if data.get('ssrr'):
            options.append('--ssrr')
        if data.get('rr'):
            options.append('--rr')
        if data.get('ts'):
            options.append('--ts')
        if options:
            parts.append('-m ipv4options')
            parts.extend(options)
        return ' '.join(parts)

    def _print_addr(self, obj, print_mask=True, print_range=False) -> str:
        """Print an address object in iptables format."""
        if print_range and isinstance(obj, AddressRange):
            start = obj.get_start_address()
            end = obj.get_end_address()
            if start and end:
                return f'{start}-{end}'

        if isinstance(obj, Interface):
            if obj.is_dynamic():
                ipv6 = self.compiler.ipv6_policy
                suffix = 'v6' if ipv6 else ''
                var = get_interface_var_name(obj, suffix=suffix)
                return f'${var} '
            for addr in getattr(obj, 'addresses', []):
                addr_str = addr.get_address()
                if addr_str:
                    return addr_str
            return ''

        if isinstance(obj, Host):
            # Resolve Host/Firewall to its first non-loopback address
            for iface in getattr(obj, 'interfaces', []):
                if iface.is_loopback():
                    continue
                for addr in getattr(iface, 'addresses', []):
                    addr_str = addr.get_address()
                    if addr_str:
                        return addr_str
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
