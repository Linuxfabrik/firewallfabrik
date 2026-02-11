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

"""PrintRule: iptables command generation from compiled CompRules.

Corresponds to fwbuilder's iptlib/print_rule.py.
Generates iptables command strings (shell or iptables-restore format).
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core.objects import (
    Address,
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
from firewallfabrik.platforms.iptables._combined_address import CombinedAddress
from firewallfabrik.platforms.iptables._utils import get_interface_var_name

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule


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


class PrintRule(PolicyRuleProcessor):
    """Generates iptables shell commands from compiled policy rules.

    This is the final processor in the pipeline that converts the
    internal CompRule representation to iptables command strings.
    """

    def __init__(self, name: str = 'generate iptables shell script') -> None:
        super().__init__(name)
        self.minus_n_tracker_initialized: bool = False
        self.have_m_iprange: bool = False
        self.current_rule_label: str = ''
        self.version: str = ''

    def initialize(self) -> None:
        """Initialize after compiler context is set."""
        if self.compiler:
            self.version = self.compiler.fw.version or ''
            self.have_m_iprange = _version_compare(self.version, '1.2.11') >= 0

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        chain = rule.ipt_chain
        ipt_comp = self.compiler
        if ipt_comp.chain_usage_counter.get(chain, 0) > 0:
            self.tmp_queue.append(rule)

            self.compiler.output.write(self._print_rule_label(rule))
            self.compiler.output.write(self._create_chain(rule.ipt_chain))

            target = rule.ipt_target
            if target and not target.startswith('.'):
                self.compiler.output.write(self._create_chain(target))

            cmd = self._build_rule_command(rule)
            self.compiler.output.write(cmd)
        else:
            self.tmp_queue.append(rule)

        return True

    def policy_rule_to_string(self, rule: CompRule) -> str:
        """Generate rule string for dedup (used by Optimize3)."""
        return self._build_rule_command(rule)

    def _build_rule_command(self, rule: CompRule) -> str:
        """Build the actual iptables command line."""
        command_line = ''

        command_line += self._start_rule_line()
        command_line += self._print_chain(rule)
        command_line += self._print_direction_and_interface(rule)

        srv = self._get_first_srv(rule)
        if srv:
            command_line += self._print_protocol(srv)

        command_line += self._print_multiport(rule)
        command_line += self._print_src_addr_from_rule(rule)
        command_line += self._print_dst_addr_from_rule(rule)
        command_line += self._print_src_service_from_rule(rule)
        command_line += self._print_dst_service_from_rule(rule)

        if srv:
            command_line += self._print_ip_service_options(rule, srv)

        command_line += self._print_modules(rule, command_line)
        command_line += self._print_time_interval(rule)
        command_line += self._print_limit(rule)
        command_line += self._print_target(rule)

        target = rule.ipt_target
        if target in ('LOG', 'ULOG', 'NFLOG'):
            log_params = self._print_log_parameters(rule)
            if log_params:
                command_line += '  ' + log_params

        command_line += self._end_rule_line()
        return command_line

    def _get_first_srv(self, rule: CompRule):
        """Get the first service object from the rule."""
        if rule.is_srv_any():
            return None
        return rule.srv[0] if rule.srv else None

    # -- Negation helpers --

    def _print_single_object_negation(self, rule: CompRule, slot: str) -> str:
        if rule._extra.get(f'{slot}_single_object_negation'):
            return '! '
        return ''

    def _print_single_option_with_negation(
        self, option: str, rule: CompRule, slot: str, arg: str
    ) -> str:
        """Print --option with negation, respecting iptables version."""
        if _version_compare(self.version, '1.4.3') >= 0:
            return f'{self._print_single_object_negation(rule, slot)}{option} {arg} '
        else:
            return f'{option} {self._print_single_object_negation(rule, slot)}{arg} '

    # -- Chain management --

    def initialize_minus_n_tracker(self) -> None:
        """Mark standard chains as already existing."""
        if self.compiler is None:
            return
        ipt_comp = self.compiler
        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
        ):
            for chain in ipt_comp.get_standard_chains():
                ipt_comp.minus_n_commands[chain] = True
        self.minus_n_tracker_initialized = True

    def _create_chain(self, chain: str) -> str:
        """Generate chain creation command if needed."""
        if not chain:
            return ''

        ipt_comp = self.compiler
        if ipt_comp is None:
            return ''

        if not self.minus_n_tracker_initialized:
            self.initialize_minus_n_tracker()

        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            ipv6 = ipt_comp.ipv6_policy
            iptables_cmd = '$IP6TABLES' if ipv6 else '$IPTABLES'

            opt_wait = ''
            if _version_compare(self.version, '1.4.20') >= 0:
                opt_wait = '-w '

            result = f'{iptables_cmd} {opt_wait}-N {chain}'

            my_table = getattr(ipt_comp, 'my_table', 'filter')
            if my_table != 'filter':
                result += f' -t {my_table}'
            result += '\n'

            ipt_comp.minus_n_commands[chain] = True
            return result

        return ''

    # -- Rule components --

    def _print_rule_label(self, rule: CompRule) -> str:
        """Print rule label as comment block."""
        label = rule.label
        if not label or label == self.current_rule_label:
            self.current_rule_label = label if label else ''
            return ''

        res = []
        if not self.compiler or not self.compiler.single_rule_compile_mode:
            res.append('# ')
            res.append(f'# Rule {label}')
            res.append('# ')
            res.append(f'echo "Rule {label}"')
            res.append('# ')

        comment = rule.comment
        if comment:
            for line in comment.split('\n'):
                if line:
                    res.append(f'# {line}')

        if self.compiler and rule.compiler_message:
            res.append(rule.compiler_message)

        self.current_rule_label = label
        if res:
            return '\n'.join(res) + '\n'
        return ''

    def _print_chain(self, rule: CompRule) -> str:
        chain = rule.ipt_chain
        if not chain:
            chain = 'UNKNOWN'
        return chain + ' '

    def _print_direction_and_interface(self, rule: CompRule) -> str:
        """Print -i/-o interface matching."""
        if rule._extra.get('.iface') == 'nil':
            return ''

        if rule.is_itf_any():
            # On FORWARD chain, add wildcard interface match (-i + / -o +)
            # to indicate traffic direction.  INPUT/OUTPUT chains don't need
            # this because the chain itself implies direction.
            if rule.ipt_chain == 'FORWARD':
                if rule.direction == Direction.Inbound:
                    return '-i + '
                if rule.direction == Direction.Outbound:
                    return '-o + '
            return ''

        iface_obj = rule.itf[0] if rule.itf else None
        if iface_obj is None or not isinstance(iface_obj, Interface):
            return ''

        iface_name = iface_obj.name
        if not iface_name:
            return ''

        # Replace wildcard '*' with '+'
        iface_name = iface_name.replace('*', '+')

        res = []
        direction = rule.direction
        if direction == Direction.Inbound:
            res.append(
                self._print_single_option_with_negation('-i', rule, 'itf', iface_name)
            )
        elif direction == Direction.Outbound:
            res.append(
                self._print_single_option_with_negation('-o', rule, 'itf', iface_name)
            )

        res.append('')
        return ' '.join(res)

    def _print_protocol(self, srv) -> str:
        """Print protocol matching."""
        if isinstance(srv, TCPService):
            return '-p tcp -m tcp '
        elif isinstance(srv, UDPService):
            return '-p udp -m udp '
        elif isinstance(srv, (ICMPService, ICMP6Service)):
            if self.compiler and self.compiler.ipv6_policy:
                return '-p ipv6-icmp '
            return '-p icmp  -m icmp '
        elif isinstance(srv, IPService):
            proto = srv.get_protocol_number()
            if proto >= 0:
                return f'-p {proto} '
        return ''

    def _print_multiport(self, rule: CompRule) -> str:
        """Print -m multiport if rule has multiple services."""
        if len(rule.srv) > 1 and rule._extra.get('ipt_multiport'):
            return ' -m multiport '
        return ''

    def _print_src_addr_from_rule(self, rule: CompRule) -> str:
        if rule.is_src_any():
            return ''
        obj = rule.src[0] if rule.src else None
        if obj is not None:
            addr = self._print_addr(obj)
            if addr:
                return self._print_single_option_with_negation(' -s', rule, 'src', addr)
        return ''

    def _print_dst_addr_from_rule(self, rule: CompRule) -> str:
        if rule.is_dst_any():
            return ''
        obj = rule.dst[0] if rule.dst else None
        if obj is not None:
            addr = self._print_addr(obj)
            if addr:
                return self._print_single_option_with_negation(' -d', rule, 'dst', addr)
        return ''

    def _print_addr(self, obj) -> str:
        """Print an address object in iptables format."""
        if isinstance(obj, CombinedAddress):
            addr = self._print_addr_basic(obj.address)
            mac = obj.get_phys_address()
            if mac:
                return f'{addr} -m mac --mac-source {mac}'
            return addr

        if isinstance(obj, Interface):
            if obj.is_dynamic():
                ipv6 = self.compiler.ipv6_policy if self.compiler else False
                suffix = 'v6' if ipv6 else ''
                var = get_interface_var_name(obj, suffix=suffix)
                return f'${var} '
            for addr in getattr(obj, 'addresses', []):
                return self._print_addr_basic(addr)
            return ''

        return self._print_addr_basic(obj)

    def _print_addr_basic(self, obj) -> str:
        """Print basic address in CIDR notation."""
        if isinstance(obj, Host):
            # Resolve Host/Firewall to its first non-loopback address
            for iface in getattr(obj, 'interfaces', []):
                if iface.is_loopback():
                    continue
                for addr in getattr(iface, 'addresses', []):
                    addr_str = addr.get_address()
                    if addr_str:
                        return f'{addr_str} '
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
                    if length != 32:
                        return f'{addr_str}/{length} '
                except ValueError:
                    pass

        return f'{addr_str} '

    def _print_src_service_from_rule(self, rule: CompRule) -> str:
        srv = self._get_first_srv(rule)
        if srv is None:
            return ''
        return self._print_src_ports(srv)

    def _print_dst_service_from_rule(self, rule: CompRule) -> str:
        if rule.is_srv_any():
            return ''

        srv = self._get_first_srv(rule)
        if srv is None:
            return ''

        if len(rule.srv) == 1:
            return self._print_dst_ports(srv)

        # Multiple services — use multiport
        if isinstance(srv, (TCPService, UDPService)):
            port_strs = []
            for s in rule.srv:
                p = self._print_dst_ports_value(s)
                if p:
                    port_strs.append(p)
            if port_strs:
                return f' --dports {",".join(port_strs)} '
        return ''

    def _print_src_ports(self, srv) -> str:
        if not isinstance(srv, (TCPService, UDPService)):
            return ''
        start = srv.src_range_start or 0
        end = srv.src_range_end or 0
        return self._print_ports(' --sport', start, end)

    def _print_dst_ports(self, srv) -> str:
        if isinstance(srv, (ICMPService, ICMP6Service)):
            return self._print_icmp(srv)
        if not isinstance(srv, (TCPService, UDPService)):
            return ''
        start = srv.dst_range_start or 0
        end = srv.dst_range_end or 0
        return self._print_ports(' --dport', start, end)

    def _print_dst_ports_value(self, srv) -> str:
        if not isinstance(srv, (TCPService, UDPService)):
            return ''
        start = srv.dst_range_start or 0
        end = srv.dst_range_end or 0
        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return str(start)
        return f'{start}:{end}'

    def _print_ports(self, flag: str, start: int, end: int) -> str:
        if start <= 0 and end <= 0:
            return ''
        if start == end or end <= 0:
            return f'{flag} {start} '
        return f'{flag} {start}:{end} '

    def _print_icmp(self, srv) -> str:
        codes = getattr(srv, 'codes', None) or srv.data or {}
        raw_type = codes.get('type', -1)
        raw_code = codes.get('code', -1)
        icmp_type = -1 if raw_type is None else int(raw_type)
        icmp_code = -1 if raw_code is None else int(raw_code)

        flag = '--icmpv6-type' if self.compiler.ipv6_policy else '--icmp-type'
        if icmp_type < 0:
            return ''
        if icmp_code < 0:
            return f' {flag} {icmp_type} '
        return f' {flag} {icmp_type}/{icmp_code}  '

    def _print_ip_service_options(self, rule: CompRule, srv) -> str:
        if srv is None:
            return ''
        parts = []
        if isinstance(srv, IPService):
            data = srv.data or {}
            tos = data.get('tos_code', '')
            dscp = data.get('dscp_code', '')
            if tos:
                parts.append(f'-m tos --tos {tos}')
            if dscp:
                parts.append(f'-m dscp --dscp {dscp}')
        if isinstance(srv, TCPService):
            flags = self._print_tcp_flags(srv)
            if flags:
                parts.append(flags)
        return ' '.join(parts)

    def _print_tcp_flags(self, srv) -> str:
        data = srv.data or {}
        flags_mask = data.get('tcp_flags_mask', '')
        flags_comp = data.get('tcp_flags_comp', '')
        if flags_mask and flags_comp:
            return f'--tcp-flags {flags_mask} {flags_comp}'
        return ''

    def _print_modules(self, rule: CompRule, command_line: str = '') -> str:
        """Print module matching (state, conntrack, etc.)."""
        stateless = rule.get_option('stateless', False)
        force_state = rule._extra.get('force_state_check', False)
        if not stateless or force_state:
            if _version_compare(self.version, '1.4.4') >= 0:
                state_module_option = 'conntrack --ctstate'
            else:
                state_module_option = 'state --state'

            if f'-m {state_module_option}' not in command_line:
                return f' -m {state_module_option} NEW '

        return ''

    def _print_time_interval(self, rule: CompRule) -> str:
        if not rule.when:
            return ''
        return ''

    def _print_limit(self, rule: CompRule) -> str:
        limit_val = rule.get_option('limit_value', -1)
        try:
            limit_val = int(limit_val)
        except (ValueError, TypeError):
            limit_val = -1
        if limit_val <= 0:
            return ''

        limit_suffix = rule.get_option('limit_suffix', '') or '/second'
        burst = rule.get_option('limit_burst', 0)
        try:
            burst = int(burst)
        except (ValueError, TypeError):
            burst = 0

        result = f'-m limit --limit {limit_val}{limit_suffix}'
        if burst > 0:
            result += f' --limit-burst {burst}'
        return result

    def _print_target(self, rule: CompRule) -> str:
        target = rule.ipt_target
        if target:
            if target.startswith('.'):
                return ''
            if target == 'REJECT':
                reject_opt = self._print_action_on_reject(rule)
                if reject_opt:
                    return f' -j REJECT {reject_opt}'
            return f' -j {target}'

        action_map = {
            PolicyAction.Accept: 'ACCEPT',
            PolicyAction.Deny: 'DROP',
            PolicyAction.Reject: 'REJECT',
            PolicyAction.Return: 'RETURN',
            PolicyAction.Continue: '',
        }

        target_name = action_map.get(rule.action, '')
        if not target_name:
            return ''

        if rule.action == PolicyAction.Reject:
            reject_opt = self._print_action_on_reject(rule)
            if reject_opt:
                return f' -j REJECT {reject_opt}'

        return f' -j {target_name}'

    def _print_action_on_reject(self, rule: CompRule) -> str:
        reject_with = rule.get_option('action_on_reject', '')
        if not reject_with:
            return ''

        # Map GUI display names and aliases to iptables --reject-with values.
        # The GUI stores human-readable names like "ICMP host unreachable";
        # the C++ compiler maps these via substring matching (see
        # PolicyCompiler_PrintRule.cpp:_printActionOnReject).
        reject_map = {
            'ICMP host unreachable': 'icmp-host-unreachable',
            'ICMP net unreachable': 'icmp-net-unreachable',
            'ICMP port unreachable': 'icmp-port-unreachable',
            'ICMP protocol unreachable': 'icmp-proto-unreachable',
            'ICMP admin prohibited': 'icmp-admin-prohibited',
            'ICMP-unreachable': 'icmp-host-unreachable',
            'TCP RST': 'tcp-reset',
        }
        reject_with = reject_map.get(reject_with, reject_with)

        # icmp-admin-prohibited requires iptables >= 1.2.9
        if (
            reject_with == 'icmp-admin-prohibited'
            and _version_compare(self.version, '1.2.9') < 0
        ):
            return ''

        return f'--reject-with {reject_with}'

    def _print_log_parameters(self, rule: CompRule) -> str:
        """Print logging parameters."""
        parts = []

        log_level = rule.get_option('log_level', '')
        if not log_level:
            log_level = (
                self.compiler.fw.get_option('log_level', '') if self.compiler else ''
            )
        if log_level:
            parts.append(f'--log-level {log_level}')

        log_prefix = rule.get_option('log_prefix', '')
        if not log_prefix:
            log_prefix = (
                self.compiler.fw.get_option('log_prefix', '') if self.compiler else ''
            )
        if log_prefix:
            log_prefix = self._expand_log_prefix(rule, str(log_prefix))
            log_prefix = log_prefix[:29]
            parts.append(f'--log-prefix "{log_prefix}"')

        return ' '.join(parts)

    def _expand_log_prefix(self, rule: CompRule, prefix: str) -> str:
        """Expand log prefix macros (%N, %A, %I, %C, %R)."""
        action = (rule._extra.get('stored_action', '') or '').upper()

        ppos = rule._extra.get('parent_rule_num', '')
        pos = str(rule.position)
        rule_num = f'{ppos}/{pos}' if ppos else pos

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

        result = prefix.replace('%N', rule_num)
        result = result.replace('%A', action)
        result = result.replace('%I', iface_name)
        result = result.replace('%C', chain)
        result = result.replace('%R', ruleset_name)
        return result

    def _start_rule_line(self) -> str:
        """Generate rule line prefix: $IPTABLES [-w] [-t table] -A"""
        ipt_comp = self.compiler
        if ipt_comp is None:
            return '$IPTABLES -A'

        ipv6 = ipt_comp.ipv6_policy
        res = '$IP6TABLES ' if ipv6 else '$IPTABLES '

        if _version_compare(self.version, '1.4.20') >= 0:
            res += '-w '

        my_table = getattr(ipt_comp, 'my_table', 'filter')
        if my_table != 'filter':
            res += f'-t {my_table} '

        res += '-A '
        return res

    def _end_rule_line(self) -> str:
        return '\n'


class PrintRuleIptRst(PrintRule):
    """Generates rules in iptables-restore format."""

    def __init__(self, name: str = 'generate code for iptables-restore') -> None:
        super().__init__(name)

    def _create_chain(self, chain: str) -> str:
        if not chain:
            return ''
        ipt_comp = self.compiler
        if ipt_comp is None:
            return ''
        if not self.minus_n_tracker_initialized:
            self.initialize_minus_n_tracker()
        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            ipt_comp.minus_n_commands[chain] = True
            return f'echo :{chain} - [0:0]'
        return ''

    def _start_rule_line(self) -> str:
        return 'echo'

    def _end_rule_line(self) -> str:
        return ''

    def _print_rule_label(self, rule: CompRule) -> str:
        label = rule.label
        if label and label != self.current_rule_label:
            self.current_rule_label = label
            return f'echo "# Rule {label}"'
        return ''

    def _declare_table(self) -> str:
        ipt_comp = self.compiler
        my_table = getattr(ipt_comp, 'my_table', 'filter') if ipt_comp else 'filter'
        return f"echo '*{my_table}'"

    def _commit(self) -> str:
        return "echo 'COMMIT'"


class PrintRuleIptRstEcho(PrintRuleIptRst):
    """Generates iptables-restore format using echo commands.

    This variant supports dynamic address variable substitution
    by using shell echo to generate the restore file.
    """

    def __init__(
        self, name: str = 'generate code for iptables-restore using echo'
    ) -> None:
        super().__init__(name)

    def _create_chain(self, chain: str) -> str:
        if not chain:
            return ''
        ipt_comp = self.compiler
        if ipt_comp is None:
            return ''
        if not self.minus_n_tracker_initialized:
            self.initialize_minus_n_tracker()
        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            ipt_comp.minus_n_commands[chain] = True
            return f'echo ":{chain} - [0:0]"'
        return ''

    def _start_rule_line(self) -> str:
        return 'echo "'

    def _end_rule_line(self) -> str:
        return '"'

    def _declare_table(self) -> str:
        ipt_comp = self.compiler
        my_table = getattr(ipt_comp, 'my_table', 'filter') if ipt_comp else 'filter'
        return f'echo "*{my_table}"'

    def _commit(self) -> str:
        return 'echo "COMMIT"'
