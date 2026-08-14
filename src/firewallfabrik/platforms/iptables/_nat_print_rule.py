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

from firewallfabrik.compiler._combined_address import CombinedAddress
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
from firewallfabrik.platforms.iptables._nat_compiler import STANDARD_NAT_CHAINS
from firewallfabrik.platforms.iptables._print_rule import tcp_flags_match
from firewallfabrik.platforms.iptables._utils import (
    check_chain_name,
    check_interface_name_in_script,
    get_address_table_var_name,
    get_interface_var_name,
    get_iptables_version,
    get_wait_option,
    ipv4_options_match,
    match_available,
    normalize_set_name,
    version_compare,
)
from firewallfabrik.platforms.linux._netfilter import (
    bridge_port_match_needs_the_bridge,
    check_interface_name,
    has_ip_options,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.iptables._nat_compiler import NATCompiler_ipt


# The release that brought NAT to ip6tables.  libip6t_SNAT.c,
# libip6t_DNAT.c, libip6t_MASQUERADE.c, libip6t_REDIRECT.c and
# libip6t_NETMAP.c were all added at once and are first contained in
# v1.4.17 (netfilter iptables history).  Before that ip6tables has no NAT
# table and none of the targets.
IP6TABLES_NAT_FIRST_RELEASE = '1.4.17'

# Everything a NAT rule can name as a target that is not a chain of ours,
# so the coexistence prefix must not be put in front of it.
_BUILTIN_NAT_TARGETS = frozenset(
    {
        'ACCEPT',
        'DNAT',
        'MASQUERADE',
        'NETMAP',
        'REDIRECT',
        'RETURN',
        'SNAT',
    }
)


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
        self.reported_long_ifaces: set[str] = set()
        self.reported_unsafe_ifaces: set[str] = set()

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
                # In coexistence mode setup_fwf_jumps creates the prefixed
                # standard chains, so they must not be created again here.
                prefixed = self._apply_chain_prefix(chain)
                if prefixed != chain:
                    ipt_comp.minus_n_commands[prefixed] = True
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

        # Build the command first: a rule the compiler cannot express yields
        # an empty one, and then not even its label belongs in the script.
        cmd = self._build_nat_command(rule)
        if not cmd:
            return True

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

        self.compiler.output.write(self._wrap_run_time(rule, cmd))

        return True

    def _print_address_table(self, obj, rule: CompRule, slot: str) -> str | None:
        """Print the match for an address table that is read on the firewall.

        See the policy print rule for the two forms; a NAT rule names its
        original source in ``osrc`` and its original destination in ``odst``,
        which the ipset match still has to spell ``src`` and ``dst``.

        Returns ``None`` when the pinned iptables has no ``set`` match, so
        the caller can leave the rule out.
        """
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        source = get_address_table_source(obj, self.compiler.fw)
        oscnf = getattr(ipt_comp, 'oscnf', None)
        ipv6 = bool(getattr(ipt_comp, 'ipv6_policy', False))
        if oscnf is not None:
            oscnf.register_multi_address_object(obj.name, source, ipv6)

        if getattr(ipt_comp, 'using_ipset', False):
            if not match_available(self.compiler, rule, self.version, 'set'):
                return None
            option = (
                '--match-set'
                if version_compare(self.version, '1.4.4') >= 0
                else '--set'
            )
            suffix = 'src' if slot == 'osrc' else 'dst'
            match = f'{option} {normalize_set_name(obj.name, ipv6)} {suffix}'
            return (
                '-m set '
                f'{self._print_single_option_with_negation("", rule, slot, match)}'
            )

        rule.set_option('address_table_file', source)
        var = get_address_table_var_name(obj)
        flag = ' -s' if slot == 'osrc' else ' -d'
        return self._print_single_option_with_negation(flag, rule, slot, f'${var}')

    def _wrap_run_time(self, rule: CompRule, cmd: str) -> str:
        """Let the OS configurator add the run-time shell wrappers."""
        oscnf = getattr(self.compiler, 'oscnf', None)
        if oscnf is None or not hasattr(oscnf, 'print_run_time_wrappers'):
            return cmd
        ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
        return oscnf.print_run_time_wrappers(
            cmd, ipv6, rule.get_option('address_table_file', '')
        )

    def _nat_available(self, rule: CompRule) -> bool:
        """Report whether the pinned ip6tables has a NAT table at all.

        IPv6 NAT is much younger than the IPv4 one: the four targets a NAT
        rule can use arrived as libip6t_SNAT.c, libip6t_DNAT.c,
        libip6t_MASQUERADE.c, libip6t_REDIRECT.c and libip6t_NETMAP.c in
        one go, all first tagged v1.4.17 (netfilter iptables history).  An
        older ip6tables answers "can't initialize ip6tables table `nat'" or
        "Couldn't load target", which stops the activation script with the
        built-in policies already at DROP, so the rule is reported and left
        out instead.
        """
        if not getattr(self.compiler, 'ipv6_policy', False):
            return True
        if version_compare(self.version, IP6TABLES_NAT_FIRST_RELEASE) >= 0:
            return True
        self.compiler.error(
            rule,
            f'ip6tables before {IP6TABLES_NAT_FIRST_RELEASE} has no NAT table; '
            'the rule is left out',
        )
        return False

    def _chain_names_usable(self, rule: CompRule) -> bool:
        """Whether this rule's chain and target can be written into the script.

        Same question as in the policy printer, with the nat table's own list
        of names the compiler picks itself.
        """
        names = [self._apply_chain_prefix(rule.ipt_chain or 'PREROUTING')]
        target = rule.ipt_target or ''
        if (
            target
            and not target.startswith('.')
            and target not in STANDARD_NAT_CHAINS
            and target not in _BUILTIN_NAT_TARGETS
        ):
            names.append(self._apply_chain_prefix(target))
        # Both names are asked before the answer is folded: a generator
        # would stop at the first bad one and lose the other's message.
        answers = [
            check_chain_name(self.compiler, name, self.reported_long_chains)
            for name in names
        ]
        return all(answers)

    def _build_nat_command(self, rule: CompRule) -> str:
        """Build NAT iptables command, empty when the rule cannot be expressed."""
        cmd = ''
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        if not self._nat_available(rule):
            return ''

        if not self._chain_names_usable(rule):
            return ''

        cmd += self._start_rule_line()
        chain_and_iface = self._print_chain_direction_and_interface(rule)
        if chain_and_iface is None:
            # The reason was reported; without the interface match the rule
            # would translate traffic of every interface.
            return ''
        cmd += chain_and_iface

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
        if isinstance(osrc, CombinedAddress) and osrc.has_phys_address():
            # An object that names both is matched on both, the way the
            # policy printer and fwbuilder's _printSrcAddr do it
            # (iptlib/PolicyCompiler_PrintRule.cpp:1615). Rendering only one
            # of the two would translate for every host carrying the other.
            # The negation belongs behind `-m mac`, not in front of it:
            # `--mac-source` carries XTOPT_INVERT (netfilter
            # extensions/libxt_mac.c) while a `!` before a `-m` is a parse
            # error, "unexpected ! flag before --match" (iptables
            # xshared.c, command_match).
            neg = self._print_single_option_with_negation(
                '--mac-source', rule, 'osrc', osrc.get_phys_address()
            )
            cmd += f'-m mac {neg}'
            addr_str = self._print_addr(osrc.address)
            if addr_str:
                cmd += self._print_single_option_with_negation(
                    ' -s', rule, 'osrc', addr_str
                )
        elif isinstance(osrc, PhysAddress):
            mac_match = self._print_mac_source(osrc, rule)
            if mac_match is None:
                # No MAC to match on; the reason was reported.
                return ''
            cmd += mac_match
        elif is_run_time_address_table(osrc):
            table_match = self._print_address_table(osrc, rule, 'osrc')
            if table_match is None:
                # The reason was reported; the rule would otherwise
                # translate every address instead of the table's.
                return ''
            cmd += table_match
        elif osrc:
            addr_str = self._print_addr(osrc)
            if not addr_str:
                # Emitting the rule without the match would translate every
                # source address, not the one the rule names.
                self.compiler.error(
                    rule,
                    f'Could not resolve an original source address for "{osrc.name}"',
                )
                if rule.ipt_target != 'RETURN':
                    return ''
            else:
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
            # no destination equivalent (netfilter extensions/libxt_mac.c
            # knows `--mac-source` alone).  Reporting it is not enough: a
            # rule that keeps its target but loses its destination match
            # translates every address the rest of the rule allows, so it
            # goes the way of the other objects that cannot be rendered.
            self.compiler.error(
                rule,
                f'MAC address "{odst.get_address()}" cannot be used as a '
                'destination, iptables can only match the source MAC; the '
                'rule is left out',
            )
            if rule.ipt_target != 'RETURN':
                return ''
        elif isinstance(odst, CombinedAddress) and odst.has_phys_address():
            # What a host with "MAC address matching" expands to.  The MAC
            # half cannot be a destination - the mac match knows
            # `--mac-source` alone - but the IP half is a match like any
            # other, and the C++ keeps exactly that half
            # (NATCompiler_ipt.cpp, verifyRuleWithMAC).  Dropping the whole
            # object instead reported "could not resolve" and left out a
            # rule that has a perfectly good destination.
            addr_str = self._print_addr(odst.address)
            if not addr_str:
                self.compiler.error(
                    rule,
                    f'"{odst.name}" is known by its MAC address only, which '
                    'cannot be matched as a destination; the rule is left out',
                )
                if rule.ipt_target != 'RETURN':
                    return ''
            else:
                self.compiler.warning(
                    rule,
                    f'the MAC address of "{odst.name}" is left out: iptables '
                    'matches the source MAC only, so the rule matches on the '
                    'destination address alone',
                )
                cmd += self._print_single_option_with_negation(
                    ' -d', rule, 'odst', addr_str
                )
        elif is_run_time_address_table(odst):
            table_match = self._print_address_table(odst, rule, 'odst')
            if table_match is None:
                # The reason was reported; the rule would otherwise
                # translate every address instead of the table's.
                return ''
            cmd += table_match
        elif odst:
            addr_str = self._print_addr(odst)
            if not addr_str:
                self.compiler.error(
                    rule,
                    f'Could not resolve an original destination address for '
                    f'"{odst.name}"',
                )
                # A RETURN rule that lost its match sends the whole helper
                # chain back to its caller, so the rule does nothing; drop it
                # and the action rule behind it would translate everything.
                if rule.ipt_target != 'RETURN':
                    return ''
            else:
                cmd += self._print_single_option_with_negation(
                    ' -d', rule, 'odst', addr_str
                )

        # Dst service
        cmd += ' '
        if osrv:
            dst_service = self._print_dst_service(rule)
            if dst_service is None:
                # The reason was reported. Translating without the service
                # match would take every protocol and port; keep only a
                # RETURN rule, whose chain would otherwise let the action
                # behind it translate everything.
                if rule.ipt_target != 'RETURN':
                    return ''
                dst_service = ''
            cmd += dst_service

        # Target
        target = rule.ipt_target
        if target and not target.startswith('.') and target not in _BUILTIN_NAT_TARGETS:
            target = self._prefix_chain(target)
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

    def _print_mac_source(self, obj, rule: CompRule) -> str | None:
        """Print a MAC address match, None when the object carries no MAC.

        iptables cannot match a MAC with ``-s``, it needs the mac module
        (fwbuilder does the same in NATCompiler_PrintRule.cpp).  An object
        with an empty MAC used to become ``--mac-source 00:00:00:00:00:00``,
        a rule no packet can ever match; fwbuilder leaves such an object out
        of the ruleset instead, and so does this.
        """
        mac = obj.get_address()
        if not mac:
            self.compiler.warning(
                rule,
                f'"{obj.name}" has no MAC address, so the rule is left out',
            )
            return None
        neg = self._print_single_option_with_negation(
            ' --mac-source', rule, 'osrc', mac
        )
        return f' -m mac{neg}'

    def _print_nat_placement(
        self, rule: CompRule, no_persistent: str = ''
    ) -> list[str]:
        """Print the options that steer how the NAT target picks an address.

        Both options are refused by an iptables that predates them, which
        stops the activation script.  `--random` arrived in 1.3.8 (netfilter
        commit "iptables: add random option to SNAT") and `--persistent` in
        1.4.4 ("SNAT/DNAT: add support for persistent multi-range NAT
        mappings"); fwbuilder gates the latter on 1.4.3, one release too
        early.

        MASQUERADE never had `--persistent` at all: its option table lists
        `to-ports`, `random` and `random-fully` and nothing else (netfilter
        extensions/libxt_NAT.c, and extensions/libipt_MASQUERADE.c in every
        release before it), so iptables answers `unknown option
        "--persistent"` and the activation script stops with the built-in
        policies already set to DROP.  fwbuilder emits only `--random` for a
        masquerading rule (NATCompiler_PrintRule.cpp).  nftables can express
        it (`masquerade persistent`, nftables tests/py/ip/masquerade.t), so
        the option is not lost there.
        """
        parts = []
        if rule.get_option('ipt_nat_random', False):
            if version_compare(self.version, '1.3.8') >= 0:
                parts.append('--random')
            else:
                self.compiler.warning(
                    rule,
                    'iptables before 1.3.8 cannot randomise the translated '
                    'port; the "Random" option is left out',
                )
        if rule.get_option('ipt_nat_persistent', False):
            if no_persistent:
                # The name is the caller's, not a fixed one: MASQUERADE and
                # REDIRECT both lack the option and a message naming the
                # wrong one of them sends the administrator to the wrong
                # rule (netfilter extensions/libxt_NAT.c option tables).
                self.compiler.warning(
                    rule,
                    f'the {no_persistent} target has no "Persistent" option; '
                    f'it is left out of this rule',
                )
            elif version_compare(self.version, '1.4.4') >= 0:
                parts.append('--persistent')
            else:
                self.compiler.warning(
                    rule,
                    'iptables before 1.4.4 cannot map a client to the same '
                    'translated address every time; the "Persistent" option '
                    'is left out',
                )
        return parts

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
            parts = []
            # Masquerading picks the address of the outgoing interface but
            # still takes a source port range, which is how a translation to
            # an address only known at run time keeps its ports (netfilter
            # extensions/libxt_MASQUERADE.man, extensions/libipt_MASQUERADE.t).
            ports = self._print_snat_ports(tsrv) if tsrv else ''
            if ports:
                parts.append(f'--to-ports {ports}')
            parts.extend(self._print_nat_placement(rule, no_persistent='MASQUERADE'))
            return ' '.join(parts)

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
            parts.extend(self._print_nat_placement(rule))
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
            parts.extend(self._print_nat_placement(rule))
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
            parts = []
            ports = self._print_dnat_ports(tsrv) if tsrv else ''
            if ports:
                parts.append(f'--to-ports {ports}')
            # REDIRECT_opts carries `random` like the other NAT targets, and
            # unlike them no `persistent` (netfilter extensions/libxt_NAT.c),
            # which is the same shape MASQUERADE has.  fwbuilder drops the
            # option here; keeping it is what the rule asks for.
            parts.extend(self._print_nat_placement(rule, no_persistent='REDIRECT'))
            return ' '.join(parts)

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

    def _apply_chain_prefix(self, chain: str) -> str:
        """Apply the coexistence chain prefix, as the policy printer does.

        Without it the NAT rules land in the real PREROUTING and
        POSTROUTING chains, where reset_fwf_chains cannot find them again -
        it only knows the prefixed ones - so every activation adds another
        copy of the whole NAT ruleset.
        """
        prefix = getattr(self.compiler, 'chain_prefix', '')
        if prefix and chain:
            return f'{prefix}_{chain}'
        return chain

    def _prefix_chain(self, chain: str) -> str:
        """Return the chain a rule is written to, reporting a name iptables
        would refuse.  See the policy printer for why the bookkeeping does
        not go through here.
        """
        chain = self._apply_chain_prefix(chain)
        check_chain_name(self.compiler, chain, self.reported_long_chains)
        return chain

    def _create_chain(self, chain: str) -> str:
        """Generate the chain creation command if the chain needs one.

        The name is checked only once the chain turns out to need creating;
        see the policy printer.
        """
        if not chain:
            return ''
        chain = self._apply_chain_prefix(chain)
        ipt_comp = cast('NATCompiler_ipt', self.compiler)

        if not self.minus_n_tracker_initialized:
            self._initialize_minus_n_tracker()

        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
            and chain not in ipt_comp.minus_n_commands
        ):
            check_chain_name(self.compiler, chain, self.reported_long_chains)
            result = self._chain_declaration(chain)
            ipt_comp.minus_n_commands[chain] = True
            return result

        return ''

    def _chain_declaration(self, chain: str) -> str:
        """Return the line that brings *chain* into existence.

        Only the wording differs between the output formats; see the policy
        printer for why the rest is decided once, above.
        """
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        opt_wait = get_wait_option(self.version)
        if opt_wait:
            opt_wait += ' '
        ipt_cmd = '$IP6TABLES' if ipt_comp.ipv6_policy else '$IPTABLES'
        return f'{ipt_cmd} {opt_wait}-t nat -N {chain}\n'

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
        """Print the rule banner, its comment and anything reported about it.

        The same three parts the policy printer writes.  Single-rule
        compile mode leaves the banner out there, so that the fragment the
        editor shows is the rule and nothing else, and a message the
        compiler recorded against the rule is written into the script so
        the administrator reading it sees why the rule looks as it does -
        neither happened here.
        """
        label = rule.label
        if not label or label == self.current_rule_label:
            return ''
        self.current_rule_label = label

        result = ''
        if not self.compiler.single_rule_compile_mode:
            result += f'# \n# Rule {label}\n# \n'
            result += f'echo "Rule {label}"\n'
            result += '# \n'
        comment = rule.comment
        if comment:
            for line in comment.split('\n'):
                if line.strip():
                    result += f'# {line}\n'
        if rule.compiler_message:
            result += f'{rule.compiler_message}\n'
        return result

    def _print_chain_direction_and_interface(self, rule: CompRule) -> str | None:
        parts = []

        iface_in_name = self._get_interface_name(rule.itf_inb)
        iface_out_name = self._get_interface_name(rule.itf_outb)

        # "nil" means the rule deliberately carries no interface match, so
        # the name is never written out and its length cannot break
        # anything.  Checking first cost the whole rule for a name it was
        # not going to use - and the negation expansion sets "nil" on the
        # RETURN half of its pair and not on the other, so the pair came
        # apart, which changes what the remaining half matches.  The policy
        # printer returns before its own check for the same reason.
        if rule.nat_iface_in == 'nil':
            iface_in_name = ''
        if rule.nat_iface_out == 'nil':
            iface_out_name = ''

        for name in (iface_in_name, iface_out_name):
            if not check_interface_name(self.compiler, name, self.reported_long_ifaces):
                return None
            # From here on the name is a bare word in a shell command, and
            # iptables takes every character the kernel allows in one.
            if not check_interface_name_in_script(
                self.compiler, name, self.reported_unsafe_ifaces
            ):
                return None

        parts.append(self._prefix_chain(rule.ipt_chain))

        if iface_in_name:
            parts.append(self._print_iface_option(rule, 'itf_inb', iface_in_name, True))
        if iface_out_name:
            parts.append(
                self._print_iface_option(rule, 'itf_outb', iface_out_name, False)
            )

        parts.append('')
        return ' '.join(parts)

    def _print_iface_option(
        self, rule: CompRule, slot: str, iface_name: str, inbound: bool
    ) -> str:
        """Print ``-i`` / ``-o``, or the physdev match for a bridge port.

        A bridged packet reaches the nat hooks carrying the bridge device
        as its in/out device, not the port it came in on - that one lives
        in the bridge layer and is what ``xt_physdev`` reads
        (``nf_bridge_get_physindev``).  ``-i <port>`` therefore never
        matches and the rule translates nothing, with nothing said about
        it.  The policy printer has used ``-m physdev`` for this since it
        was written; xt_physdev registers no hook mask at all
        (net/netfilter/xt_physdev.c), so the nat table takes it too.

        ``--physdev-out`` alone stopped matching non-bridged traffic in
        iptables 1.2.9, which is why the outbound form adds
        ``--physdev-is-bridged``.
        """
        obj = getattr(rule, slot)[0] if getattr(rule, slot) else None
        bridged = (
            isinstance(obj, Interface)
            and obj.is_bridge_port()
            and (not self.version or version_compare(self.version, '1.3.0') >= 0)
        )
        if not bridged:
            option = '-i' if inbound else '-o'
            return self._print_single_option_with_negation(
                option, rule, slot, iface_name
            )
        # Several bridges can share one wildcard port name (`vnet+` on both
        # br0 and br1, which is what libvirt gives a host with more than one
        # virtual network), and then the port match alone no longer says
        # which bridge is meant: a rule written for one of them translates
        # the other one's guests too.  Naming the bridge next to it settles
        # that, and is only worth doing when there is more than one bridge.
        # The policy printer has done this since it was written.
        parent = getattr(obj, 'parent_interface', None)
        parent_name = parent.name if parent is not None else ''
        name_the_bridge = bridge_port_match_needs_the_bridge(
            obj, getattr(self.compiler, 'bridge_count', 0)
        )

        parts = []
        if inbound:
            if name_the_bridge:
                parts.append(f'-i {parent_name}')
            option = self._print_single_option_with_negation(
                '--physdev-in', rule, slot, iface_name
            )
            parts.append(f'-m physdev {option.rstrip()}')
        else:
            if name_the_bridge:
                parts.append(f'-o {parent_name}')
            option = self._print_single_option_with_negation(
                '--physdev-out', rule, slot, iface_name
            )
            parts.append(f'-m physdev --physdev-is-bridged {option.rstrip()}')
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

        REDIRECT and MASQUERADE (`--to-ports`), and DNAT/SNAT that translate
        a port, need an explicit protocol; the port comes from the translated
        service, which also pins the protocol. Mirrors the `meta l4proto` the
        nftables compiler injects for the same rules.

        NETMAP is deliberately not in the list: its only option is `--to`
        (netfilter extensions/libipt_NETMAP.c), so a network translation
        never carries a port and has no reason to be narrowed to one
        protocol.
        """
        ipt_comp = cast('NATCompiler_ipt', self.compiler)
        rt = rule.nat_rule_type
        tsrv = ipt_comp.get_first_tsrv(rule)
        if rt in (NATRuleType.Masq, NATRuleType.SNAT):
            has_port = bool(self._print_snat_ports(tsrv)) if tsrv else False
        elif rt in (NATRuleType.Redirect, NATRuleType.DNAT):
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
        """Print `-m multiport` for a rule that lists more than one service.

        The flag alone is not enough: PrepareForMultiport sets it on every
        chunk it produces, and a service list of 16 leaves a trailing chunk
        of one, which then prints the single-service `--dport`.  That
        belongs to the tcp/udp match, so the multiport module ends up with
        no option of its own and iptables refuses the command with
        "multiport expection an option" (netfilter
        extensions/libxt_multiport.c:248, ``multiport_check``).  The policy
        print rule has always counted the services first.
        """
        if len(rule.osrv) > 1 and rule.ipt_multiport:
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

    def _print_dst_service(self, rule: CompRule) -> str | None:
        """Print destination service matching for NAT rules.

        Handles CustomService, TagService and UserService in addition
        to the standard TCP/UDP/ICMP/IP types (matching fwbuilder's
        NATCompiler_PrintRule::_printDestinationPort).

        Returns ``None`` when the service object carries nothing to match
        on, so the caller can leave the rule out instead of translating
        every protocol and port between the addresses it names.
        """
        if rule.is_osrv_any():
            return ''
        srv = rule.osrv[0] if rule.osrv else None
        if srv is None:
            return ''

        if isinstance(srv, CustomService):
            ipt_comp = cast('NATCompiler_ipt', self.compiler)
            code = (srv.codes or {}).get(ipt_comp.my_platform_name(), '')
            if not code:
                # VerifyCustomServices already reported the missing code.
                return None
            return f'{code} '

        if isinstance(srv, TagService):
            tag_code = srv.get_code()
            if not tag_code:
                self.compiler.error(
                    rule, f'Tag service "{srv.name}" carries no tag to match on'
                )
                return None
            return f'-m mark --mark {tag_code} '

        if isinstance(srv, UserService):
            uid = srv.userid or ''
            if not uid:
                self.compiler.error(
                    rule, f'User service "{srv.name}" names no user to match on'
                )
                return None
            return f'-m owner --uid-owner {uid} '

        if len(rule.osrv) == 1:
            if isinstance(srv, (TCPService, UDPService)):
                ports = self._print_dst_ports(srv)
                # A TCP service may inspect the flags, and neither fwbuilder's
                # NAT printer nor this one used to write them out: the rule
                # then translated every TCP packet between the addresses it
                # names, not the handshake stage it was written for.  The
                # match is legal in the nat table, so it is emitted rather
                # than reported.
                flags = tcp_flags_match(srv) if isinstance(srv, TCPService) else ''
                if ports and flags:
                    return f'--dport {ports} {flags} '
                if flags:
                    return f'{flags} '
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
                ip_str = self._print_ip(rule, srv)
                if ip_str is None:
                    return None
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
        """Print translated ports (uses '-' separator instead of ':').

        A match port range may leave a bound out -- ``:1024`` reads as "from
        0" to the tcp and udp matches (``extensions/libxt_tcp.c``:
        ``parse_tcp_ports``).  A translation target has no such shorthand:
        ``parse_ports`` in ``extensions/libxt_NAT.c`` hands each side to
        ``xtables_strtoui`` and answers ``Port `-1024' not valid`` for a
        missing lower bound and ``Port range `0' funky`` for a missing
        upper one, either of which stops the activation script.  So a
        half-open range is written out: no lower bound means from 0, no
        upper bound means the single port named.  Same as nftables.
        """
        if rs < 0:
            rs = 0
        if re_ < 0:
            re_ = 0
        if rs > 0 or re_ > 0:
            if rs == re_ or re_ == 0:
                return str(rs)
            return f'{rs}-{re_}'
        return ''

    def _print_icmp(self, srv) -> str:
        codes = getattr(srv, 'codes', None) or srv.data or {}
        raw_type = codes.get('type', -1)
        raw_code = codes.get('code', -1)
        icmp_type = -1 if raw_type is None else int(raw_type)
        icmp_code = -1 if raw_code is None else int(raw_code)
        if icmp_type < 0:
            # A service naming no type matches ICMP as a whole.  The IPv4
            # icmp match still insists on --icmp-type (XTOPT_MAND in
            # extensions/libipt_icmp.c, enforced in
            # libxtables/xtoptions.c), and its own type table spells that
            # "any" (extensions/libxt_icmp.h).  ip6tables has no such
            # keyword, so IPv6 drops the -m icmp6 match instead; the
            # protocol match alone already covers every ICMPv6 message.
            # Same split as the policy print rule.
            return '' if self.compiler.ipv6_policy else 'any'
        if icmp_code >= 0:
            return f'{icmp_type}/{icmp_code}'
        return str(icmp_type)

    def _print_ip(self, rule: CompRule, srv) -> str | None:
        """Print IPService fragment and IP option matching for NAT rules.

        Matches fwbuilder PolicyCompiler_PrintRule::_printIP().
        """
        data = srv.data or {}
        parts = []
        # fwbuilder's NAT printer reads neither the ToS nor the DSCP of an
        # IP service (NATCompiler_PrintRule.cpp, _printIP), and the policy
        # printer reads both.  A NAT rule whose service names one and whose
        # command does not carries a wider condition than the editor shows
        # and translates traffic the rule was not written for, so it is
        # reported rather than passed on.
        if data.get('tos', '') or data.get('dscp', ''):
            self.compiler.error(
                rule,
                'the service of this NAT rule matches on the ToS or DSCP '
                'field, which a NAT rule cannot express; the rule is left out',
            )
            return None
        if _is_true(data.get('fragm')) or _is_true(data.get('short_fragm')):
            if self.compiler.ipv6_policy:
                # ip6tables refuses -f outright and names the replacement
                # itself: "`-f' is not supported in IPv6, use -m frag
                # instead" (netfilter iptables/xshared.c:1793).  The option
                # is not even in ip6tables' option table.  Same split as the
                # policy print rule, gate included: extensions/libip6t_frag.c
                # first ships in v1.2.7.
                if not match_available(self.compiler, rule, self.version, 'frag'):
                    return None
                parts.append('-m frag --fragmore')
            else:
                parts.append('-f')
        # The ipv4options match reads the IPv4 header option field, which an
        # IPv6 packet does not have, so ip6tables has no such module.  The
        # policy print rule leaves the block out for IPv6 for that reason,
        # and both build the match with the same shared helper.
        if not self.compiler.ipv6_policy:
            ip_opts, problem = ipv4_options_match(data, self.version)
            if problem:
                self.compiler.warning(rule, problem)
            if ip_opts:
                parts.append(ip_opts)
            elif problem:
                # Without the match the rule would translate every packet,
                # options or not.
                return None
        elif has_ip_options(data):
            self.compiler.error(
                rule,
                'IP service matching an IPv4 header option cannot be '
                'compiled for IPv6, which has no such field; the rule is '
                'left out of the IPv6 ruleset',
            )
            return None
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
                # NAT match (-s / -d).  A range that is not a prefix does
                # not reach here: NATExpandAddressRanges writes every range
                # in OSrc and ODst out as the networks covering it, which is
                # what the C++ NAT compiler does as well
                # (NATCompiler_ipt::ExpandAddressRanges, wired
                # unconditionally, unlike the policy compiler's -m iprange).
                # The last line is therefore a safety net, not a form the
                # generated script relies on - `-s a-b` is not an address
                # and iptables answers "host/network not found".
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

    def _declare_table(self) -> str:
        return ''

    def _commit(self) -> str:
        return ''

    def _quote(self, s: str) -> str:
        return f'"{s}"'


class NATPrintRuleIptRstEcho(NATPrintRule):
    """NAT rules as iptables-restore input, built with echo.

    The generated script echoes the restore stream so that a rule can
    carry a shell variable - a run-time address table, a dynamic interface
    address - which a plain restore file cannot.  fwbuilder has a second,
    non-echo variant for the case where no rule needs one; this port never
    selected it.
    """

    def _print_rule_label(self, rule: CompRule) -> str:
        # The banner of the shell form ends in `echo "Rule N"`, and in this
        # form that line lands in the restore stream itself, where
        # iptables-restore has no idea what to do with it.  A comment is
        # all the stream takes.
        label = rule.label
        if label and label != self.current_rule_label:
            self.current_rule_label = label
            return f'# Rule {label}\n'
        return ''

    def _chain_declaration(self, chain: str) -> str:
        if self.compiler.single_rule_compile_mode:
            return ''
        # The quotes keep the shell from reading `[0:0]` as a glob.
        return f'echo ":{chain} - [0:0]"\n'

    def _start_rule_line(self) -> str:
        return 'echo "-A '

    def _end_rule_line(self) -> str:
        return '"\n'

    def process_next(self) -> bool:
        if self.print_once_on_top:
            self.print_once_on_top = False
        return super().process_next()

    def _commit(self) -> str:
        return 'echo COMMIT\n'

    def _quote(self, s: str) -> str:
        return f'\\"{s}\\"'
