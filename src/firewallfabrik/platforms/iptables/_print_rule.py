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
import uuid
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._interval_helpers import (
    DOW_NAMES_SHORT,
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
    get_address_table_source,
    is_run_time_address_table,
    is_valid_dscp,
    range_to_cidr,
)
from firewallfabrik.platforms.iptables._utils import (
    TARGET_FIRST_RELEASE,
    check_chain_name,
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
    check_interface_name,
    has_ip_options,
    reject_type_token,
    sanitize_log_prefix,
)

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt


def _is_true(val) -> bool:
    """Check a data-dict value that may be a Python bool or a string 'True'/'False'."""
    return str(val) == 'True'


# Map symbolic syslog level names to numeric values.  Matches the order
# iptables expects for --log-level and the numeric form fwbuilder emits.
_LOG_LEVEL_MAP = {
    'alert': '1',
    'crit': '2',
    'debug': '7',
    'emerg': '0',
    'err': '3',
    'error': '3',
    'info': '6',
    'notice': '5',
    'panic': '0',
    'warn': '4',
    'warning': '4',
}

# Targets that only write a log message and let the packet fall through to
# the next rule.
LOG_TARGETS = frozenset({'LOG', 'NFLOG', 'ULOG'})

# The limit match stores its rate as XT_LIMIT_SCALE * unit / rate in a
# 32-bit field, so a rate above XT_LIMIT_SCALE per unit rounds to zero and
# iptables refuses it with "Rate too fast" (netfilter
# extensions/libxt_limit.c: parse_rate, include/linux/netfilter/xt_limit.h).
# The burst is bounded by the option itself.  nftables counts tokens
# directly and has neither ceiling.
XT_LIMIT_SCALE = 10000
MAX_LIMIT_BURST = 10000

# Reject types that the REJECT target only learnt along the way.  Everything
# else in reject_table dates from the first release that has the target at
# all, so only these three need a gate (netfilter iptables history):
#
#   icmp-admin-prohibited  extensions/libipt_REJECT.c, v1.2.9
#   icmp6-policy-fail      extensions/libip6t_REJECT.c, v1.6.0
#   icmp6-reject-route     extensions/libip6t_REJECT.c, v1.6.0
#
# The last two arrived together in "added missing icmpv6 codes in REJECT"
# (RFC 4443 codes 5 and 6).  An older binary answers "unknown reject type",
# which stops the activation script, so the rule keeps the target's default
# type and the change is reported.
#
# Every entry of reject_table has a primary name and an alias, and REJECT
# accepts either, so both spellings need the same gate.  An imported .fwb
# carries whichever one the administrator picked.
REJECT_TOKEN_FIRST_RELEASE = {
    'admin-prohib': '1.2.9',
    'icmp-admin-prohibited': '1.2.9',
    'icmp6-policy-fail': '1.6.0',
    'icmp6-reject-route': '1.6.0',
    'policy-fail': '1.6.0',
    'reject-route': '1.6.0',
}

# The dstlimit match is the older incarnation of hashlimit and left
# netfilter iptables in "Remove extensions for unmaintained/obsolete
# patchlets" (b1f56830); the first release without it is v1.3.8.  A rule
# ticking "use dstlimit" on anything newer names a module the tool cannot
# load, so it is emitted as written and the reason is reported.
DSTLIMIT_LAST_RELEASE = '1.3.7'
DSTLIMIT_NOTE = (
    'The "dstlimit" match left netfilter iptables after '
    f'{DSTLIMIT_LAST_RELEASE}; use the rate limit without the dstlimit '
    'option, which compiles to the "hashlimit" match that replaced it'
)

# The LOG target carries its prefix in a 30-byte field and the NFLOG one
# in a 64-byte field (netfilter linux/include/uapi/linux/netfilter/
# xt_LOG.h and xt_NFLOG.h), so one character of each is the terminator.
# iptables truncates a longer prefix without a word.  nftables has room
# for 127 characters and keeps the whole string.
MAX_LOG_PREFIX = 29
MAX_NFLOG_PREFIX = 63
LIMIT_UNIT_SECONDS = {
    '/day': 24 * 60 * 60,
    '/hour': 60 * 60,
    '/minute': 60,
    '/second': 1,
}


class PrintRule(PolicyRuleProcessor):
    """Generates iptables shell commands from compiled policy rules.

    This is the final processor in the pipeline that converts the
    internal CompRule representation to iptables command strings.
    """

    def __init__(self, name: str = 'generate iptables shell script') -> None:
        super().__init__(name)
        self.minus_n_tracker_initialized: bool = False
        self.current_rule_label: str = ''
        self.version: str = ''
        self.reported_long_chains: set[str] = set()
        self.reported_long_ifaces: set[str] = set()

    def initialize(self) -> None:
        """Initialize after compiler context is set."""
        self.version = get_iptables_version(self.compiler.fw)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        chain = rule.ipt_chain
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        self.tmp_queue.append(rule)

        if ipt_comp.chain_usage_counter.get(chain, 0) <= 0:
            return True

        # Build the command first: a rule the compiler cannot express yields
        # an empty one, and then not even its label belongs in the script.
        cmd = self._build_rule_command(rule)
        if not cmd:
            return True

        self.compiler.output.write(self._print_rule_label(rule))
        self.compiler.output.write(self._create_chain(rule.ipt_chain))

        target = rule.ipt_target
        if target and not target.startswith('.'):
            self.compiler.output.write(self._create_chain(target))

        self.compiler.output.write(self._wrap_run_time(rule, cmd))

        return True

    def _wrap_run_time(self, rule: CompRule, cmd: str) -> str:
        """Let the OS configurator add the run-time shell wrappers."""
        oscnf = getattr(self.compiler, 'oscnf', None)
        if oscnf is None or not hasattr(oscnf, 'print_run_time_wrappers'):
            return cmd
        ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
        return oscnf.print_run_time_wrappers(
            cmd, ipv6, rule.get_option('address_table_file', '')
        )

    def policy_rule_to_string(self, rule: CompRule) -> str:
        """Generate rule string for dedup (used by Optimize3)."""
        return self._build_rule_command(rule)

    def _build_rule_command(self, rule: CompRule) -> str:
        """Build the actual iptables command line."""
        command_line = ''

        command_line += self._start_rule_line()
        command_line += self._print_chain(rule)
        iface_match = self._print_direction_and_interface(rule)
        if iface_match is None:
            # The reason was reported; without the interface match the rule
            # would apply to every interface.
            return ''
        command_line += iface_match

        srv = self._get_first_srv(rule)
        if srv:
            command_line += self._print_protocol(srv)

        command_line += self._print_multiport(rule)

        src_addr = self._print_src_addr_from_rule(rule)
        dst_addr = self._print_dst_addr_from_rule(rule)
        if src_addr is None or dst_addr is None:
            # The reason was reported already. Emitting the rule without the
            # match would apply it to every address, the opposite of what it
            # says, so leave it out.
            if not self._keeps_the_ruleset_tighter(rule):
                return ''
            src_addr = src_addr or ''
            dst_addr = dst_addr or ''
        command_line += src_addr
        command_line += dst_addr

        command_line += self._print_src_service_from_rule(rule)
        command_line += self._print_dst_service_from_rule(rule)

        if srv:
            ip_options = self._print_ip_service_options(rule, srv)
            if ip_options is None:
                if not self._keeps_the_ruleset_tighter(rule):
                    return ''
                ip_options = ''
            command_line += ip_options
            custom_srv = self._print_custom_services(rule, srv)
            if custom_srv is None:
                if not self._keeps_the_ruleset_tighter(rule):
                    return ''
                custom_srv = ''
            command_line += custom_srv

        command_line += self._print_modules(rule, command_line)
        time_interval = self._print_time_interval(rule)
        if time_interval is None:
            # Without the time match the rule would apply around the clock,
            # which is wider than what it says. The reason was reported.
            return ''
        command_line += time_interval
        command_line += self._print_limit(rule)
        connlimit = self._print_connlimit(rule)
        if connlimit is None:
            # The release has no such match and the reason was reported.
            # Without it an Accept rule would let through more connections
            # than the rule allows, and a Deny rule would stop all of them.
            return ''
        command_line += connlimit
        hashlimit = self._print_hashlimit(rule)
        if hashlimit is None:
            # The release has no such match and the reason was reported.
            return ''
        command_line += hashlimit
        target_part = self._print_target(rule)
        if target_part is None:
            # The target does not exist on this release, which was reported.
            # A rule that only marks or classifies has nothing left to do.
            return ''
        command_line += target_part

        target = rule.ipt_target
        if target in ('LOG', 'ULOG', 'NFLOG'):
            log_params = self._print_log_parameters(rule)
            if log_params:
                command_line += '  ' + log_params

        command_line += self._end_rule_line()
        return command_line

    @staticmethod
    def _keeps_the_ruleset_tighter(rule: CompRule) -> bool:
        """Is a rule that lost its address match better kept than dropped?

        A rule the compiler could not restrict matches everything, so leaving
        it out is what keeps the generated ruleset closest to the intent -
        except when it only sends the packet back to the calling chain.  The
        negation expansion builds such a chain out of a RETURN rule that
        excludes the negated addresses and an action rule behind it; drop the
        RETURN and the action applies to all traffic instead of none.
        Keeping it makes the whole chain return, so the rule does nothing,
        which is the right answer for a rule that cannot be compiled.
        """
        target = rule.ipt_target or ''
        return target == 'RETURN' or target.startswith('.')

    def _get_first_srv(self, rule: CompRule):
        """Get the first service object from the rule."""
        if rule.is_srv_any():
            return None
        return rule.srv[0] if rule.srv else None

    # -- Negation helpers --

    def _print_single_object_negation(self, rule: CompRule, slot: str) -> str:
        if getattr(rule, f'{slot}_single_object_negation'):
            return '! '
        return ''

    def _print_single_option_with_negation(
        self, option: str, rule: CompRule, slot: str, arg: str
    ) -> str:
        """Print --option with negation, respecting iptables version.

        The two spellings do not overlap: iptables 1.4.3 both taught the
        parser the leading ``!`` and turned the deprecation of the old
        ``--option ! value`` into an error (netfilter iptables
        ``0f16c725`` and ``e0390bee``, both first in v1.4.3), so a release
        takes one of them and refuses the other.  Every option the compiler
        can negate goes through here, including the ones fwbuilder writes
        with a fixed leading ``!``.
        """
        if version_compare(self.version, '1.4.3') >= 0:
            return f'{self._print_single_object_negation(rule, slot)}{option} {arg} '
        else:
            return f'{option} {self._print_single_object_negation(rule, slot)}{arg} '

    # -- Chain management --

    def initialize_minus_n_tracker(self) -> None:
        """Mark standard chains as already existing."""
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        if (
            hasattr(ipt_comp, 'minus_n_commands')
            and ipt_comp.minus_n_commands is not None
        ):
            for chain in ipt_comp.get_standard_chains():
                ipt_comp.minus_n_commands[chain] = True
                # In coexistence mode, the prefixed standard chains
                # are created by setup_fwf_jumps, so mark them too.
                prefixed = self._apply_chain_prefix(chain)
                if prefixed != chain:
                    ipt_comp.minus_n_commands[prefixed] = True
        self.minus_n_tracker_initialized = True

    def _create_chain(self, chain: str, apply_prefix: bool = True) -> str:
        """Generate chain creation command if needed.

        The name is checked only once the chain turns out to need creating.
        This method is also handed the target of a rule, and a target that
        shares its name with a standard chain is filtered out below, not
        here - it is a target, not a name anybody chose for a chain.
        """
        if not chain:
            return ''
        if apply_prefix:
            chain = self._apply_chain_prefix(chain)

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if not self.minus_n_tracker_initialized:
            self.initialize_minus_n_tracker()

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

        Only the wording differs between the output formats; which name is
        declared, whether it needs declaring at all and whether iptables
        would accept it are decided once, in :meth:`_create_chain`.  The
        restore formats used to answer all four questions again and got the
        first one wrong, declaring the unprefixed name while the rules
        referred to the prefixed one.
        """
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        iptables_cmd = '$IP6TABLES' if ipt_comp.ipv6_policy else '$IPTABLES'
        opt_wait = get_wait_option(self.version)
        if opt_wait:
            opt_wait += ' '
        my_table = getattr(ipt_comp, 'my_table', 'filter')
        table_opt = f' -t {my_table}' if my_table != 'filter' else ''
        return f'{iptables_cmd} {opt_wait}-N {chain}{table_opt} 2>/dev/null\n'

    # -- Rule components --

    def _print_rule_label(self, rule: CompRule) -> str:
        """Print rule label as comment block."""
        label = rule.label
        if not label or label == self.current_rule_label:
            self.current_rule_label = label if label else ''
            return ''

        res = []
        if not self.compiler.single_rule_compile_mode:
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

        if rule.compiler_message:
            res.append(rule.compiler_message)

        self.current_rule_label = label
        if res:
            return '\n'.join(res) + '\n'
        return ''

    def _apply_chain_prefix(self, chain: str) -> str:
        """Apply the coexistence chain prefix if one is configured."""
        prefix = getattr(self.compiler, 'chain_prefix', '')
        if prefix and chain:
            return f'{prefix}_{chain}'
        return chain

    def _prefix_chain(self, chain: str) -> str:
        """Return the chain a rule is written to, reporting a name iptables
        would refuse.

        The bookkeeping of which chains exist goes through
        :meth:`_apply_chain_prefix` instead: it seeds itself with the
        standard chains, which carry the names of the targets the compiler
        emits, and those are not chain names the administrator chose.
        """
        chain = self._apply_chain_prefix(chain)
        check_chain_name(self.compiler, chain, self.reported_long_chains)
        return chain

    def _print_chain(self, rule: CompRule) -> str:
        chain = rule.ipt_chain
        if not chain:
            chain = 'UNKNOWN'
        return self._prefix_chain(chain) + ' '

    def _print_direction_and_interface(self, rule: CompRule) -> str | None:
        """Print -i/-o interface matching, None when the rule cannot carry it."""
        if rule.iface_label == 'nil':
            return ''

        direction = rule.direction
        if direction not in (Direction.Inbound, Direction.Outbound):
            return ''

        inbound = direction == Direction.Inbound

        if rule.is_itf_any():
            # On FORWARD / PREROUTING / POSTROUTING chains, add wildcard
            # interface match (-i + / -o +) to indicate traffic direction.
            # INPUT/OUTPUT chains don't need this because the chain itself
            # implies direction.  Matches fwbuilder output.
            if rule.ipt_chain in ('FORWARD', 'PREROUTING', 'POSTROUTING'):
                return '-i + ' if inbound else '-o + '
            return ''

        iface_obj = rule.itf[0] if rule.itf else None
        if iface_obj is None or not isinstance(iface_obj, Interface):
            return ''

        iface_name = iface_obj.name
        if not iface_name:
            return ''
        if not check_interface_name(
            self.compiler, iface_name, self.reported_long_ifaces
        ):
            return None

        # iptables spells a trailing wildcard '+', fwbuilder stores '*'.
        if iface_name.endswith('*'):
            iface_name = iface_name[:-1] + '+'

        if iface_obj.is_bridge_port() and (
            not self.version or version_compare(self.version, '1.3.0') >= 0
        ):
            return self._print_bridge_port(rule, iface_obj, iface_name, inbound)

        option = '-i' if inbound else '-o'
        return (
            self._print_single_option_with_negation(option, rule, 'itf', iface_name)
            + ' '
        )

    def _print_bridge_port(
        self, rule: CompRule, iface_obj, iface_name: str, inbound: bool
    ) -> str:
        """Print the interface match of a rule that names a bridge port.

        In the filter and mangle tables a bridged packet carries the bridge
        device as its in/out device, not the port it came in on
        (``nf_bridge_get_physindev`` in the netfilter ``xt_physdev`` module
        is what holds the port), so ``-i <port>`` never matches.  The port
        is matched with ``-m physdev`` instead.

        ``--physdev-out`` alone stopped matching non-bridged traffic in
        iptables 1.2.9, so the outbound form adds ``--physdev-is-bridged``.
        And because several bridges can share one wildcard port name
        (``vnet+`` on both br0 and br1), the parent bridge is named as well
        once the firewall has more than one bridge, so the rule still tells
        the two apart.  Same as C++
        ``PolicyCompiler_ipt::PrintRule::_printDirectionAndInterface``.

        A negated interface element negates the port match, not the bridge
        it hangs on: "everything except what comes in on vnet0" still only
        concerns that bridge.  Both physdev options carry XTOPT_INVERT
        (netfilter extensions/libxt_physdev.c), so the ``!`` goes where the
        non-bridge branch puts it.  Without it the rule loads and matches
        the exact opposite set of packets, and nothing reports that.
        """
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        parent = getattr(iface_obj, 'parent_interface', None)
        parent_name = parent.name if parent is not None else ''

        parts = []
        name_the_bridge = (
            ipt_comp.bridge_count > 1 and iface_name.endswith('+') and parent_name
        )
        if inbound:
            if name_the_bridge:
                parts.append(f'-i {parent_name}')
            option = self._print_single_option_with_negation(
                '--physdev-in', rule, 'itf', iface_name
            )
            parts.append(f'-m physdev {option.rstrip()}')
        else:
            if name_the_bridge:
                parts.append(f'-o {parent_name}')
            option = self._print_single_option_with_negation(
                '--physdev-out', rule, 'itf', iface_name
            )
            parts.append(f'-m physdev --physdev-is-bridged {option.rstrip()}')
        return ' '.join(parts) + ' '

    def _print_protocol(self, srv) -> str:
        """Print protocol matching.

        CustomService: check if the platform code already contains
        ``-p`` to avoid duplicating the protocol flag.
        TagService/UserService: skip protocol output (they are
        protocol-independent).
        """
        if isinstance(srv, CustomService):
            ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
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
                # fwbuilder asymmetry: for ip6tables it only adds
                # ``-m icmp6`` when a concrete icmpv6-type is set.
                # A bare ``any`` ICMP6 service stays as ``-p ipv6-icmp``.
                codes = getattr(srv, 'codes', None) or getattr(srv, 'data', None) or {}
                raw_type = codes.get('type', -1)
                try:
                    icmp_type = int(raw_type) if raw_type is not None else -1
                except (TypeError, ValueError):
                    icmp_type = -1
                if icmp_type < 0:
                    return '-p ipv6-icmp '
                return '-p ipv6-icmp -m icmp6 '
            return '-p icmp  -m icmp '
        elif isinstance(srv, IPService):
            proto = srv.get_protocol_number()
            if proto >= 0:
                return f'-p {proto} '
        return ''

    def _print_multiport(self, rule: CompRule) -> str:
        """Print -m multiport if rule has multiple services."""
        if len(rule.srv) > 1 and rule.ipt_multiport:
            return ' -m multiport '
        return ''

    def _print_address_table(self, obj, rule: CompRule, slot: str) -> str | None:
        """Print the match for an address table that is read on the firewall.

        With the ipset module the table is a named set and the match reads
        it directly.  Without it the address comes from a shell variable
        that the wrapper around the command assigns per line of the file
        (fwbuilder ``_printIpSetMatch`` / ``_printAddr``).

        Returns ``None`` when the pinned iptables has no ``set`` match, so
        the caller can leave the rule out.
        """
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        source = get_address_table_source(obj)
        oscnf = getattr(ipt_comp, 'oscnf', None)
        ipv6 = bool(getattr(ipt_comp, 'ipv6_policy', False))
        if oscnf is not None:
            oscnf.register_multi_address_object(obj.name, source, ipv6)

        if getattr(ipt_comp, 'using_ipset', False):
            # MATCH_FIRST_RELEASE carries the row for exactly this, but
            # nothing asked it: `libxt_set.c` first shipped in v1.4.9 and
            # there never was a `libip6t_set.c`, so an older ip6tables
            # answers "Couldn't load match `set'" and the activation script
            # stops with the built-in policies already at DROP.
            if not self._match_available(rule, 'set'):
                return None
            # `--set` was renamed in iptables 1.4.4 and only kept as a
            # deprecated alias since (netfilter extensions/libxt_set.c).
            option = (
                '--match-set'
                if version_compare(self.version, '1.4.4') >= 0
                else '--set'
            )
            suffix = 'src' if slot == 'src' else 'dst'
            match = f'{option} {normalize_set_name(obj.name, ipv6)} {suffix}'
            return f'-m set {self._print_single_option_with_negation("", rule, slot, match)}'

        rule.set_option('address_table_file', source)
        var = get_address_table_var_name(obj)
        flag = ' -s' if slot == 'src' else ' -d'
        return self._print_single_option_with_negation(flag, rule, slot, f'${var}')

    def _print_src_addr_from_rule(self, rule: CompRule) -> str | None:
        """Print the source match, None when the object could not be rendered."""
        if rule.is_src_any():
            return ''
        obj = rule.src[0] if rule.src else None
        if obj is None:
            return ''
        if isinstance(obj, PhysAddress):
            return self._print_mac_source(obj, rule)
        if isinstance(obj, AddressRange):
            return self._print_address_range(obj, rule, 'src')
        if is_run_time_address_table(obj):
            return self._print_address_table(obj, rule, 'src')
        addr = self._print_addr(obj)
        if addr:
            return self._print_single_option_with_negation(' -s', rule, 'src', addr)
        self.compiler.error(
            rule, f'Could not resolve a source address for "{obj.name}"'
        )
        return None

    def _print_dst_addr_from_rule(self, rule: CompRule) -> str | None:
        """Print the destination match, None when it could not be rendered."""
        if rule.is_dst_any():
            return ''
        obj = rule.dst[0] if rule.dst else None
        if obj is None:
            return ''
        if isinstance(obj, PhysAddress):
            # The mac module only matches the source address; iptables has
            # no destination equivalent.
            self.compiler.error(
                rule,
                f'MAC address "{obj.get_address()}" cannot be used as a '
                'destination, iptables can only match the source MAC',
            )
            return None
        if isinstance(obj, AddressRange):
            return self._print_address_range(obj, rule, 'dst')
        if is_run_time_address_table(obj):
            return self._print_address_table(obj, rule, 'dst')
        addr = self._print_addr(obj)
        if addr:
            return self._print_single_option_with_negation(' -d', rule, 'dst', addr)
        self.compiler.error(
            rule, f'Could not resolve a destination address for "{obj.name}"'
        )
        return None

    def _print_mac_source(self, obj: PhysAddress, rule: CompRule) -> str | None:
        """Print a MAC address match, None when the object carries no MAC.

        iptables cannot match a MAC with ``-s``, it needs the mac module
        (fwbuilder does the same in PolicyCompiler_PrintRule.cpp).  An object
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
        # The `!` of the extrapositioned form goes between `-m mac` and
        # `--mac-source`: `--mac-source` carries XTOPT_INVERT (netfilter
        # extensions/libxt_mac.c), while `-m mac!` is not a module iptables
        # knows and a `!` in front of the `-m` is a parse error of its own,
        # "unexpected ! flag before --match" (iptables xshared.c,
        # command_match).
        neg = self._print_single_option_with_negation('--mac-source', rule, 'src', mac)
        return f' -m mac {neg}'

    def _print_address_range(self, obj: AddressRange, rule: CompRule, slot: str) -> str:
        """Print AddressRange with ``-m iprange``.

        Corresponds to fwbuilder's AddressRange handling in
        ``_printSrcAddrFromRule`` / ``_printDstAddrFromRule``.  When
        start and end align with an exact CIDR block the shorter
        ``-s <cidr>`` / ``-d <cidr>`` form is emitted (matching
        fwbuilder and avoiding the ``xt_iprange`` kernel module).
        Otherwise ``-m iprange --src-range``/``--dst-range`` is used;
        a single address falls back to plain ``-s``/``-d``.
        """
        start = obj.get_start_address()
        end = obj.get_end_address()
        if not start:
            return ''
        flag = '-s' if slot == 'src' else '-d'
        if end and start != end:
            cidr = range_to_cidr(start, end)
            if cidr:
                return self._print_single_option_with_negation(flag, rule, slot, cidr)
            range_flag = '--src-range' if slot == 'src' else '--dst-range'
            option = self._print_single_option_with_negation(
                range_flag, rule, slot, f'{start}-{end}'
            )
            return f'-m iprange {option}'
        return self._print_single_option_with_negation(flag, rule, slot, start)

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
                ipv6 = self.compiler.ipv6_policy
                suffix = 'v6' if ipv6 else ''
                var = get_interface_var_name(obj, suffix=suffix)
                return f'${var} '
            addr = self._select_af_address(getattr(obj, 'addresses', []))
            if addr is not None:
                return self._print_addr_basic(addr)
            return ''

        return self._print_addr_basic(obj)

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

    def _print_addr_basic(self, obj) -> str:
        """Print basic address in CIDR notation."""
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
                return f'{addr.get_address()} '
            return ''

        if isinstance(obj, DNSName):
            # Runtime DNSName — use the DNS record directly as address
            return f'{(obj.data or {}).get("dnsrec", obj.name)} '

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
                    # A host mask says nothing and is left out, the way
                    # fwbuilder's InetAddr::isHostMask() decides it: what
                    # counts as one depends on the address family.  Testing
                    # against 32 alone would strip the prefix off an IPv6
                    # /32 -- the size of a provider allocation -- and turn
                    # the match into a single host.
                    if length != net.max_prefixlen:
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

        # Multiple services — use multiport (requires ipt_multiport flag)
        if rule.ipt_multiport and isinstance(srv, (TCPService, UDPService)):
            port_strs = []
            for s in rule.srv:
                p = self._print_dst_ports_value(s)
                if p:
                    port_strs.append(p)
            if port_strs:
                return f' --dports {",".join(port_strs)} '

        # Fallback: print first service only (should not happen if pipeline
        # is correct, but avoids generating --dports without -m multiport)
        return self._print_dst_ports(srv)

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
            # fwbuilder: ``--icmp-type any`` for IPv4, omit for IPv6.
            if self.compiler.ipv6_policy:
                return ''
            return f' {flag} any '
        if icmp_code < 0:
            return f' {flag} {icmp_type} '
        return f' {flag} {icmp_type}/{icmp_code}  '

    def _match_available(self, rule: CompRule, match: str) -> bool:
        return match_available(self.compiler, rule, self.version, match)

    def _print_ip_service_options(self, rule: CompRule, srv) -> str | None:
        """Print IPService options (fragments, TOS/DSCP, IP options, TCP flags).

        Matches fwbuilder PolicyCompiler_PrintRule::_printIP().

        Returns ``None`` when the pinned iptables cannot carry one of the
        options, so the caller can leave the rule out; emitting it without
        the option would apply it to traffic the rule does not name.
        """
        if srv is None:
            return ''
        parts = []
        if isinstance(srv, IPService):
            data = srv.data or {}
            # Fragments
            if _is_true(data.get('fragm')) or _is_true(data.get('short_fragm')):
                if self.compiler.ipv6_policy:
                    parts.append('-m frag --fragmore')
                else:
                    parts.append('-f')
            # TOS / DSCP
            tos = data.get('tos', '')
            dscp = data.get('dscp', '')
            if (tos and not self._match_available(rule, 'tos')) or (
                dscp and not self._match_available(rule, 'dscp')
            ):
                return None
            if tos:
                parts.append(f'-m tos --tos {tos}')
            elif dscp:
                if not is_valid_dscp(dscp):
                    # An unknown DiffServ class (e.g. "AF4") is rejected by
                    # iptables at load time; report it instead of emitting a
                    # rule that fails to load.
                    self.compiler.error(
                        rule,
                        f'IP service has an invalid DSCP value "{dscp}"; '
                        'use a DiffServ class (for example AF41) or a numeric '
                        'code point',
                    )
                # Symbolic DiffServ class names use --dscp-class
                # (matches fwbuilder PolicyCompiler_PrintRule::_printIP)
                elif dscp[:2].upper() in ('AF', 'BE', 'CS', 'EF'):
                    parts.append(f'-m dscp --dscp-class {dscp}')
                else:
                    parts.append(f'-m dscp --dscp {dscp}')
            # IP options (IPv4 only)
            if not self.compiler.ipv6_policy:
                ip_opts, problem = ipv4_options_match(data, self.version)
                if problem:
                    self.compiler.warning(rule, problem)
                if ip_opts:
                    parts.append(ip_opts)
                elif problem:
                    # The match cannot be written; without it the rule would
                    # apply to every packet, options or not.
                    return None
            elif has_ip_options(data):
                self.compiler.error(
                    rule,
                    'IP service matching an IPv4 header option cannot be '
                    'compiled for IPv6, which has no such field; the rule is '
                    'left out of the IPv6 ruleset',
                )
                return None
        if isinstance(srv, TCPService):
            flags = self._print_tcp_flags(srv)
            if flags:
                parts.append(flags)
        if not parts:
            return ''
        # Every fragment of the command line ends with a space, otherwise the
        # next one (`-m time`, `-m limit`) is glued to the last argument here
        # and iptables reads them as one token.
        return ' '.join(parts) + ' '

    def _print_custom_services(self, rule: CompRule, srv) -> str | None:
        """Print CustomService, TagService and UserService matching.

        Corresponds to the CustomService/TagService/UserService blocks
        inside fwbuilder's PolicyCompiler_PrintRule::_printDstService().

        Returns ``None`` when the object carries nothing to match on, so the
        caller can leave the rule out.  Emitting it without the match would
        apply it to every protocol and port instead of the one service the
        rule names.
        """
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        neg = self._print_single_object_negation(rule, 'srv')

        if isinstance(srv, CustomService):
            code = (srv.codes or {}).get(ipt_comp.my_platform_name(), '')
            if not code:
                # VerifyCustomServices already reported the missing code.
                return None
            return f'{neg}{code} '

        if isinstance(srv, TagService):
            tag_code = srv.get_code()
            if not tag_code:
                self.compiler.error(
                    rule, f'Tag service "{srv.name}" carries no tag to match on'
                )
                return None
            option = self._print_single_option_with_negation(
                '--mark', rule, 'srv', tag_code
            )
            return f'-m mark {option}'

        if isinstance(srv, UserService):
            uid = srv.userid or ''
            if not uid:
                self.compiler.error(
                    rule, f'User service "{srv.name}" names no user to match on'
                )
                return None
            option = self._print_single_option_with_negation(
                '--uid-owner', rule, 'srv', uid
            )
            return f'-m owner {option}'

        return ''

    def _print_tcp_flags(self, srv) -> str:
        """Format TCP flags for iptables ``--tcp-flags MASK COMP``.

        Matches fwbuilder PolicyCompiler_PrintRule::_printTCPFlags(); the
        service decides which flags go into MASK and COMP.
        """
        mask_names, comp_names = srv.tcp_flag_match()
        if not mask_names:
            return ''
        if len(mask_names) == len(srv.TCP_FLAG_ORDER):
            mask_str = 'ALL'
        else:
            mask_str = ','.join(f.upper() for f in mask_names)
        comp_str = ','.join(f.upper() for f in comp_names) if comp_names else 'NONE'
        return f'--tcp-flags {mask_str} {comp_str}'

    def _print_modules(self, rule: CompRule, command_line: str = '') -> str:
        """Print module matching (state, conntrack, etc.)."""
        stateless = rule.get_option('stateless', False)
        force_state = rule.force_state_check
        if not stateless or force_state:
            if version_compare(self.version, '1.4.4') >= 0:
                state_module_option = 'conntrack --ctstate'
            else:
                state_module_option = 'state --state'

            if f'-m {state_module_option}' not in command_line:
                return f' -m {state_module_option} NEW '

        return ''

    def _print_time_interval(self, rule: CompRule) -> str | None:
        """Print ``-m time`` matching for time/weekday constraints.

        Ports fwbuilder's ``PolicyCompiler_ipt::PrintRule::_printTimeInterval``
        (PolicyCompiler_PrintRule.cpp:1387), without the ``--datestart`` /
        ``--datestop`` branch: an Interval that pins a calendar date is not
        modelled here.

        The option names depend on the iptables version. The time module was
        rewritten in 1.4.0: the weekday list is ``--days`` before that and
        ``--weekdays`` since (netfilter extensions/libxt_time.c), and
        ``--kerneltz`` only exists from 1.4.11 on.  That rewrite is also
        when the match reached ip6tables at all, so an older ip6tables gets
        no time match; returns ``None`` then, so the caller can leave the
        rule out instead of running it around the clock.
        """
        if not rule.when:
            return ''

        interval = rule.when[0]
        data = interval.data or {}

        if is_any_interval(data):
            return ''

        if not self._match_available(rule, 'time'):
            return None

        start_h, start_m, end_h, end_m, days = parse_interval_data(data)

        parts = ['-m time']
        parts.append(f'--timestart {start_h:02d}:{start_m:02d}')
        parts.append(f'--timestop {end_h:02d}:{end_m:02d}')

        if sorted(days) != list(range(7)):
            day_names = ','.join(DOW_NAMES_SHORT[d] for d in days)
            weekdays_opt = (
                '--weekdays'
                if version_compare(self.version, '1.4.0') >= 0
                else '--days'
            )
            parts.append(f'{weekdays_opt} {day_names}')

        if version_compare(self.version, '1.4.11') >= 0 and self.compiler.fw.get_option(
            'use_kerneltz'
        ):
            parts.append('--kerneltz')

        return ' '.join(parts) + ' '

    def _print_connlimit(self, rule: CompRule) -> str | None:
        """Print ``-m connlimit``, the limit on concurrent connections.

        Ports ``PolicyCompiler_PrintRule.cpp:301``.  The option counts the
        connections of one source address, or of the ``/mask`` block it sits
        in, and the rule matches while that count is *above* the limit; the
        editor's "not" turns it into "up to", which the match expresses with
        its own ``!`` (``--connlimit-above`` carries XTOPT_INVERT, netfilter
        extensions/libxt_connlimit.c).

        Returns ``None`` when the pinned iptables has no such match, so the
        caller can leave the rule out: a rule that silently loses its limit
        accepts every connection or drops every one, depending on its
        action, instead of the ones over the limit.
        """
        try:
            limit = int(rule.get_option('connlimit_value', 0) or 0)
        except (TypeError, ValueError):
            return ''
        if limit <= 0:
            return ''
        if not self._match_available(rule, 'connlimit'):
            return None

        negated = bool(rule.get_option('connlimit_above_not', False))
        neg = '! ' if negated else ''
        result = f' -m connlimit {neg}--connlimit-above {limit}'
        try:
            masklen = int(rule.get_option('connlimit_masklen', 0) or 0)
        except (TypeError, ValueError):
            masklen = 0
        if masklen > 0:
            result += f' --connlimit-mask {masklen}'
        return result + ' '

    #: The four things a hashlimit can key its buckets on, in the order
    #: iptables prints them (PolicyCompiler_PrintRule.cpp:334).
    _HASHLIMIT_MODES = ('srcip', 'dstip', 'srcport', 'dstport')

    def _hashlimit_mode(self, rule: CompRule) -> str:
        """Return the ``--hashlimit-mode`` list the rule asks for.

        Firewall Builder stored one string in v2.1 and four booleans from
        v3 on, and an imported file can carry either, so both are read.
        The GUI writes the booleans without the ``mode_`` infix, which is a
        third spelling of the same four.
        """
        stored = str(rule.get_option('hashlimit_mode', '') or '').strip()
        if stored:
            return stored
        modes = [
            mode
            for mode in self._HASHLIMIT_MODES
            if rule.get_option(f'hashlimit_mode_{mode}', False)
            or rule.get_option(f'hashlimit_{mode}', False)
        ]
        return ','.join(modes)

    def _print_hashlimit(self, rule: CompRule) -> str | None:
        """Print ``-m hashlimit``, the rate limit kept per source or port.

        Ports ``PolicyCompiler_PrintRule.cpp:312``.  Every option of the
        match is spelled with the module's own name, and the module is
        called ``dstlimit`` in its older incarnation, which is why the name
        is a variable rather than a literal.

        Returns ``None`` when the pinned iptables has no such match, so the
        caller can leave the rule out rather than let a rule meant to cap a
        rate through unconditionally.
        """
        try:
            limit = int(rule.get_option('hashlimit_value', 0) or 0)
        except (TypeError, ValueError):
            return ''
        if limit <= 0:
            return ''
        if not self._match_available(rule, 'hashlimit'):
            return None

        module = (
            'dstlimit'
            if rule.get_option('hashlimit_dstlimit', False)
            else ('hashlimit')
        )
        if (
            module == 'dstlimit'
            and version_compare(self.version, DSTLIMIT_LAST_RELEASE) > 0
        ):
            # Same class as the ipv4options match: the option is honoured,
            # because an administrator who ticked it means it, but the
            # module it names has not been in iptables since 1.3.8 and the
            # command answers "Couldn't load match", which stops the
            # activation script.
            self.compiler.warning(rule, DSTLIMIT_NOTE)
        parts = [
            f'-m {module}',
            f'--{module} {limit}{rule.get_option("hashlimit_suffix", "") or ""}',
        ]

        def number(key: str) -> int:
            try:
                return int(rule.get_option(key, 0) or 0)
            except (TypeError, ValueError):
                return 0

        burst = number('hashlimit_burst')
        if burst > 0:
            parts.append(f'--{module}-burst {burst}')

        mode = self._hashlimit_mode(rule)
        if mode:
            parts.append(f'--{module}-mode {mode}')

        # The name is what the module files its hash table under, and it is
        # mandatory (XTOPT_MAND, netfilter extensions/libxt_hashlimit.c), so
        # a rule that names none gets one derived from its position, the way
        # fwbuilder does it.
        name = str(rule.get_option('hashlimit_name', '') or '').strip()
        if not name:
            name = f'htable_rule_{rule.position}'
        parts.append(f'--{module}-name {name}')
        self._check_hashlimit_table(rule, name, limit, mode)

        for key, option in (
            ('hashlimit_size', 'htable-size'),
            ('hashlimit_max', 'htable-max'),
            ('hashlimit_expire', 'htable-expire'),
            ('hashlimit_gcinterval', 'htable-gcinterval'),
        ):
            value = number(key)
            if value > 0:
                parts.append(f'--{module}-{option} {value}')

        return ' ' + ' '.join(parts) + ' '

    def _check_hashlimit_table(
        self, rule: CompRule, name: str, limit: int, mode: str
    ) -> None:
        """Warn when a second rule asks the same hash table for something else.

        The kernel looks a hash table up by its name and family alone
        (net/netfilter/xt_hashlimit.c, htable_find_get) and hands the
        existing one back, configuration and all.  So the rate and the mode
        of the second rule are never applied: it counts into the first
        rule's buckets at the first rule's rate, which is not what the
        editor shows and what nothing at activation time says a word about.
        """
        if getattr(self.compiler, 'muted_now', False):
            # Optimize3 renders every rule a second time to compare the
            # command; registering the table there would report the rule
            # against itself.
            return
        tables = self.compiler.hashlimit_tables
        shape = (limit, rule.get_option('hashlimit_suffix', '') or '', mode)
        first = tables.setdefault(name, shape)
        if first != shape:
            self.compiler.warning(
                rule,
                f'the rate limit table "{name}" is already in use by another '
                'rule with a different rate or a different key; the kernel '
                'keeps the settings of the first one for both',
            )

    def _print_limit(self, rule: CompRule) -> str:
        """Print ``-m limit`` rate limiting.

        fwbuilder applies the limit configured in the firewall settings to
        log rules and the limit configured on the rule itself to every
        other rule (PolicyCompiler_PrintRule.cpp:271).
        """
        negated = False
        if rule.ipt_target in LOG_TARGETS:
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

        if negated:
            # The limit match has no inverted form: --limit carries no
            # XTOPT_INVERT (netfilter extensions/libxt_limit.c), and
            # xtables_option_parse() answers a leading "!" with
            # 'option "--limit" cannot be inverted'
            # (netfilter libxtables/xtoptions.c).  Emitting the rule with a
            # plain --limit would turn "only above this rate" into "only
            # below it", so the condition is reported instead.  nftables
            # writes it as `limit rate over`.
            self.compiler.error(
                rule,
                'Rate limit is negated, which the iptables limit match cannot '
                'express; the rule is left without it',
            )
            return ''

        limit_suffix = limit_suffix or '/second'
        try:
            burst = int(burst)
        except (ValueError, TypeError):
            burst = 0

        max_rate = XT_LIMIT_SCALE * LIMIT_UNIT_SECONDS.get(limit_suffix, 1)
        if limit_val > max_rate:
            self.compiler.error(
                rule,
                f'Rate limit {limit_val}{limit_suffix} is faster than iptables '
                f'can express; the limit match tops out at {max_rate}'
                f'{limit_suffix}',
            )
            return ''
        if burst > MAX_LIMIT_BURST:
            self.compiler.error(
                rule,
                f'Rate limit burst {burst} is out of range; iptables accepts '
                f'0 to {MAX_LIMIT_BURST}',
            )
            return ''

        result = f'-m limit --limit {limit_val}{limit_suffix}'
        if burst > 0:
            result += f' --limit-burst {burst}'
        return result

    # Standard iptables targets that must never be prefixed.
    _BUILTIN_TARGETS = frozenset(
        {
            'ACCEPT',
            'DROP',
            'LOG',
            'MARK',
            'NFLOG',
            'QUEUE',
            'REDIRECT',
            'REJECT',
            'RETURN',
            'CLASSIFY',
            'CONNMARK',
            'DNAT',
            'MASQUERADE',
            'NETMAP',
            'NOTRACK',
            'ROUTE',
            'SNAT',
            'TCPMSS',
            'ULOG',
        }
    )

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

    def _target_available(self, rule: CompRule, target: str) -> bool:
        """Whether the pinned iptables knows a target, for this family.

        Reports the reason once per rule and leaves the answer to the
        caller, which drops the rule: a classifying or marking rule exists
        only for its target, so emitting it without one would install a
        rule that counts packets and does nothing.  The alternative is
        worse - ip6tables answers "Couldn't load target" and stops the
        activation script with every built-in policy already set to DROP.
        """
        first = TARGET_FIRST_RELEASE[target][bool(self.compiler.ipv6_policy)]
        if version_compare(self.version, first) >= 0:
            return True
        tool = 'ip6tables' if self.compiler.ipv6_policy else 'iptables'
        self.compiler.error(
            rule,
            f'{tool} before {first} has no "{target}" target; the rule is left out',
        )
        return False

    def _print_target(self, rule: CompRule) -> str | None:
        """Print the ``-j`` part, or ``None`` when the rule cannot be built."""
        # Tagging and classification pick their own target and carry the
        # value with it, so they come before the generic target mapping
        # (fwbuilder PolicyCompiler_PrintRule::_printTarget).
        if rule.get_option('tagging', False):
            tag_value = self._get_tag_value(rule)
            if not tag_value:
                self.compiler.error(
                    rule,
                    'tagging rule has no Tag Service to take the mark from',
                )
                return ''
            return f' -j MARK --set-mark {tag_value}'

        if rule.get_option('classification', False):
            classify_str = rule.get_option('classify_str', '')
            if not classify_str:
                self.compiler.error(
                    rule,
                    'classification rule has no traffic class to set',
                )
                return ''
            if not self._target_available(rule, 'CLASSIFY'):
                return None
            return f' -j CLASSIFY --set-class {classify_str}'

        target = rule.ipt_target
        if target:
            if target == '.CUSTOM':
                # The rule carries the target verbatim, e.g. `-j TCPMSS
                # --clamp-mss-to-pmtu`.
                custom_str = rule.get_option('custom_str', '')
                if not custom_str:
                    self.compiler.error(
                        rule, 'rule with a custom action has no target to run'
                    )
                    return ''
                return f' {custom_str}'
            if target.startswith('.'):
                return ''
            if target == 'REJECT':
                reject_opt = self._print_action_on_reject(rule)
                if reject_opt:
                    return f' -j REJECT {reject_opt}'
            if target == 'CONNMARK':
                # A bare `-j CONNMARK` is refused by iptables ("No operation
                # specified"); the operation is set by SplitIfTagAndConnmark.
                connmark_arg = rule.get_option('CONNMARK_arg', '')
                if connmark_arg:
                    if not self._target_available(rule, 'CONNMARK'):
                        return None
                    return f' -j CONNMARK {connmark_arg}'
            # Prefix user-chain targets, but not built-in targets.
            if target not in self._BUILTIN_TARGETS:
                target = self._prefix_chain(target)
            return f' -j {target}'

        action_map = {
            PolicyAction.Accept: 'ACCEPT',
            PolicyAction.Deny: 'DROP',
            PolicyAction.Reject: 'REJECT',
            PolicyAction.Return: 'RETURN',
            PolicyAction.Continue: '',
        }

        action = rule.action
        target_name = (
            action_map.get(action, '') if isinstance(action, PolicyAction) else ''
        )
        if not target_name:
            return ''

        if rule.action == PolicyAction.Reject:
            reject_opt = self._print_action_on_reject(rule)
            if reject_opt:
                return f' -j REJECT {reject_opt}'

        return f' -j {target_name}'

    def _print_action_on_reject(self, rule: CompRule) -> str:
        """Print ``--reject-with`` for the reject type the rule names.

        The value is normalised by the shared helper, so the nftables
        compiler picks the same ICMP message for the same rule.  Only the
        version gate below is specific to iptables.
        """
        reject_with = rule.get_option('action_on_reject', '')
        if not reject_with:
            return ''

        is_ipv6 = getattr(self.compiler, 'ipv6_policy', False)
        token = reject_type_token(reject_with, is_ipv6)

        if not token:
            # fwbuilder's own placeholders for "no reject type here" arrive
            # here too (PolicyCompiler_ipt::resetActionOnReject); anything
            # else is a value iptables would stop the activation script on.
            if reject_with not in ('NOP', 'none'):
                self.compiler.warning(
                    rule,
                    f'Reject type "{reject_with}" is not one this platform '
                    'accepts; rejecting with the default type instead',
                )
            return ''

        first = REJECT_TOKEN_FIRST_RELEASE.get(token)
        if first and version_compare(self.version, first) < 0:
            tool = 'ip6tables' if is_ipv6 else 'iptables'
            self.compiler.warning(
                rule,
                f'{tool} before {first} does not know the reject type '
                f'"{token}"; rejecting with the default type instead',
            )
            return ''

        return f'--reject-with {token}'

    def _print_log_parameters(self, rule: CompRule) -> str:
        """Print logging parameters for LOG or NFLOG target."""
        target = rule.ipt_target
        if target == 'NFLOG':
            return self._print_nflog_parameters(rule)
        return self._print_log_parameters_standard(rule)

    def _print_log_parameters_standard(self, rule: CompRule) -> str:
        """Print standard LOG target parameters."""
        parts = []

        log_level = rule.get_option('log_level', '')
        if not log_level:
            log_level = self.compiler.fw.get_option('log_level')
        if log_level:
            # fwbuilder emits either the symbolic name (e.g. `info`) or the
            # numeric syslog level (e.g. `6`), controlled by the firewall-level
            # option `use_numeric_log_levels`.  Match that behaviour exactly so
            # recompiling the same `.fwb` / `.fwf` produces the expected form.
            use_numeric = bool(self.compiler.fw.get_option('use_numeric_log_levels'))
            if use_numeric:
                log_level = _LOG_LEVEL_MAP.get(str(log_level), log_level)
            parts.append(f'--log-level {log_level}')

        log_prefix = self._log_prefix(rule, MAX_LOG_PREFIX)
        if log_prefix:
            parts.append(f'--log-prefix {self._quote(log_prefix)}')

        # Per-rule option overrides firewall-level default (matching fwbuilder).
        fw_opt = self.compiler.fw.get_option
        if rule.get_option('log_tcp_seq', False) or fw_opt('log_tcp_seq'):
            parts.append('--log-tcp-sequence')
        if rule.get_option('log_tcp_opt', False) or fw_opt('log_tcp_opt'):
            parts.append('--log-tcp-options')
        if rule.get_option('log_ip_opt', False) or fw_opt('log_ip_opt'):
            parts.append('--log-ip-options')

        return ' '.join(parts)

    def _print_nflog_parameters(self, rule: CompRule) -> str:
        """Print NFLOG target parameters.

        NFLOG sends packets via netlink to a userspace logging daemon.
        Parameters:
        - --nflog-group N: netlink multicast group (default 1)
        - --nflog-prefix "...": log prefix string
        - --nflog-size N: bytes of packet to copy (0 = entire packet)
        - --nflog-threshold N: packets to queue before sending to userspace
        """
        parts = []

        nlgroup = self.compiler.fw.get_option('ulog_nlgroup')
        try:
            nlgroup = int(nlgroup)
        except (TypeError, ValueError):
            nlgroup = 1
        parts.append(f'--nflog-group {nlgroup}')

        log_prefix = self._log_prefix(rule, MAX_NFLOG_PREFIX)
        if log_prefix:
            parts.append(f'--nflog-prefix {self._quote(log_prefix)}')

        cprange = self.compiler.fw.get_option('ulog_cprange')
        try:
            cprange = int(cprange)
        except (TypeError, ValueError):
            cprange = 0
        if cprange > 0:
            # --nflog-range sets the length but not XT_NFLOG_F_COPY_LEN, so
            # the kernel ignores it (netfilter iptables commit 7070b1f3,
            # "nflog-range does not truncate packets").  --nflog-size, which
            # does set the flag, arrived in iptables 1.6.1; an older target
            # has no way to say this at all.
            if version_compare(self.version, '1.6.1') >= 0:
                parts.append(f'--nflog-size {cprange}')
            else:
                self.compiler.warning(
                    rule,
                    'iptables before 1.6.1 cannot limit how much of a packet '
                    'NFLOG copies to userspace; the "Copy range" setting is '
                    'left out and the whole packet is copied',
                )

        qthreshold = self.compiler.fw.get_option('ulog_qthreshold')
        try:
            qthreshold = int(qthreshold)
        except (TypeError, ValueError):
            qthreshold = 1
        if qthreshold > 1:
            parts.append(f'--nflog-threshold {qthreshold}')

        return ' '.join(parts)

    def _log_prefix(self, rule: CompRule, limit: int) -> str:
        """Return the log prefix to emit, empty when there is none left.

        The emptiness test has to come *after* the expansion: a macro can
        expand to nothing, and `sanitize_log_prefix` drops the characters
        the shell would treat as expansion or substitution, so a prefix
        made only of those ends up empty here.  Emitting it anyway gives
        `--log-prefix ""`, and both targets declare their prefix with
        `.min = 1` (netfilter extensions/libxt_LOG.c and libxt_NFLOG.c),
        which `xtopt_parse_string` (libxtables/xtoptions.c) answers with
        "Argument must have a minimum length of 1 characters" - the
        activation script stops there with the policies already at DROP.
        """
        prefix = rule.get_option('log_prefix', '')
        if not prefix:
            prefix = self.compiler.fw.get_option('log_prefix')
        if not prefix:
            return ''
        prefix = self._expand_log_prefix(rule, str(prefix))
        if not prefix:
            self.compiler.warning(
                rule,
                'Nothing is left of the log prefix once the characters the '
                'generated script cannot pass on are removed; the rule logs '
                'without one',
            )
            return ''
        return self._truncate_log_prefix(rule, prefix, limit)

    def _truncate_log_prefix(self, rule: CompRule, prefix: str, limit: int) -> str:
        """Cut *prefix* to what the target can carry, and say so.

        Ports the warning of fwbuilder's
        ``PolicyCompiler_ipt::PrintRule::_printLogPrefix``.  Silently
        cutting the prefix is how a log parser starts missing the fields
        behind it, and the nftables backend takes the full string, so the
        same policy would write differently shaped log lines on the two
        platforms without anyone noticing.
        """
        if len(prefix) <= limit:
            return prefix
        self.compiler.warning(
            rule,
            f'Log prefix "{prefix}" is longer than the {limit} characters '
            'iptables can carry and has been truncated',
        )
        return prefix[:limit]

    def _expand_log_prefix(self, rule: CompRule, prefix: str) -> str:
        """Expand log prefix macros (%N, %A, %I, %C, %R)."""
        action = (rule.stored_action or '').upper()

        ppos = rule.parent_rule_num
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
        if self.compiler.source_ruleset:
            ruleset_name = self.compiler.source_ruleset.name

        result = prefix.replace('%N', rule_num)
        result = result.replace('%A', action)
        result = result.replace('%I', iface_name)
        result = result.replace('%C', chain)
        result = result.replace('%R', ruleset_name)

        cleaned = sanitize_log_prefix(result)
        if cleaned != result:
            self.compiler.warning(
                rule,
                f'Log prefix "{result}" holds a character the generated script '
                f'cannot pass on and was written as "{cleaned}"',
            )
        return cleaned

    def _start_rule_line(self) -> str:
        """Generate rule line prefix: $IPTABLES [-w] [-t table] -A"""
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        ipv6 = ipt_comp.ipv6_policy
        res = '$IP6TABLES ' if ipv6 else '$IPTABLES '

        opt_wait = get_wait_option(self.version)
        if opt_wait:
            res += f'{opt_wait} '

        my_table = getattr(ipt_comp, 'my_table', 'filter')
        if my_table != 'filter':
            res += f'-t {my_table} '

        res += '-A '
        return res

    def _end_rule_line(self) -> str:
        return '\n'

    def _quote(self, s: str) -> str:
        """Quote an argument that may contain spaces, such as a log prefix.

        Ports fwbuilder's virtual ``PolicyCompiler_ipt::PrintRule::_quote``:
        every output format needs its own quoting, so the subclasses below
        override this.
        """
        return f'"{s}"'


class PrintRuleIptRst(PrintRule):
    """Generates rules in iptables-restore format."""

    def __init__(self, name: str = 'generate code for iptables-restore') -> None:
        super().__init__(name)

    def _chain_declaration(self, chain: str) -> str:
        # This format writes the restore stream itself, so the declaration
        # is a plain line, the way its rules are plain `-A` lines and the
        # way the NAT twin already wrote it.  It used to `echo`, which only
        # the Echo subclass below wants.
        return f':{chain} - [0:0]\n'

    def _start_rule_line(self) -> str:
        # fwbuilder PolicyCompiler_PrintRuleIptRst::_startRuleLine: ``-A ``
        return '-A '

    def _end_rule_line(self) -> str:
        # fwbuilder PolicyCompiler_PrintRuleIptRst::_endRuleLine: newline
        return '\n'

    def _print_rule_label(self, rule: CompRule) -> str:
        label = rule.label
        if label and label != self.current_rule_label:
            self.current_rule_label = label
            return f'echo "# Rule {label}"\n'
        return ''

    def _declare_table(self) -> str:
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
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

    def _chain_declaration(self, chain: str) -> str:
        # This format builds the restore stream with `echo`, so the
        # declaration is echoed like every rule line.  The quotes are
        # load-bearing: an unquoted `[0:0]` is a bracket glob, and a file
        # named `0` in the directory the script runs from would rewrite the
        # line, whereupon iptables-restore stops at the first chain.
        return f'echo ":{chain} - [0:0]"\n'

    def _start_rule_line(self) -> str:
        # fwbuilder PolicyCompiler_PrintRuleIptRstEcho::_startRuleLine
        return 'echo "-A '

    def _end_rule_line(self) -> str:
        # fwbuilder PolicyCompiler_PrintRuleIptRstEcho::_endRuleLine
        return '"\n'

    def _quote(self, s: str) -> str:
        # The whole rule is wrapped in `echo "..."`, so an inner quote has
        # to be escaped for the shell. Without the backslashes the shell
        # closes the echo argument early and the prefix loses its trailing
        # space (fwbuilder PolicyCompiler_PrintRuleIptRstEcho::_quote).
        return f'\\"{s}\\"'

    def _declare_table(self) -> str:
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        my_table = getattr(ipt_comp, 'my_table', 'filter') if ipt_comp else 'filter'
        return f'echo "*{my_table}"'

    def _commit(self) -> str:
        return 'echo "COMMIT"'
