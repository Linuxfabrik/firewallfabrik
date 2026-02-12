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

"""PolicyCompiler_ipt: iptables filter/mangle rule compilation.

Corresponds to fwbuilder's iptlib/policy_compiler_ipt.py.
Core iptables compiler with 55+ rule processors that transform
firewall policy rules into iptables commands.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    ConvertToAtomicForAddresses,
    ConvertToAtomicForInterfaces,
    DetectShadowing,
    DropIPv4Rules,
    DropIPv6Rules,
    DropRuleWithEmptyRE,
    EliminateDuplicatesInDST,
    EliminateDuplicatesInSRC,
    EliminateDuplicatesInSRV,
    EmptyGroupsInRE,
    ExpandGroups,
    ResolveMultiAddress,
    SimplePrintProgress,
)
from firewallfabrik.core.objects import (
    Address,
    Direction,
    Firewall,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    PolicyAction,
    TCPService,
    UDPService,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator

# Module-level chain counter
_chain_no = 0

STANDARD_CHAINS = [
    'INPUT',
    'OUTPUT',
    'FORWARD',
    'PREROUTING',
    'POSTROUTING',
    'RETURN',
    'LOG',
    'ACCEPT',
    'DROP',
    'REJECT',
    'MARK',
    'CONNMARK',
    'QUEUE',
    'CLASSIFY',
    'ROUTE',
]


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


class PolicyCompiler_ipt(PolicyCompiler):
    """IPT-specific policy compiler with 55+ rule processors.

    Handles:
    - Chain assignment (INPUT/OUTPUT/FORWARD/custom)
    - Negation via temporary chains
    - Interface matching
    - Multiport optimization
    - MAC address filtering
    - Logging rules
    - Action mapping to iptables targets
    - iptables-restore format
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
        oscnf: OSConfigurator | None = None,
        minus_n_commands: dict | None = None,
    ) -> None:
        super().__init__(session, fw, ipv6_policy)
        self.oscnf = oscnf

        self.have_dynamic_interfaces: bool = False
        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False
        self.my_table: str = 'filter'
        self.minus_n_commands: dict[str, bool] | None = minus_n_commands
        self.bridge_count: int = 0

        # Chain management
        self.chain_usage_counter: dict[str, int] = defaultdict(int)
        self.upstream_chains: dict[str, list[str]] = defaultdict(list)
        self.registered_chains: set[str] = set()
        self.tmp_chain_counters: dict[str, int] = {}

        # Print rule processor reference
        self.print_rule_processor = None

        # iptables version
        self.version: str = fw.version or ''

        # ipset usage flag
        self.using_ipset: bool = False
        if _version_compare(self.version, '1.4.1.1') >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set', False))

    @staticmethod
    def get_standard_chains() -> list[str]:
        return STANDARD_CHAINS

    def my_platform_name(self) -> str:
        return 'iptables'

    def prolog(self) -> int:
        """Initialize compiler: verify platform, set up interfaces."""
        for chain in self.get_standard_chains():
            self.chain_usage_counter[chain] = 1

        n = super().prolog()

        if n > 0:
            for iface in self.fw.interfaces:
                if iface.is_dynamic():
                    self.have_dynamic_interfaces = True

        return n

    def compile(self) -> None:
        """Main compilation: sets up the full rule processor pipeline."""
        banner = (
            f" Compiling ruleset {self.get_rule_set_name()} for '{self.my_table}' table"
        )
        if self.ipv6_policy:
            banner += ', IPv6'
        self.info(banner)

        super().compile()

        # -- Full processor pipeline --
        self.add(Begin('Begin compilation'))

        self.add_rule_filter()

        self.add(StoreAction('store action'))

        self.add(InterfaceAndDirection('interface+dir'))
        self.add(
            SplitIfIfaceAndDirectionBoth('split interface rule with direction both')
        )

        self.add(ResolveMultiAddress('resolve compile-time MultiAddress'))

        self.add(EmptyGroupsInRE('check for empty groups in SRC', 'src'))
        self.add(EmptyGroupsInRE('check for empty groups in DST', 'dst'))
        self.add(EmptyGroupsInRE('check for empty groups in SRV', 'srv'))
        self.add(EmptyGroupsInRE('check for empty groups in ITF', 'itf'))

        self.add(ExpandGroups('expand all groups'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))
        self.add(EliminateDuplicatesInSRC('eliminate duplicates in SRC'))
        self.add(EliminateDuplicatesInDST('eliminate duplicates in DST'))
        self.add(EliminateDuplicatesInSRV('eliminate duplicates in SRV'))

        self.add(FillActionOnReject('fill action_on_reject'))

        self.add(Logging2('process logging'))

        # -- Negation processors --
        self.add(SingleSrvNegation('single srv negation'))
        self.add(SrvNegation('process negation in Srv'))
        self.add(SingleSrcNegation('single src negation'))
        self.add(SingleDstNegation('single dst negation'))
        self.add(SplitIfSrcNegAndFw('split if src negated and fw'))
        self.add(SplitIfDstNegAndFw('split if dst negated and fw'))
        self.add(SrcNegation('process negation in Src'))
        self.add(DstNegation('process negation in Dst'))

        self.add(SplitIfSrcAny('split rule if src is any'))
        self.add(SplitIfDstAny('split rule if dst is any'))
        self.add(SplitIfSrcMatchesFw('split if src matches FW'))
        self.add(SplitIfDstMatchesFw('split if dst matches FW'))

        self.add(DecideOnChainIfDstFW('decide chain if Dst has fw'))
        self.add(SplitIfSrcFWNetwork('split rule if src has a net fw has interface on'))
        self.add(DecideOnChainIfSrcFW('decide chain if Src has fw'))
        self.add(SplitIfDstFWNetwork('split rule if dst has a net fw has interface on'))
        self.add(SpecialCaseWithFW2('replace fw with its interfaces if src==dst==fw'))
        self.add(DecideOnChainIfLoopback('any-any rule on loopback'))
        self.add(FinalizeChain('assign chain'))
        self.add(DecideOnTarget('set target'))

        self.add(RemoveFW('remove fw'))
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))

        self.add(
            CheckInterfaceAgainstAddressFamily(
                'check if interface matches address family'
            )
        )

        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))
        self.add(
            DropRuleWithEmptyRE(
                'drop rules with empty elements after address family filter'
            )
        )

        self.add(
            SpecialCaseWithUnnumberedInterface(
                'check for special cases with unnumbered interface'
            )
        )

        self.add(ConvertToAtomicForInterfaces('convert to atomic by interfaces'))

        self.add(Optimize1('optimization 1, pass 1'))
        self.add(Optimize1('optimization 1, pass 2'))
        self.add(Optimize1('optimization 1, pass 3'))

        self.add(GroupServicesByProtocol('split on services'))
        self.add(SeparatePortRanges('separate port ranges'))
        self.add(CheckForStatefulICMP6Rules('check for stateful ICMPv6 rules'))

        self.add(Optimize2('optimization 2'))

        self.add(PrepareForMultiport('prepare for multiport'))

        self.add(ConvertToAtomicForAddresses('convert to atomic by addresses'))

        self.add(Optimize3('optimization 3'))

        self.add(CheckForObjectsWithErrors('check for objects with errors'))

        if (
            self.fw.get_option('check_shading', False)
            and not self.single_rule_compile_mode
        ):
            self.add(DetectShadowing('detect rule shadowing'))

        self.add(CountChainUsage('count chain usage'))

        # Print rule
        self.add(self.create_print_rule_processor())
        self.add(SimplePrintProgress())

        self.run_rule_processors()

    def debug_print_rule(self, rule) -> str:
        """Rich debug output matching C++ PolicyCompiler_ipt::debugPrintRule."""
        src_names = [getattr(o, 'name', str(o)) for o in rule.src] or ['Any']
        dst_names = [getattr(o, 'name', str(o)) for o in rule.dst] or ['Any']
        srv_names = [getattr(o, 'name', str(o)) for o in rule.srv] or ['Any']
        itf_names = []
        for o in rule.itf:
            s = getattr(o, 'name', str(o))
            if isinstance(o, Interface):
                if o.is_dynamic():
                    s += 'D'
                if o.is_unnumbered():
                    s += 'U'
            itf_names.append(s)
        itf_names = itf_names or ['Any']

        src_neg = '!' if rule.negations.get('src') else ''
        dst_neg = '!' if rule.negations.get('dst') else ''
        srv_neg = '!' if rule.negations.get('srv') else ''
        itf_neg = '!' if rule.negations.get('itf') else ''

        lines = []
        max_rows = max(len(src_names), len(dst_names), len(srv_names), len(itf_names))
        for row in range(max_rows):
            src_col = f'{src_neg}{src_names[row]}' if row < len(src_names) else ''
            dst_col = f'{dst_neg}{dst_names[row]}' if row < len(dst_names) else ''
            srv_col = f'{srv_neg}{srv_names[row]}' if row < len(srv_names) else ''
            itf_col = f'{itf_neg}{itf_names[row]}' if row < len(itf_names) else ''

            label_col = ''
            if row == 0:
                label_col = rule.label

            line = (
                f'{label_col:15s}'
                f'{src_col:>18s}'
                f'{dst_col:>18s}'
                f'{srv_col:>12s}'
                f'{itf_col:>8s}'
            )

            if row == 0:
                action_str = str(rule.action.value) if rule.action else ''
                dir_str = str(rule.direction.value) if rule.direction else ''
                logging_str = ' LOG' if rule.options.get('logging') else ''
                line += f'{action_str:>9s}{dir_str:>9s}{logging_str}'

            lines.append(line)

        meta = f' pos={rule.position}'
        meta += f' c={rule.ipt_chain}'
        meta += f' t={rule.ipt_target}'

        iface_str = rule.iface_label
        if iface_str:
            meta += f' .iface={iface_str}'

        if rule.options.get('tagging'):
            meta += ' (tag)'
        if rule.options.get('classification'):
            meta += ' (class)'
        if rule.options.get('routing'):
            meta += ' (route)'

        if rule.action and str(rule.action.value) == 'Reject':
            aor = rule.options.get('action_on_reject', '')
            if aor:
                meta += f' {aor}'

        if rule.options.get('limit_value', 0) > 0:
            meta += ' limit'
        if rule.options.get('connlimit_value', 0) > 0:
            meta += ' connlimit'
        if rule.options.get('hashlimit_value', 0) > 0:
            meta += ' hashlimit'

        lines.append(meta)
        return '\n'.join(lines)

    def epilog(self) -> None:
        """Finalize compilation."""
        if (
            self.fw.get_option('use_iptables_restore', False)
            and self.get_compiled_script_length() > 0
            and not self.single_rule_compile_mode
        ):
            self.output.write('#\n')

    def add_rule_filter(self) -> None:
        """Drop rules that belong in the mangle table."""
        self.add(DropMangleTableRules('remove rules that require mangle table'))

    def create_print_rule_processor(self):
        """Create the appropriate PrintRule processor based on options."""
        from firewallfabrik.platforms.iptables._print_rule import (
            PrintRule,
            PrintRuleIptRstEcho,
        )

        use_restore = bool(self.fw.get_option('use_iptables_restore', False))

        if use_restore:
            pr = PrintRuleIptRstEcho('generate code for iptables-restore')
        else:
            pr = PrintRule('generate iptables shell script')

        pr.set_context(self)
        pr.initialize()
        self.print_rule_processor = pr
        return pr

    def get_rule_set_name(self) -> str:
        if self.source_ruleset:
            return self.source_ruleset.name
        return 'Policy'

    def get_compiled_script_length(self) -> int:
        return len(self.output.getvalue())

    # -- Chain management --

    def get_new_tmp_chain_name(self, rule: CompRule) -> str:
        """Generate a new temporary chain name."""
        chain_id = str(rule.id).replace('-', '')[:12]
        n = self.tmp_chain_counters.get(chain_id, 0)
        name = f'C{chain_id}.{n}'
        self.tmp_chain_counters[chain_id] = n + 1
        return name

    def get_new_chain_name(
        self,
        rule: CompRule,
        iface: Interface | None,
    ) -> str:
        """Generate a new chain name based on direction and rule position."""
        parts = []
        if iface is not None:
            iface_name = iface.name.replace('*', '')
            parts.append(f'{iface_name}_')

        direction = rule.direction
        if direction == Direction.Inbound:
            parts.append('In_')
        elif direction == Direction.Outbound:
            parts.append('Out_')

        ruleset_name = self.get_rule_set_name()
        if ruleset_name != 'Policy':
            parts.append(f'{ruleset_name}_')
        else:
            parts.append('RULE_')

        pos = rule.position
        if pos >= 0:
            parts.append(str(pos))
        else:
            parts.append('000')

        suffix = rule.subrule_suffix
        if suffix:
            parts.append(f'_{suffix}')

        return ''.join(parts)

    def register_chain(self, chain: str) -> None:
        self.registered_chains.add(chain)

    def insert_upstream_chain(self, parent: str, child: str) -> None:
        self.upstream_chains[parent].append(child)

    def register_rule_set_chain(self, chain_name: str) -> None:
        self.register_chain(chain_name)
        self.chain_usage_counter[chain_name] = 1

    def set_chain(self, rule: CompRule, chain: str) -> None:
        rule.ipt_chain = chain
        self.register_chain(chain)

    def is_chain_descendant_of_input(self, chain: str) -> bool:
        if chain == 'INPUT':
            return True
        for parent, children in self.upstream_chains.items():
            if chain in children:
                return self.is_chain_descendant_of_input(parent)
        return False

    def is_chain_descendant_of_output(self, chain: str) -> bool:
        if chain == 'OUTPUT':
            return True
        for parent, children in self.upstream_chains.items():
            if chain in children:
                return self.is_chain_descendant_of_output(parent)
        return False

    def get_used_chains(self) -> list[str]:
        return [c for c, count in self.chain_usage_counter.items() if count > 0]

    def have_connmark_rules(self) -> bool:
        return self.have_connmark

    def have_connmark_rules_in_output(self) -> bool:
        return self.have_connmark_in_output

    # -- Action helpers --

    def get_action_on_reject(self, rule: CompRule) -> str:
        return rule.get_option('action_on_reject', '') or ''

    # -- Output generation --

    def flush_and_set_default_policy(self) -> str:
        """Generate flush and default policy commands for iptables-restore."""
        if self.single_rule_compile_mode:
            return ''
        if not self.fw.get_option('use_iptables_restore', False):
            return ''

        result = ''
        result += 'echo :INPUT DROP [0:0]\n'
        result += 'echo :FORWARD DROP [0:0]\n'
        result += 'echo :OUTPUT DROP [0:0]\n'
        return result

    def print_automatic_rules(self) -> str:
        """Generate automatic rules using the automatic_rules configlet."""
        from firewallfabrik.driver._configlet import Configlet

        if self.single_rule_compile_mode:
            return ''

        version = self.version
        ipv6 = self.ipv6_policy
        iptables_cmd = '$IP6TABLES' if ipv6 else '$IPTABLES'

        use_restore = bool(self.fw.get_option('use_iptables_restore', False))

        begin_rule = '' if use_restore else f'{iptables_cmd} -A'

        if _version_compare(version, '1.4.4') >= 0:
            state_module_option = 'conntrack --ctstate'
        else:
            state_module_option = 'state --state'

        conf = Configlet('linux24', 'automatic_rules')
        conf.collapse_empty_strings(True)

        conf.set_variable('begin_rule', begin_rule)
        conf.set_variable('end_rule', '')
        conf.set_variable('state_module_option', state_module_option)

        conf.set_variable(
            'accept_established',
            1 if self.fw.get_option('accept_established', False) else 0,
        )

        ipv4_fwd = self.fw.get_option('linux24_ip_forward', '')
        ipforw = str(ipv4_fwd) in ('1', 'On', 'on', '')
        conf.set_variable('ipforw', 1 if ipforw else 0)

        conf.set_variable('mgmt_access', 0)
        conf.set_variable(
            'bridging_firewall', 1 if self.fw.get_option('bridging_fw', False) else 0
        )
        conf.set_variable(
            'drop_new_tcp_with_no_syn',
            1 if self.fw.get_option('drop_new_tcp_with_no_syn', False) else 0,
        )
        conf.set_variable(
            'add_rules_for_ipv6_neighbor_discovery',
            1 if (ipv6 and self.fw.get_option('ipv6_neighbor_discovery', False)) else 0,
        )

        drop_invalid = self.fw.get_option('drop_invalid', False)
        log_invalid = self.fw.get_option('log_invalid', False)
        conf.set_variable(
            'drop_invalid', 1 if (drop_invalid and not log_invalid) else 0
        )
        conf.set_variable(
            'drop_invalid_and_log', 1 if (drop_invalid and log_invalid) else 0
        )

        conf.set_variable('not_use_ulog', 1)
        conf.set_variable('use_ulog', 0)
        conf.set_variable('use_nlgroup', 0)
        conf.set_variable('use_cprange', 0)
        conf.set_variable('use_qthreshold', 0)
        conf.set_variable('invalid_match_log_prefix', '"INVALID "')

        return conf.expand()

    def commit(self) -> str:
        """Generate COMMIT for iptables-restore format."""
        if self.fw.get_option('use_iptables_restore', False):
            return "echo 'COMMIT'\n"
        return ''


# ═══════════════════════════════════════════════════════════════════
# Rule Processors
# ═══════════════════════════════════════════════════════════════════


class _Passthrough(PolicyRuleProcessor):
    """Base for processors that pass rules through (stub)."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)
        return True


class DropMangleTableRules(PolicyRuleProcessor):
    """Drop rules that belong in the mangle table."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        rs = self.compiler.source_ruleset
        if rs is not None:
            mangle_only = (
                rs.options.get('mangle_only_rule_set', False) if rs.options else False
            )
            if isinstance(mangle_only, str):
                mangle_only = mangle_only.lower() == 'true'
            if mangle_only:
                return True  # drop

        if (
            rule.action == PolicyAction.Continue
            and not rule.get_option('log', False)
            and (
                rule.get_option('tagging', False)
                or rule.get_option('routing', False)
                or rule.get_option('classification', False)
            )
        ):
            return True  # drop

        self.tmp_queue.append(rule)
        return True


class StoreAction(PolicyRuleProcessor):
    """Store original action before any transformations."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        action_str = rule.action.name if rule.action else ''
        rule.stored_action = action_str
        self.tmp_queue.append(rule)
        return True


class Logging2(PolicyRuleProcessor):
    """Process logging — create log chain with LOG + action rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_option('log', False):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        # Special case: Continue action without tagging/classification/routing
        if (
            rule.action == PolicyAction.Continue
            and not rule.get_option('tagging', False)
            and not rule.get_option('classification', False)
            and not rule.get_option('routing', False)
        ):
            rule.ipt_target = 'LOG'
            self.tmp_queue.append(rule)
            return True

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_chain_name(rule, None)

        # 1) Jump rule: from current chain to new_chain
        r = rule.clone()
        r.ipt_target = new_chain
        r.set_option('classification', False)
        r.set_option('routing', False)
        r.set_option('tagging', False)
        r.set_option('log', False)
        r.action = PolicyAction.Continue
        self.tmp_queue.append(r)

        # 2) LOG rule in new_chain: all elements reset to any
        r2 = rule.clone()
        r2.src = []
        r2.dst = []
        r2.srv = []
        r2.itf = []
        r2.when = []
        r2.ipt_chain = new_chain
        r2.upstream_rule_chain = this_chain
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        r2.ipt_target = 'LOG'
        r2.action = PolicyAction.Continue
        r2.direction = Direction.Both
        r2.set_option('log', False)
        r2.set_option('classification', False)
        r2.set_option('routing', False)
        r2.set_option('tagging', False)
        r2.set_option('stateless', True)
        r2.set_option('limit_value', -1)
        r2.force_state_check = False
        self.tmp_queue.append(r2)

        # 3) Action rule in new_chain: all elements reset, inherits action
        r3 = rule.clone()
        r3.src = []
        r3.dst = []
        r3.srv = []
        r3.itf = []
        r3.when = []
        r3.ipt_chain = new_chain
        r3.upstream_rule_chain = this_chain
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        r3.iface_label = 'nil'
        r3.direction = Direction.Both
        r3.set_option('log', False)
        r3.final = True
        r3.set_option('stateless', True)
        r3.set_option('limit_value', -1)
        r3.force_state_check = False
        self.tmp_queue.append(r3)

        return True


class SingleSrcNegation(PolicyRuleProcessor):
    """Handle single-object src negation with inline '!' syntax."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('src') and len(rule.src) == 1:
            obj = rule.src[0]
            if isinstance(obj, Address) and not self.compiler.complex_match(
                obj, self.compiler.fw
            ):
                rule.src_single_object_negation = True
                rule.set_neg('src', False)
        self.tmp_queue.append(rule)
        return True


class SingleDstNegation(PolicyRuleProcessor):
    """Handle single-object dst negation with inline '!' syntax."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('dst') and len(rule.dst) == 1:
            obj = rule.dst[0]
            if isinstance(obj, Address) and not self.compiler.complex_match(
                obj, self.compiler.fw
            ):
                rule.dst_single_object_negation = True
                rule.set_neg('dst', False)
        self.tmp_queue.append(rule)
        return True


class SingleSrvNegation(PolicyRuleProcessor):
    """Handle single-object srv negation (TagService/UserService only)."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        # TagService/UserService would get single_object_negation here.
        # Currently no-op — all common services use temp chain pattern.
        self.tmp_queue.append(rule)
        return True


class SplitIfSrcNegAndFw(PolicyRuleProcessor):
    """Split rule when src is negated and contains firewall objects."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if (
            not rule.get_neg('src')
            or rule.ipt_chain
            or rule.direction == Direction.Inbound
        ):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        fw_likes: list = []
        not_fw_likes: list = []
        for obj in rule.src:
            if ipt_comp.complex_match(obj, ipt_comp.fw):
                fw_likes.append(obj)
            else:
                not_fw_likes.append(obj)

        if not fw_likes:
            self.tmp_queue.append(rule)
            return True

        # Rule A: OUTPUT chain with FW objects (still negated)
        r = rule.clone()
        r.src = fw_likes
        ipt_comp.set_chain(r, 'OUTPUT')
        r.direction = Direction.Outbound
        self.tmp_queue.append(r)

        # Rule B: original with non-FW objects only
        rule.src = not_fw_likes
        if not not_fw_likes:
            rule.set_neg('src', False)
        rule.set_option('no_output_chain', True)
        self.tmp_queue.append(rule)
        return True


class SplitIfDstNegAndFw(PolicyRuleProcessor):
    """Split rule when dst is negated and contains firewall objects."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if (
            not rule.get_neg('dst')
            or rule.ipt_chain
            or rule.direction == Direction.Outbound
        ):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        fw_likes: list = []
        not_fw_likes: list = []
        for obj in rule.dst:
            if ipt_comp.complex_match(obj, ipt_comp.fw):
                fw_likes.append(obj)
            else:
                not_fw_likes.append(obj)

        if not fw_likes:
            self.tmp_queue.append(rule)
            return True

        # Rule A: INPUT chain with FW objects (still negated)
        r = rule.clone()
        r.dst = fw_likes
        ipt_comp.set_chain(r, 'INPUT')
        r.direction = Direction.Inbound
        self.tmp_queue.append(r)

        # Rule B: original with non-FW objects only
        rule.dst = not_fw_likes
        if not not_fw_likes:
            rule.set_neg('dst', False)
        rule.set_option('no_input_chain', True)
        self.tmp_queue.append(rule)
        return True


class SrcNegation(PolicyRuleProcessor):
    """Handle multi-object src negation via temp chain with RETURN rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('src'):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        rule.set_neg('src', False)

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except src
        r_jump = rule.clone()
        r_jump.src = []
        r_jump.ipt_target = new_chain
        r_jump.action = PolicyAction.Continue
        r_jump.set_option('classification', False)
        r_jump.set_option('routing', False)
        r_jump.set_option('tagging', False)
        r_jump.set_option('log', False)
        r_jump.set_option('limit_value', -1)
        r_jump.set_option('connlimit_value', -1)
        r_jump.set_option('hashlimit_value', -1)
        self.tmp_queue.append(r_jump)

        # Return rule: keep only src objects
        r_return = rule.clone()
        r_return.dst = []
        r_return.srv = []
        r_return.itf = []
        r_return.when = []
        r_return.ipt_chain = new_chain
        r_return.upstream_rule_chain = this_chain
        r_return.action = PolicyAction.Return
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything
        # TODO: C++ preserves "any TCP" service when action_on_reject is TCP RST
        r_action = rule.clone()
        r_action.src = []
        r_action.dst = []
        r_action.srv = []
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.upstream_rule_chain = this_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_action)

        return True


class DstNegation(PolicyRuleProcessor):
    """Handle multi-object dst negation via temp chain with RETURN rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('dst'):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        rule.set_neg('dst', False)

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except dst
        r_jump = rule.clone()
        r_jump.dst = []
        r_jump.ipt_target = new_chain
        r_jump.action = PolicyAction.Continue
        r_jump.set_option('classification', False)
        r_jump.set_option('routing', False)
        r_jump.set_option('tagging', False)
        r_jump.set_option('log', False)
        r_jump.set_option('limit_value', -1)
        r_jump.set_option('connlimit_value', -1)
        r_jump.set_option('hashlimit_value', -1)
        self.tmp_queue.append(r_jump)

        # Return rule: keep only dst objects
        r_return = rule.clone()
        r_return.src = []
        r_return.srv = []
        r_return.itf = []
        r_return.when = []
        r_return.ipt_chain = new_chain
        r_return.upstream_rule_chain = this_chain
        r_return.action = PolicyAction.Return
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything
        # TODO: C++ preserves "any TCP" service when action_on_reject is TCP RST
        r_action = rule.clone()
        r_action.src = []
        r_action.dst = []
        r_action.srv = []
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.upstream_rule_chain = this_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_action)

        return True


class SrvNegation(PolicyRuleProcessor):
    """Handle service negation via temp chain with RETURN rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('srv'):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        rule.set_neg('srv', False)

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except srv
        r_jump = rule.clone()
        r_jump.srv = []
        r_jump.ipt_target = new_chain
        r_jump.action = PolicyAction.Continue
        r_jump.set_option('classification', False)
        r_jump.set_option('routing', False)
        r_jump.set_option('tagging', False)
        r_jump.set_option('log', False)
        r_jump.set_option('limit_value', -1)
        r_jump.set_option('connlimit_value', -1)
        r_jump.set_option('hashlimit_value', -1)
        self.tmp_queue.append(r_jump)

        # Return rule: keep only srv objects
        r_return = rule.clone()
        r_return.src = []
        r_return.dst = []
        r_return.itf = []
        r_return.when = []
        r_return.ipt_chain = new_chain
        r_return.upstream_rule_chain = this_chain
        r_return.action = PolicyAction.Return
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything
        r_action = rule.clone()
        r_action.src = []
        r_action.dst = []
        r_action.srv = []
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.upstream_rule_chain = this_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_action)

        return True


class InterfaceAndDirection(PolicyRuleProcessor):
    """Fill in interface and direction information."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.direction is None or rule.direction == Direction.Undefined:
            rule.direction = Direction.Both

        if rule.is_itf_any() and rule.direction == Direction.Both:
            rule.iface_label = 'nil'
            return True

        if not rule.is_itf_any():
            obj = rule.itf[0] if rule.itf else None
            if isinstance(obj, Interface):
                rule.iface_label = obj.name

        return True


class SplitIfIfaceAndDirectionBoth(PolicyRuleProcessor):
    """Split interface rule with direction 'both' into two rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        direction = rule.direction
        if direction == Direction.Both and not rule.is_itf_any():
            r1 = rule.clone()
            r1.direction = Direction.Inbound
            self.tmp_queue.append(r1)

            r2 = rule.clone()
            r2.direction = Direction.Outbound
            self.tmp_queue.append(r2)
        else:
            self.tmp_queue.append(rule)

        return True


class FillActionOnReject(PolicyRuleProcessor):
    """Fill in action_on_reject from global settings if empty."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.action == PolicyAction.Reject and not rule.get_option(
            'action_on_reject', ''
        ):
            global_reject = self.compiler.fw.get_option('action_on_reject', '')
            if global_reject:
                rule.set_option('action_on_reject', global_reject)

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcAny(PolicyRuleProcessor):
    """Split rule if src is 'any' and firewall is part of any."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Check per-rule option first, then fall back to global firewall option
        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.get_option(
                'firewall_is_part_of_any_and_networks', False
            )
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.get_option('no_output_chain', False):
            self.tmp_queue.append(rule)
            return True

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # C++ also splits when single_object_negation is set, but only if
        # the single negated object does NOT match the firewall itself.
        src_neg_split = (
            rule.src_single_object_negation
            and len(rule.src) == 1
            and not ipt_comp.complex_match(rule.src[0], ipt_comp.fw)
        )
        if rule.direction != Direction.Inbound and (rule.is_src_any() or src_neg_split):
            r = rule.clone()
            ipt_comp.set_chain(r, 'OUTPUT')
            r.direction = Direction.Outbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstAny(PolicyRuleProcessor):
    """Split rule if dst is 'any' and firewall is part of any."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Check per-rule option first, then fall back to global firewall option
        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.get_option(
                'firewall_is_part_of_any_and_networks', False
            )
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.get_option('no_input_chain', False):
            self.tmp_queue.append(rule)
            return True

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # C++ also splits when single_object_negation is set, but only if
        # the single negated object does NOT match the firewall itself.
        dst_neg_split = (
            rule.dst_single_object_negation
            and len(rule.dst) == 1
            and not ipt_comp.complex_match(rule.dst[0], ipt_comp.fw)
        )
        if rule.direction != Direction.Outbound and (
            rule.is_dst_any() or dst_neg_split
        ):
            r = rule.clone()
            ipt_comp.set_chain(r, 'INPUT')
            r.direction = Direction.Inbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcMatchesFw(PolicyRuleProcessor):
    """Split rule if src contains the firewall object."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if len(rule.src) <= 1:
            self.tmp_queue.append(rule)
            return True

        to_extract = []
        for obj in rule.src:
            if ipt_comp.complex_match(obj, ipt_comp.fw):
                to_extract.append(obj)

        if to_extract and len(rule.src) > len(to_extract):
            for obj in to_extract:
                r = rule.clone()
                r.src = [obj]
                self.tmp_queue.append(r)
                rule.src.remove(obj)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstMatchesFw(PolicyRuleProcessor):
    """Split rule if dst contains the firewall object."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if len(rule.dst) <= 1:
            self.tmp_queue.append(rule)
            return True

        to_extract = []
        for obj in rule.dst:
            if ipt_comp.complex_match(obj, ipt_comp.fw):
                to_extract.append(obj)

        if to_extract and len(rule.dst) > len(to_extract):
            for obj in to_extract:
                r = rule.clone()
                r.dst = [obj]
                self.tmp_queue.append(r)
                rule.dst.remove(obj)

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcFWNetwork(PolicyRuleProcessor):
    """Split rule if src contains a network the FW has an interface on."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain or rule.is_src_any():
            self.tmp_queue.append(rule)
            return True

        if rule.direction != Direction.Inbound:
            has_match = False
            for obj in rule.src:
                if (
                    isinstance(obj, (Network, NetworkIPv6))
                    and ipt_comp.find_address_for(obj, ipt_comp.fw) is not None
                ):
                    has_match = True
                    break

            if has_match:
                r = rule.clone()
                ipt_comp.set_chain(r, 'OUTPUT')
                r.direction = Direction.Outbound
                self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstFWNetwork(PolicyRuleProcessor):
    """Split rule if dst contains a network the FW has an interface on."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain or rule.is_dst_any():
            self.tmp_queue.append(rule)
            return True

        if rule.direction != Direction.Outbound:
            has_match = False
            for obj in rule.dst:
                if (
                    isinstance(obj, (Network, NetworkIPv6))
                    and ipt_comp.find_address_for(obj, ipt_comp.fw) is not None
                ):
                    has_match = True
                    break

            if has_match:
                r = rule.clone()
                ipt_comp.set_chain(r, 'INPUT')
                r.direction = Direction.Inbound
                self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SpecialCaseWithFW2(PolicyRuleProcessor):
    """Replace fw with its interface addresses when src==dst==fw."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        src_obj = rule.src[0] if rule.src else None
        dst_obj = rule.dst[0] if rule.dst else None

        if (
            src_obj is not None
            and dst_obj is not None
            and isinstance(src_obj, Firewall)
            and src_obj.id == ipt_comp.fw.id
            and isinstance(dst_obj, Firewall)
            and dst_obj.id == ipt_comp.fw.id
        ):
            all_addrs = []
            for iface in ipt_comp.fw.interfaces:
                if iface.is_unnumbered():
                    continue
                for addr in iface.addresses:
                    if (ipt_comp.ipv6_policy and isinstance(addr, IPv6)) or (
                        not ipt_comp.ipv6_policy and isinstance(addr, IPv4)
                    ):
                        all_addrs.append(addr)

            rule.src = list(all_addrs)
            rule.dst = list(all_addrs)

        self.tmp_queue.append(rule)
        return True


class DecideOnChainIfDstFW(PolicyRuleProcessor):
    """Set chain to INPUT if dst matches the firewall."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        dst = rule.dst[0] if rule.dst else None
        if dst is not None:
            direction = rule.direction
            matches_fw = ipt_comp.complex_match(dst, ipt_comp.fw)

            if direction == Direction.Inbound:
                if matches_fw:
                    ipt_comp.set_chain(rule, 'INPUT')
            elif direction == Direction.Both and matches_fw:
                ipt_comp.set_chain(rule, 'INPUT')
                rule.direction = Direction.Inbound

        self.tmp_queue.append(rule)
        return True


class DecideOnChainIfSrcFW(PolicyRuleProcessor):
    """Set chain to OUTPUT if src contains the firewall."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        src = rule.src[0] if rule.src else None
        if src is not None:
            direction = rule.direction
            matches_fw = ipt_comp.complex_match(src, ipt_comp.fw)

            if direction == Direction.Outbound:
                if matches_fw:
                    ipt_comp.set_chain(rule, 'OUTPUT')
            elif direction == Direction.Both and matches_fw:
                ipt_comp.set_chain(rule, 'OUTPUT')
                rule.direction = Direction.Outbound

        self.tmp_queue.append(rule)
        return True


class DecideOnChainIfLoopback(PolicyRuleProcessor):
    """Assign INPUT/OUTPUT chain for any-any rules on loopback interface."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            rule.is_src_any()
            and rule.is_dst_any()
            and not rule.ipt_chain
            and not rule.is_itf_any()
        ):
            iface = rule.itf[0] if rule.itf else None
            if isinstance(iface, Interface) and iface.is_loopback():
                direction = rule.direction
                if direction == Direction.Inbound:
                    ipt_comp.set_chain(rule, 'INPUT')
                elif direction == Direction.Outbound:
                    ipt_comp.set_chain(rule, 'OUTPUT')
                elif direction == Direction.Both:
                    r = rule.clone()
                    ipt_comp.set_chain(r, 'OUTPUT')
                    r.direction = Direction.Outbound
                    self.tmp_queue.append(r)

                    ipt_comp.set_chain(rule, 'INPUT')
                    rule.direction = Direction.Inbound

        self.tmp_queue.append(rule)
        return True


class FinalizeChain(PolicyRuleProcessor):
    """Finalize chain assignment: INPUT/OUTPUT/FORWARD."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # Default to FORWARD
        ipt_comp.set_chain(rule, 'FORWARD')

        if ipt_comp.my_table == 'mangle':
            direction = rule.direction
            if direction == Direction.Inbound:
                ipt_comp.set_chain(rule, 'PREROUTING')
            elif direction == Direction.Outbound:
                ipt_comp.set_chain(rule, 'POSTROUTING')
        else:
            src = rule.src[0] if rule.src else None
            dst = rule.dst[0] if rule.dst else None
            direction = rule.direction

            if direction == Direction.Inbound:
                if dst is not None and ipt_comp.complex_match(dst, ipt_comp.fw):
                    ipt_comp.set_chain(rule, 'INPUT')
            elif direction == Direction.Outbound:
                if src is not None and ipt_comp.complex_match(src, ipt_comp.fw):
                    ipt_comp.set_chain(rule, 'OUTPUT')
            else:
                if dst is not None and ipt_comp.complex_match(dst, ipt_comp.fw):
                    ipt_comp.set_chain(rule, 'INPUT')
                elif src is not None and ipt_comp.complex_match(src, ipt_comp.fw):
                    ipt_comp.set_chain(rule, 'OUTPUT')

        self.tmp_queue.append(rule)
        return True


class DecideOnTarget(PolicyRuleProcessor):
    """Set the iptables target based on rule action."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.ipt_target:
            return True

        target_map = {
            PolicyAction.Accept: 'ACCEPT',
            PolicyAction.Deny: 'DROP',
            PolicyAction.Reject: 'REJECT',
            PolicyAction.Return: 'RETURN',
            PolicyAction.Pipe: 'QUEUE',
            PolicyAction.Continue: '.CONTINUE',
            PolicyAction.Custom: '.CUSTOM',
        }
        action = rule.action
        if isinstance(action, PolicyAction):
            target = target_map.get(action)
            if target is not None:
                rule.ipt_target = target

        return True


class RemoveFW(PolicyRuleProcessor):
    """Remove firewall object from src/dst after chain decision.

    Only removes the Firewall object itself (by ID match), NOT interface
    addresses that happen to belong to the firewall. This matches
    fwbuilder's is_firewall_or_cluster() check.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        chain = rule.ipt_chain
        fw_id = ipt_comp.fw.id

        if chain == 'INPUT':
            rule.dst = [obj for obj in rule.dst if obj.id != fw_id]
        elif chain == 'OUTPUT':
            rule.src = [obj for obj in rule.src if obj.id != fw_id]

        self.tmp_queue.append(rule)
        return True


class ExpandMultipleAddresses(PolicyRuleProcessor):
    """Expand hosts/firewalls with multiple addresses."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.compiler.expand_addr(rule, 'src')
        self.compiler.expand_addr(rule, 'dst')
        self.tmp_queue.append(rule)
        return True


class CheckInterfaceAgainstAddressFamily(_Passthrough):
    """Check if interface matches address family."""

    pass


class SpecialCaseWithUnnumberedInterface(_Passthrough):
    """Check for special cases with unnumbered interface."""

    pass


class Optimize1(PolicyRuleProcessor):
    """Optimization: split rule by element with fewest objects into temp chain.

    Creates a temporary chain with a jump rule that matches on the element
    being optimized. The original rule moves to the temp chain with that
    element cleared. This reduces the total number of iptables rules from
    the Cartesian product (Src x Dst x Srv) by factoring out common
    elements.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        srcn = len(rule.src)
        dstn = len(rule.dst)
        srvn = len(rule.srv)
        srcany = srcn == 0
        dstany = dstn == 0
        srvany = srvn == 0

        # If all services are TCP or UDP, multiport can collapse them
        if srvn > 0 and not srvany:
            all_tcp_or_udp = all(
                isinstance(s, (TCPService, UDPService)) for s in rule.srv
            )
            if all_tcp_or_udp:
                srvn = 1

        # Guard: can't optimize if all elements have <=1 objects or
        # two+ elements are "any"
        if (
            (srcn <= 1 and dstn <= 1 and srvn <= 1)
            or (srcany and dstany)
            or (srcany and srvany)
            or (dstany and srvany)
        ):
            self.tmp_queue.append(rule)
            return True

        # Treat "any" as very large for comparison purposes
        _MAXSIZE = 2**31
        if srcany:
            srcn = _MAXSIZE
        if dstany:
            dstn = _MAXSIZE
        if srvany:
            srvn = _MAXSIZE

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        # Pick element with fewest objects to optimize by
        if (
            not srvany
            and srvn <= dstn
            and srvn <= srcn
            and not rule.get_option('do_not_optimize_by_srv', False)
        ):
            self._optimize(rule, 'srv', ipt_comp)
            return True

        if not srcany and srcn <= dstn and srcn <= srvn:
            self._optimize(rule, 'src', ipt_comp)
            return True

        if not dstany and dstn <= srcn and dstn <= srvn:
            self._optimize(rule, 'dst', ipt_comp)
            return True

        self.tmp_queue.append(rule)
        return True

    def _optimize(self, rule: CompRule, element: str, ipt_comp) -> None:
        """Create a jump rule + move original to temp chain.

        For each rule element:
        - If it's NOT the optimized element AND has >1 objects: clear in jump
        - Otherwise (IS optimized, OR has <=1 objects): keep in jump, clear
          in original. This matches fwbuilder's _optimize_for_rule_element.
        """
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)
        this_chain = rule.ipt_chain

        r = rule.clone()
        for attr in ('src', 'dst', 'srv'):
            items = getattr(r, attr)
            if attr != element and len(items) > 1:
                # Multi-element non-optimized: clear in jump rule
                setattr(r, attr, [])
            else:
                # Optimized element, or single/any: keep in jump, clear
                # in original
                setattr(rule, attr, [])

        # Jump rule: keep state matching, just change target
        r.ipt_target = new_chain
        r.action = PolicyAction.Continue
        self.tmp_queue.append(r)

        # Original rule: moved to temp chain, made stateless
        rule.set_option('stateless', True)
        rule.force_state_check = False
        rule.ipt_chain = new_chain
        rule.upstream_rule_chain = this_chain
        ipt_comp.register_chain(new_chain)
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        rule.direction = Direction.Both
        rule.iface_label = 'nil'
        rule.itf = []
        self.tmp_queue.append(rule)


class GroupServicesByProtocol(PolicyRuleProcessor):
    """Split rule when services belong to different protocols."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.srv) <= 1:
            self.tmp_queue.append(rule)
            return True

        from firewallfabrik.core.objects import Service

        groups: dict[int, list] = {}
        for srv in rule.srv:
            proto = srv.get_protocol_number() if isinstance(srv, Service) else -1
            groups.setdefault(proto, []).append(srv)

        if len(groups) <= 1:
            self.tmp_queue.append(rule)
        else:
            for _proto, srvs in sorted(groups.items()):
                r = rule.clone()
                r.srv = srvs
                self.tmp_queue.append(r)

        return True


class SeparatePortRanges(PolicyRuleProcessor):
    """Separate TCP/UDP services with port ranges into individual rules.

    Services where src or dst port range start != end (i.e. actual port
    ranges like 749:750) or "any TCP/UDP" services (all ports zero) get
    pulled out into their own rules because they can't be combined with
    single-port services in a ``-m multiport`` match.
    """

    @staticmethod
    def _is_port_range(srv) -> bool:
        from firewallfabrik.core.objects import TCPService, UDPService

        if not isinstance(srv, (TCPService, UDPService)):
            return False

        srs = srv.src_range_start or 0
        sre = srv.src_range_end or 0
        drs = srv.dst_range_start or 0
        dre = srv.dst_range_end or 0

        # Normalize: single port has end==0 or end==start
        if srs != 0 and sre == 0:
            sre = srs
        if drs != 0 and dre == 0:
            dre = drs

        # "Any TCP/UDP" (all zeros) — treat as full range
        if srs == 0 and sre == 0 and drs == 0 and dre == 0:
            sre = 65535
            dre = 65535

        return srs != sre or drs != dre

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.srv) <= 1:
            self.tmp_queue.append(rule)
            return True

        # Pull out services matching the condition into individual rules
        separated = []
        for srv in rule.srv:
            if self._is_port_range(srv):
                r = rule.clone()
                r.srv = [srv]
                self.tmp_queue.append(r)
                separated.append(srv)

        # Remove separated services from the original rule
        remaining = [s for s in rule.srv if s not in separated]
        if remaining:
            rule.srv = remaining
            self.tmp_queue.append(rule)

        return True


class CheckForStatefulICMP6Rules(_Passthrough):
    """Check for stateful ICMPv6 rules."""

    pass


class Optimize2(_Passthrough):
    """Optimization pass 2."""

    pass


class PrepareForMultiport(PolicyRuleProcessor):
    """Prepare rules for multiport matching."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        from firewallfabrik.core.objects import TCPService, UDPService

        if len(rule.srv) > 1:
            all_same_proto = True
            first_proto = type(rule.srv[0])
            for s in rule.srv[1:]:
                if type(s) is not first_proto:
                    all_same_proto = False
                    break

            if (
                all_same_proto
                and isinstance(rule.srv[0], (TCPService, UDPService))
                and len(rule.srv) <= 15
            ):
                rule.ipt_multiport = True

        self.tmp_queue.append(rule)
        return True


class Optimize3(PolicyRuleProcessor):
    """Remove duplicate rules that produce identical iptables commands."""

    def __init__(self, name: str = '') -> None:
        super().__init__(name)
        self._seen: set[str] = set()

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        pr = getattr(self.compiler, 'print_rule_processor', None)
        if pr is None:
            self.tmp_queue.append(rule)
            return True

        rule_str = pr.policy_rule_to_string(rule)
        if rule_str in self._seen:
            return True  # duplicate, drop

        self._seen.add(rule_str)
        self.tmp_queue.append(rule)
        return True


class CheckForObjectsWithErrors(_Passthrough):
    """Check for objects with errors in rule elements."""

    pass


class CountChainUsage(PolicyRuleProcessor):
    """Count chain usage for all rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        chain = rule.ipt_chain
        if chain:
            ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
            ipt_comp.chain_usage_counter[chain] = (
                ipt_comp.chain_usage_counter.get(chain, 0) + 1
            )
        self.tmp_queue.append(rule)
        return True
