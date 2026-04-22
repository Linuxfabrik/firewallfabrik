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
    CheckForTCPEstablished,
    ConvertToAtomic,
    ConvertToAtomicForAddresses,
    DetectShadowing,
    DropIPv4Rules,
    DropIPv6Rules,
    DropRuleWithEmptyRE,
    EliminateDuplicatesInDST,
    EliminateDuplicatesInSRC,
    EliminateDuplicatesInSRV,
    EmptyGroupsInRE,
    ExpandGroups,
    RecursiveGroupsInRE,
    ReplaceClusterInterfaceInItfRE,
    ResolveMultiAddress,
    SimplePrintProgress,
    SingleRuleFilter,
)
from firewallfabrik.compiler.processors._policy import (
    ItfNegation,
)
from firewallfabrik.compiler.processors._policy import (
    TimeNegation as BaseTimeNegation,
)
from firewallfabrik.compiler.processors._service import (
    SeparateSrcPort,
    SeparateTCPWithFlags,
    SeparateUserServices,
    VerifyCustomServices,
)
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    CustomService,
    Direction,
    Firewall,
    Host,
    ICMP6Service,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    PhysAddress,
    PolicyAction,
    TCPService,
    UDPService,
    UserService,
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

        # Chain prefix for coexistence mode (e.g. 'fwf' → fwf_INPUT)
        self.chain_prefix: str = ''

        # ipset usage flag
        self.using_ipset: bool = False
        if _version_compare(self.version, '1.4.1.1') >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set'))

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

    def run_shadowing_pass(self) -> None:
        """Run a separate shadowing detection pass before the main compilation.

        Corresponds to fwbuilder's separate shadowing detection pass
        (PolicyCompiler_ipt.cpp lines 4302-4386).  This builds its own
        processor pipeline that only produces warnings/errors via
        ``self.warning()`` / ``self.abort()`` without affecting the main
        compilation output.

        The pipeline is: Begin -> ConvertAnyToNotFWForShadowing ->
        SplitIfSrcAnyForShadowing -> SplitIfDstAnyForShadowing ->
        ConvertToAtomic (full Cartesian product) -> DetectShadowing.
        """
        # Save the main processor chain
        saved_processors = self.rule_processors
        self.rule_processors = []

        # Build the shadowing detection pipeline.  Mirrors fwbuilder's
        # PolicyCompiler_ipt.cpp shadow pass: SplitIfSrcAnyForShadowing
        # and SplitIfDstAnyForShadowing are intentionally skipped
        # (#if 0 in the C++ source).  Including them produced
        # synthetic fw->fw atomic variants from rules with "any"
        # source or destination, which then appeared to be shadowed
        # by earlier rules that legitimately targeted the firewall
        # itself - emitting "Rule X shadows Rule Y" false positives.
        self.add(Begin('Detecting rule shadowing'))
        self.add(ConvertAnyToNotFWForShadowing("convert 'any' to '!fw'"))
        self.add(ConvertToAtomic('convert to atomic rules'))
        self.add(DetectShadowing('Detect shadowing'))

        # Run the shadowing pipeline (only produces warnings/errors)
        self.run_rule_processors()

        # Restore the main processor chain
        self.rule_processors = saved_processors

    def compile(self) -> None:
        """Main compilation: sets up the full rule processor pipeline."""
        banner = (
            f" Compiling ruleset {self.get_rule_set_name()} for '{self.my_table}' table"
        )
        if self.ipv6_policy:
            banner += ', IPv6'
        self.info(banner)

        super().compile()

        # Run separate shadowing detection pass before the main pipeline
        if self.fw.get_option('check_shading') and not self.single_rule_compile_mode:
            self.run_shadowing_pass()

        # -- Full processor pipeline --
        self.add(Begin('Begin compilation'))
        self.add(SingleRuleFilter('single rule filter'))

        self.add_rule_filter()

        self.add(DeprecateOptionRoute('deprecate option Route'))

        self.add(
            CheckForUnsupportedCombinationsInMangle(
                'check for unsupported Tag+Route and Classify+Route combinations'
            )
        )

        self.add(
            ClearTagClassifyInFilter('clear Tag and Classify options in filter table')
        )
        self.add(ClearLogInMangle('clear logging in rules in mangle table'))
        self.add(
            ClearActionInTagClassifyIfMangle(
                'clear action in rules with Tag and Classify in mangle'
            )
        )

        self.add(StoreAction('store action'))

        self.add(Logging1('check global logging override option'))

        self.add(ExpandGroupsInItf('expand groups in Itf'))
        self.add(ReplaceClusterInterfaceInItfRE('replace cluster interfaces', 'itf'))
        self.add(SingleObjectNegationItf('single object negation in Itf'))
        self.add(ItfNegation('process negation in Itf'))

        self.add(DecideOnChainForClassify('set chain for action is Classify'))

        self.add(InterfaceAndDirection('interface+dir'))
        self.add(
            SplitIfIfaceAndDirectionBoth('split interface rule with direction both')
        )

        self.add(ResolveMultiAddress('resolve compile-time MultiAddress'))

        self.add(RecursiveGroupsInRE('check for recursive groups in SRC', 'src'))
        self.add(RecursiveGroupsInRE('check for recursive groups in DST', 'dst'))
        self.add(RecursiveGroupsInRE('check for recursive groups in SRV', 'srv'))

        self.add(EmptyGroupsInRE('check for empty groups in SRC', 'src'))
        self.add(EmptyGroupsInRE('check for empty groups in DST', 'dst'))
        self.add(EmptyGroupsInRE('check for empty groups in SRV', 'srv'))
        self.add(EmptyGroupsInRE('check for empty groups in ITF', 'itf'))

        self.add(ExpandGroups('expand all groups'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))
        self.add(EliminateDuplicatesInSRC('eliminate duplicates in SRC'))
        self.add(EliminateDuplicatesInDST('eliminate duplicates in DST'))
        self.add(EliminateDuplicatesInSRV('eliminate duplicates in SRV'))

        # -- Srv negation & reject processors (matching fwbuilder order) --
        self.add(SingleSrvNegation('single srv negation'))
        self.add(
            SplitRuleIfSrvAnyActionReject(
                'split rule if action is reject and srv is any'
            )
        )
        self.add(SrvNegation('process negation in Srv'))

        self.add(ExpandGroupsInSrv('expand groups in Srv'))

        self.add(CheckForTCPEstablished('check for TCP established flag'))

        self.add(FillActionOnReject('fill action_on_reject'))
        self.add(
            SplitServicesIfRejectWithTCPReset('split if action on reject is TCP reset')
        )
        self.add(FillActionOnReject('fill action_on_reject 2'))
        self.add(
            SplitServicesIfRejectWithTCPReset(
                'split if action on reject is TCP reset 2'
            )
        )

        # -- Address negation processors --
        self.add(SingleSrcNegation('single src negation'))
        self.add(SingleDstNegation('single dst negation'))
        self.add(SplitIfSrcNegAndFw('split if src negated and fw'))
        self.add(SplitIfDstNegAndFw('split if dst negated and fw'))
        self.add(SrcNegation('process negation in Src'))
        self.add(DstNegation('process negation in Dst'))

        self.add(
            BaseTimeNegation(allow_negation=False, name='process negation in Time')
        )

        self.add(Logging2('process logging'))

        # -- Mangle table split processors (after Logging2, per fwbuilder) --
        self.add(
            SplitIfTagClassifyOrRoute(
                'split rule if tagging, classification or routing options'
            )
        )
        self.add(SplitIfTagAndConnmark('Tag+CONNMARK combo'))
        self.add(RouteProcessor('process route rules'))

        self.add(Accounting('accounting'))

        self.add(SplitIfSrcAny('split rule if src is any'))

        if self.my_table == 'mangle':
            self.add(CheckActionInMangleTable('check allowed actions in mangle table'))

        self.add(SetChainForMangle('set chain for mangle rules'))
        self.add(SetChainPreroutingForTag('chain PREROUTING for Tag'))

        self.add(SplitIfDstAny('split rule if dst is any'))

        self.add(SetChainPostroutingForTag('chain POSTROUTING for Tag'))

        self.add(ProcessMultiAddressObjectsInSrc('process MultiAddress objects in Src'))
        self.add(ProcessMultiAddressObjectsInDst('process MultiAddress objects in Dst'))

        # Address range handling (iptables >= 1.2.11)
        self.add(SpecialCaseAddressRangeInSrc('replace single address range in Src'))
        self.add(SpecialCaseAddressRangeInDst('replace single address range in Dst'))
        self.add(
            SplitIfSrcMatchingAddressRange('split if Src has matching address range')
        )
        self.add(
            SplitIfDstMatchingAddressRange('split if Dst has matching address range')
        )
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))

        self.add(SplitIfSrcMatchesFw('split if src matches FW'))
        self.add(SplitIfDstMatchesFw('split if dst matches FW'))

        self.add(SpecialCaseWithFW1('special case with firewall'))

        self.add(DecideOnChainIfDstFW('decide chain if Dst has fw'))
        self.add(SplitIfSrcFWNetwork('split rule if src has a net fw has interface on'))
        self.add(DecideOnChainIfSrcFW('decide chain if Src has fw'))
        self.add(SplitIfDstFWNetwork('split rule if dst has a net fw has interface on'))
        self.add(SpecialCaseWithFW2('replace fw with its interfaces if src==dst==fw'))
        self.add(DecideOnChainIfLoopback('any-any rule on loopback'))
        self.add(FinalizeChain('assign chain'))

        self.add(SpecialCaseWithFWInDstAndOutbound('drop outbound with fw in dst'))

        self.add(DecideOnTarget('set target'))

        self.add(CheckForRestoreMarkInOutput('check for CONNMARK restore in OUTPUT'))

        self.add(RemoveFW('remove fw'))
        self.add(
            ExpandMultipleAddressesIfNotFWInSrc(
                'expand multiple addresses if not FW in Src'
            )
        )
        self.add(
            ExpandMultipleAddressesIfNotFWInDst(
                'expand multiple addresses if not FW in Dst'
            )
        )
        self.add(
            ExpandLoopbackInterfaceAddress(
                'check for loopback interface in rule objects'
            )
        )
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

        self.add(CheckForUnnumbered('check for unnumbered interfaces'))
        self.add(
            CheckForDynamicInterfacesOfOtherObjects(
                'check for dynamic interfaces of other objects'
            )
        )

        if self.fw.get_option('bridging_fw'):
            self.add(BridgingFw('handle bridging firewall cases'))

        self.add(
            SpecialCaseWithUnnumberedInterface(
                'check for special cases with unnumbered interface'
            )
        )

        self.add(InterfacePolicyRulesWithOptimization('process interface policy rules'))

        self.add(Optimize1('optimization 1, pass 1'))
        self.add(Optimize1('optimization 1, pass 2'))
        self.add(Optimize1('optimization 1, pass 3'))

        self.add(GroupServicesByProtocol('split on services'))
        self.add(SeparateTCPWithFlags('split on TCP services with flags'))
        self.add(VerifyCustomServices('verify custom services'))
        self.add(SpecialCasesWithCustomServices('special cases with custom services'))
        self.add(SeparatePortRanges('separate port ranges'))
        self.add(SeparateUserServices('separate user services'))
        self.add(SeparateSrcPort('split on TCP and UDP with source ports'))
        self.add(CheckForStatefulICMP6Rules('check for stateful ICMPv6 rules'))

        self.add(Optimize2('optimization 2'))

        self.add(PrepareForMultiport('prepare for multiport'))

        self.add(ConvertToAtomicForAddresses('convert to atomic by addresses'))

        self.add(CheckForZeroAddr('check for zero addresses'))
        self.add(CheckMACInOUTPUTChain('check for MAC in OUTPUT chain'))
        self.add(CheckUserServiceInWrongChains('check for UserService in wrong chains'))

        self.add(ConvertToAtomicForIntervals('convert to atomic by intervals'))

        self.add(Optimize3('optimization 3'))

        self.add(OptimizeForMinusIOPlus("optimize for '-i +' / '-o +'"))

        self.add(CheckForObjectsWithErrors('check for objects with errors'))

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
            self.fw.get_option('use_iptables_restore')
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

        use_restore = bool(self.fw.get_option('use_iptables_restore'))

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

    def is_action_on_reject_tcp_rst(self, rule: CompRule) -> bool:
        """Return True if action_on_reject is TCP RST."""
        s = self.get_action_on_reject(rule)
        return bool(s and 'TCP ' in s)

    def reset_action_on_reject(self, rule: CompRule) -> None:
        """Reset action_on_reject to a non-TCP value.

        Uses the global option as fallback; if that is also TCP RST,
        sets to 'NOP' as a safe fallback (matching fwbuilder behavior).
        """
        go = self.fw.get_option('action_on_reject') or ''
        if go:
            if 'TCP ' in go:
                rule.set_option('action_on_reject', 'NOP')
            else:
                rule.set_option('action_on_reject', go)
        else:
            rule.set_option('action_on_reject', 'none')

    # -- Output generation --

    def flush_and_set_default_policy(self) -> str:
        """Generate flush and default policy commands for iptables-restore."""
        if self.single_rule_compile_mode:
            return ''
        if not self.fw.get_option('use_iptables_restore'):
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

        use_restore = bool(self.fw.get_option('use_iptables_restore'))

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

        # Chain names — prefixed in coexistence mode.
        prefix = self.chain_prefix
        conf.set_variable('chain_input', f'{prefix}_INPUT' if prefix else 'INPUT')
        conf.set_variable(
            'chain_output',
            f'{prefix}_OUTPUT' if prefix else 'OUTPUT',
        )
        conf.set_variable(
            'chain_forward',
            f'{prefix}_FORWARD' if prefix else 'FORWARD',
        )
        drop_inv = f'{prefix}_drop_invalid' if prefix else 'drop_invalid'
        conf.set_variable('prefix_drop_invalid', drop_inv)
        create_cmd = (
            f'{iptables_cmd} -N {drop_inv} 2>/dev/null' if not use_restore else ''
        )
        conf.set_variable('create_drop_invalid_chain', create_cmd)

        conf.set_variable(
            'accept_established',
            1 if self.fw.get_option('accept_established') else 0,
        )

        ipv4_fwd = self.fw.get_option('linux24_ip_forward')
        ipforw = str(ipv4_fwd) in ('1', 'On', 'on', '')
        conf.set_variable('ipforw', 1 if ipforw else 0)

        conf.set_variable('mgmt_access', 0)
        conf.set_variable(
            'bridging_firewall', 1 if self.fw.get_option('bridging_fw') else 0
        )
        conf.set_variable(
            'drop_new_tcp_with_no_syn',
            1 if not self.fw.get_option('accept_new_tcp_with_no_syn') else 0,
        )
        conf.set_variable(
            'add_rules_for_ipv6_neighbor_discovery',
            1 if (ipv6 and self.fw.get_option('ipv6_neighbor_discovery')) else 0,
        )

        drop_invalid = self.fw.get_option('drop_invalid')
        log_invalid = self.fw.get_option('log_invalid')
        conf.set_variable(
            'drop_invalid', 1 if (drop_invalid and not log_invalid) else 0
        )
        conf.set_variable(
            'drop_invalid_and_log', 1 if (drop_invalid and log_invalid) else 0
        )

        use_nflog = self.fw.get_option('use_NFLOG')
        conf.set_variable('use_nflog', 1 if use_nflog else 0)
        conf.set_variable('not_use_nflog', 0 if use_nflog else 1)

        # Legacy ULOG is always disabled (deprecated)
        conf.set_variable('not_use_ulog', 1)
        conf.set_variable('use_ulog', 0)

        nlgroup = 1
        cprange = 0
        qthreshold = 1
        if use_nflog:
            try:
                nlgroup = int(self.fw.get_option('ulog_nlgroup') or 1)
            except (TypeError, ValueError):
                nlgroup = 1
            try:
                cprange = int(self.fw.get_option('ulog_cprange') or 0)
            except (TypeError, ValueError):
                cprange = 0
            try:
                qthreshold = int(self.fw.get_option('ulog_qthreshold') or 1)
            except (TypeError, ValueError):
                qthreshold = 1

        conf.set_variable('nlgroup', nlgroup)
        conf.set_variable('cprange', cprange)
        conf.set_variable('qthreshold', qthreshold)
        conf.set_variable('use_nlgroup', 1 if nlgroup else 0)
        conf.set_variable('use_cprange', 1 if cprange > 0 else 0)
        conf.set_variable('use_qthreshold', 1 if qthreshold > 1 else 0)
        conf.set_variable('invalid_match_log_prefix', '"INVALID "')

        return conf.expand()

    def commit(self) -> str:
        """Generate COMMIT for iptables-restore format."""
        if self.fw.get_option('use_iptables_restore'):
            return "echo 'COMMIT'\n"
        return ''


# ═══════════════════════════════════════════════════════════════════
# Rule Processors
# ═══════════════════════════════════════════════════════════════════


class ConvertToAtomicForIntervals(PolicyRuleProcessor):
    """Split rules with multiple time intervals into separate rules.

    Corresponds to C++ PolicyCompiler::ConvertToAtomicForIntervals.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.when or len(rule.when) <= 1:
            self.tmp_queue.append(rule)
            return True

        for interval in rule.when:
            r = rule.clone()
            r.when = [interval]
            self.tmp_queue.append(r)

        return True


class ExpandGroupsInItf(PolicyRuleProcessor):
    """Expand groups in the interface rule element."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.compiler.expand_groups_in_element(rule, 'itf')
        self.tmp_queue.append(rule)
        return True


class ExpandGroupsInSrv(PolicyRuleProcessor):
    """Expand groups in the service rule element."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.compiler.expand_groups_in_element(rule, 'srv')
        self.tmp_queue.append(rule)
        return True


class InterfacePolicyRulesWithOptimization(PolicyRuleProcessor):
    """Split rules with multiple interfaces, setting subrule suffix.

    Like ConvertToAtomicForInterfaces but sets subrule_suffix for
    chain tracking. Matches C++ InterfacePolicyRulesWithOptimization.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.is_itf_any() or len(rule.itf) <= 1:
            self.tmp_queue.append(rule)
            return True

        for itf_obj in rule.itf:
            r = rule.clone()
            r.itf = [itf_obj]
            r.subrule_suffix = 'i1'
            self.tmp_queue.append(r)

        return True


class SingleObjectNegationItf(PolicyRuleProcessor):
    """Handle single-object interface negation."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('itf') and len(rule.itf) == 1:
            rule.itf_single_object_negation = True
            rule.set_neg('itf', False)
        self.tmp_queue.append(rule)
        return True


class SpecialCasesWithCustomServices(PolicyRuleProcessor):
    """Handle CustomService objects with ESTABLISHED/RELATED in their code.

    If a CustomService's platform code contains 'ESTABLISHED' or 'RELATED',
    it must be separated and made stateless (it handles state matching itself).

    Corresponds to C++ PolicyCompiler_ipt::specialCasesWithCustomServices.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.srv:
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        platform = ipt_comp.my_platform_name()

        to_separate = []
        for srv in rule.srv:
            if isinstance(srv, CustomService):
                code = (srv.codes or {}).get(platform, '')
                if code and ('ESTABLISHED' in code or 'RELATED' in code):
                    to_separate.append(srv)

        for srv in to_separate:
            r = rule.clone()
            r.srv = [srv]
            r.set_option('stateless', True)
            self.tmp_queue.append(r)

        remaining = [s for s in rule.srv if s not in to_separate]
        if remaining:
            rule.srv = remaining
            self.tmp_queue.append(rule)

        return True


class _Passthrough(PolicyRuleProcessor):
    """Base for processors that pass rules through (stub)."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)
        return True


class Accounting(PolicyRuleProcessor):
    """Handle rules with Accounting action.

    iptables does not have a target that does nothing without terminating
    packet processing (like NOP), so we create a new user chain with
    target RETURN.

    If the rule has an explicit ``rule_name_accounting`` option, that is
    used as the chain name; otherwise a new chain name is generated.

    When the generated chain name matches the current chain (shouldn't
    happen normally), the rule is turned into a Continue with RETURN
    target in-place.  Otherwise, a jump rule is created in the current
    chain and a RETURN rule is placed in the new chain.

    Corresponds to C++ ``PolicyCompiler_ipt::accounting``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.action != PolicyAction.Accounting or rule.ipt_target:
            self.tmp_queue.append(rule)
            return True

        rule_iface = rule.itf[0] if rule.itf else None

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_chain_name(rule, rule_iface)

        # Use explicit accounting chain name if provided
        rule_name_accounting = rule.get_option('rule_name_accounting', '')
        if rule_name_accounting:
            new_chain = rule_name_accounting

        if new_chain == this_chain:
            # Same chain: just set RETURN target and Continue action
            rule.ipt_target = 'RETURN'
            rule.action = PolicyAction.Continue
        else:
            # Create RETURN rule in the new chain (all elements cleared)
            r = rule.clone()
            r.src = []
            r.dst = []
            r.srv = []
            r.ipt_chain = new_chain
            r.upstream_rule_chain = this_chain
            ipt_comp.register_chain(new_chain)
            ipt_comp.insert_upstream_chain(this_chain, new_chain)
            r.ipt_target = 'RETURN'
            r.set_option('log', False)
            r.action = PolicyAction.Continue
            self.tmp_queue.append(r)

            # Modify original rule: jump to new chain
            rule.ipt_target = new_chain
            rule.set_option('log', False)
            rule.set_option('limit_value', -1)
            rule.set_option('connlimit_value', -1)
            rule.set_option('hashlimit_value', -1)

        self.tmp_queue.append(rule)
        return True


class BridgingFw(PolicyRuleProcessor):
    """Handle bridging firewall cases.

    For rules in the INPUT chain whose destination is a broadcast or
    multicast address, split the rule so that a copy goes into the
    FORWARD chain as well.  This handles broadcasts forwarded by a
    bridge that must also be accepted by the firewall itself.

    If the rule's interface is unnumbered or a bridge port, the rule is
    simply moved to FORWARD (no split needed -- the original is kept
    as-is in FORWARD).

    Corresponds to C++ ``PolicyCompiler_ipt::bridgingFw``.
    """

    @staticmethod
    def _is_broadcast_or_multicast(addr: Address) -> bool:
        """Check if an address is broadcast or multicast.

        Matches C++ ``bridgingFw::checkForMatchingBroadcastAndMulticast``
        simplified for our model: checks the address itself for broadcast
        (255.255.255.255) or multicast (224.0.0.0/4).
        """
        import ipaddress as _ipa

        if not isinstance(addr, Address):
            return False
        addr_str = addr.get_address()
        if not addr_str:
            return False
        try:
            ip = _ipa.ip_address(addr_str)
        except ValueError:
            return False
        # Address comparison against the "any" literal, not a socket bind.
        if ip == _ipa.ip_address('0.0.0.0'):  # nosec B104
            return False  # "any" is not broadcast/multicast
        return ip == _ipa.ip_address('255.255.255.255') or ip.is_multicast

    @staticmethod
    def _matches_interface_broadcast(
        addr: Address,
        fw,
    ) -> bool:
        """Check if address matches a broadcast address of any firewall interface.

        Matches C++ ``bridgingFw::checkForMatchingBroadcastAndMulticast``
        interface iteration logic.
        """
        import ipaddress as _ipa

        addr_str = addr.get_address()
        if not addr_str:
            return False
        try:
            obj_addr = _ipa.ip_address(addr_str)
        except ValueError:
            return False

        for iface in fw.interfaces:
            if not iface.is_regular():
                continue
            for iface_addr in iface.addresses:
                if not isinstance(iface_addr, IPv4):
                    continue
                ip_str = iface_addr.get_address()
                mask_str = iface_addr.get_netmask()
                if not ip_str or not mask_str:
                    continue
                try:
                    mask = _ipa.ip_address(mask_str)
                    # Skip host masks (255.255.255.255) -- bug #780345
                    if int(mask) == 0xFFFFFFFF:
                        continue
                    net = _ipa.ip_network(f'{ip_str}/{mask_str}', strict=False)
                    if obj_addr == net.network_address:
                        return True
                    if obj_addr == net.broadcast_address:
                        return True
                except ValueError:
                    continue
        return False

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        dst = rule.dst[0] if rule.dst else None

        if rule.ipt_chain == 'INPUT' and dst is not None:
            is_bcast_mcast = self._is_broadcast_or_multicast(
                dst,
            ) or self._matches_interface_broadcast(dst, ipt_comp.fw)

            if is_bcast_mcast:
                rule_iface = rule.itf[0] if rule.itf else None

                if isinstance(rule_iface, Interface) and (
                    rule_iface.is_unnumbered() or rule_iface.is_bridge_port()
                ):
                    # Unnumbered or bridge port: just move to FORWARD
                    ipt_comp.set_chain(rule, 'FORWARD')
                else:
                    # Regular interface: split into INPUT + FORWARD copy
                    r = rule.clone()
                    ipt_comp.set_chain(r, 'FORWARD')
                    self.tmp_queue.append(r)

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
        rule.originated_from_a_rule_with_tagging = bool(
            rule.get_option('tagging', False)
        )
        rule.originated_from_a_rule_with_classification = bool(
            rule.get_option('classification', False)
        )
        rule.originated_from_a_rule_with_routing = bool(
            rule.get_option('routing', False)
        )
        self.tmp_queue.append(rule)
        return True


class Logging2(PolicyRuleProcessor):
    """Process logging — create log chain with LOG/NFLOG + action rules."""

    def _log_target(self) -> str:
        """Return 'NFLOG' when the firewall option is set, otherwise 'LOG'."""
        if self.compiler.fw.get_option('use_NFLOG'):
            return 'NFLOG'
        return 'LOG'

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_option('log', False):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        log_target = self._log_target()

        # Special case: Continue action without tagging/classification/routing
        if (
            rule.action == PolicyAction.Continue
            and not rule.get_option('tagging', False)
            and not rule.get_option('classification', False)
            and not rule.get_option('routing', False)
        ):
            rule.ipt_target = log_target
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

        # 2) LOG/NFLOG rule in new_chain: all elements reset to any
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
        r2.ipt_target = log_target
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


class Logging1(PolicyRuleProcessor):
    """Force logging on all rules if fw has log_all option set.

    Corresponds to C++ ``PolicyCompiler_ipt::Logging1``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if self.compiler.fw.get_option('log_all'):
            rule.set_option('log', True)

        self.tmp_queue.append(rule)
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
        # https://github.com/Linuxfabrik/firewallfabrik/issues/16
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
        # https://github.com/Linuxfabrik/firewallfabrik/issues/16
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
            global_reject = self.compiler.fw.get_option('action_on_reject')
            if global_reject:
                rule.set_option('action_on_reject', global_reject)

        self.tmp_queue.append(rule)
        return True


class SplitRuleIfSrvAnyActionReject(PolicyRuleProcessor):
    """Split Reject rules with srv=any into TCP RST + original.

    When a Reject rule has no specific action_on_reject and srv is "any",
    creates an additional rule for "Any TCP" with action_on_reject="TCP RST"
    so TCP connections get RST while others get ICMP unreachable.

    Corresponds to C++ ``PolicyCompiler_ipt::splitRuleIfSrvAnyActionReject``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        aor = ipt_comp.get_action_on_reject(rule)

        if rule.action == PolicyAction.Reject and not aor and rule.is_srv_any():
            # Create TCP-only reject rule with TCP RST
            import uuid

            any_tcp = TCPService(id=uuid.uuid4(), name='Any TCP')
            any_tcp.src_range_start = 0
            any_tcp.src_range_end = 0
            any_tcp.dst_range_start = 0
            any_tcp.dst_range_end = 0

            r = rule.clone()
            r.srv = [any_tcp]
            r.set_option('action_on_reject', 'TCP RST')
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitServicesIfRejectWithTCPReset(PolicyRuleProcessor):
    """Split rules with Reject + TCP RST that have mixed TCP/non-TCP services.

    When action is Reject and action_on_reject contains "TCP ":
    - Only non-TCP services: warn and reset action_on_reject
    - Only TCP services: pass through unchanged
    - Both: create two rules (non-TCP without TCP RST, TCP with TCP RST)

    Called twice in the pipeline (matching fwbuilder behavior).

    Corresponds to C++ ``PolicyCompiler_ipt::splitServicesIfRejectWithTCPReset``.
    """

    def __init__(self, name: str = '') -> None:
        super().__init__(name)
        self._seen_rules: set[int] = set()

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            rule.action != PolicyAction.Reject
            or not ipt_comp.is_action_on_reject_tcp_rst(rule)
        ):
            self.tmp_queue.append(rule)
            return True

        if not rule.srv:
            # srv is "any" — can't split services, pass through
            self.tmp_queue.append(rule)
            return True

        tcp_services: list = []
        other_services: list = []
        for srv in rule.srv:
            # Use protocol name (more reliable — CustomService can set protocol)
            if srv.get_protocol_name() == 'tcp':
                tcp_services.append(srv)
            else:
                other_services.append(srv)

        if other_services and not tcp_services:
            # Only non-TCP services with TCP RST reject — warn and reset
            if rule.position not in self._seen_rules:
                self.compiler.warning(
                    rule,
                    "Rule action 'Reject' with TCP RST can be used "
                    'only with TCP services.',
                )
            ipt_comp.reset_action_on_reject(rule)
            self.tmp_queue.append(rule)
            self._seen_rules.add(rule.position)
            return True

        if not other_services and tcp_services:
            # Only TCP services — pass through unchanged
            self.tmp_queue.append(rule)
            return True

        # Both TCP and non-TCP — split into two rules
        # Rule 1: non-TCP services, clear action_on_reject
        r1 = rule.clone()
        r1.srv = other_services
        r1.set_option('action_on_reject', '')
        r1.subrule_suffix = '1'
        self.tmp_queue.append(r1)

        # Rule 2: TCP services, keep TCP RST
        r2 = rule.clone()
        r2.srv = tcp_services
        r2.subrule_suffix = '2'
        self.tmp_queue.append(r2)

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
            afpa = self.compiler.fw.get_option('firewall_is_part_of_any_and_networks')
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
            afpa = self.compiler.fw.get_option('firewall_is_part_of_any_and_networks')
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


class ConvertAnyToNotFWForShadowing(PolicyRuleProcessor):
    """Create Return rules for fw when src/dst is 'any' and fw-is-part-of-any is off.

    For the shadowing detection pass: when 'firewall_is_part_of_any_and_networks'
    is off, 'any' does NOT include the firewall. To model this for shadowing,
    create a Return rule with fw in the relevant element.

    Corresponds to C++ PolicyCompiler_ipt::convertAnyToNotFWForShadowing.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.get_option('firewall_is_part_of_any_and_networks')

        if not afpa:
            ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

            if rule.is_src_any():
                r = rule.clone()
                r.action = PolicyAction.Return
                r.src = [ipt_comp.fw]
                self.tmp_queue.append(r)

            if rule.is_dst_any():
                r = rule.clone()
                r.action = PolicyAction.Return
                r.dst = [ipt_comp.fw]
                self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcAnyForShadowing(PolicyRuleProcessor):
    """Split rules with src=any for the shadowing detection pass.

    When fw-is-part-of-any is on, create an OUTPUT copy with fw in src.

    Corresponds to C++ PolicyCompiler_ipt::splitIfSrcAnyForShadowing.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_option('classification', False):
            self.tmp_queue.append(rule)
            return True

        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.get_option('firewall_is_part_of_any_and_networks')

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            afpa
            and not rule.get_option('no_output_chain', False)
            and rule.direction != Direction.Inbound
            and rule.is_src_any()
        ):
            r = rule.clone()
            ipt_comp.set_chain(r, 'OUTPUT')
            r.direction = Direction.Outbound
            r.src = [ipt_comp.fw]
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstAnyForShadowing(PolicyRuleProcessor):
    """Split rules with dst=any for the shadowing detection pass.

    When fw-is-part-of-any is on, create an INPUT copy with fw in dst.

    Corresponds to C++ PolicyCompiler_ipt::splitIfDstAnyForShadowing.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_option('classification', False):
            self.tmp_queue.append(rule)
            return True

        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.get_option('firewall_is_part_of_any_and_networks')

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            afpa
            and not rule.get_option('no_input_chain', False)
            and rule.direction != Direction.Outbound
            and rule.is_dst_any()
        ):
            r = rule.clone()
            ipt_comp.set_chain(r, 'INPUT')
            r.direction = Direction.Inbound
            r.dst = [ipt_comp.fw]
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class ProcessMultiAddressObjectsInRE(PolicyRuleProcessor):
    """Process runtime MultiAddress objects (AddressTable, DNSName).

    For AddressTable objects: register with OS configurator and set
    the address_table_file option for runtime resolution.
    For DNSName objects: leave as-is (resolved at runtime).
    If multiple runtime objects exist, split into separate rules.

    Corresponds to C++ PolicyCompiler_ipt::processMultiAddressObjectsInRE.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        from firewallfabrik.core.objects import MultiAddressRunTime

        elements = getattr(rule, self._slot)
        if not elements:
            self.tmp_queue.append(rule)
            return True

        # Find runtime MultiAddress objects
        runtime_objs = [obj for obj in elements if isinstance(obj, MultiAddressRunTime)]

        if not runtime_objs:
            self.tmp_queue.append(rule)
            return True

        if len(elements) == 1 and len(runtime_objs) == 1:
            # Single runtime object -- register and pass through
            mart = runtime_objs[0]
            self._register_runtime_object(rule, mart)
            self.tmp_queue.append(rule)
            return True

        # Multiple objects -- split runtime ones into separate rules
        for mart in runtime_objs:
            r = rule.clone()
            setattr(r, self._slot, [mart])
            self._register_runtime_object(r, mart)
            self.tmp_queue.append(r)

        # Keep non-runtime objects in original rule
        remaining = [obj for obj in elements if obj not in runtime_objs]
        if remaining:
            setattr(rule, self._slot, remaining)
            self.tmp_queue.append(rule)

        return True

    def _register_runtime_object(self, rule, mart) -> None:
        """Register a runtime MultiAddress object with the OS configurator."""
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        if ipt_comp.oscnf is not None and hasattr(
            ipt_comp.oscnf, 'register_multi_address'
        ):
            ipt_comp.oscnf.register_multi_address(mart)
        # Set address table file path if applicable
        source_name = getattr(mart, 'source_name', '') or ''
        if source_name:
            rule.set_option('address_table_file', source_name)


class ProcessMultiAddressObjectsInSrc(ProcessMultiAddressObjectsInRE):
    def __init__(self, name):
        super().__init__(name, 'src')


class ProcessMultiAddressObjectsInDst(ProcessMultiAddressObjectsInRE):
    def __init__(self, name):
        super().__init__(name, 'dst')


class SplitIfSrcMatchesFw(PolicyRuleProcessor):
    """Split rule if src contains the firewall object.

    See :class:`SplitIfDstMatchesFw` for the rationale behind the
    ``len(remaining) > 1`` guard.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if len(rule.src) <= 1:
            self.tmp_queue.append(rule)
            return True

        remaining = list(rule.src)
        extracted = []
        for obj in list(remaining):
            if len(remaining) <= 1:
                break
            if ipt_comp.complex_match(obj, ipt_comp.fw):
                extracted.append(obj)
                remaining.remove(obj)

        for obj in extracted:
            r = rule.clone()
            r.src = [obj]
            self.tmp_queue.append(r)

        rule.src = remaining
        self.tmp_queue.append(rule)
        return True


class SplitIfDstMatchesFw(PolicyRuleProcessor):
    """Split rule if dst contains the firewall object.

    Mirrors C++ ``Compiler::splitIfRuleElementMatchesFW``: iterate
    dst objects, splitting each firewall-matching object into its own
    clone, but stop as soon as exactly one element remains in the
    original dst (``nre > 1`` guard in the C++ source).  Without that
    guard an AddressRange that overlaps the firewall (e.g. a /24 that
    contains the fw interface IP) would be pulled out together with
    the firewall object, leaving the original rule with an empty dst.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if len(rule.dst) <= 1:
            self.tmp_queue.append(rule)
            return True

        remaining = list(rule.dst)
        extracted = []
        for obj in list(remaining):
            if len(remaining) <= 1:
                break
            if ipt_comp.complex_match(obj, ipt_comp.fw):
                extracted.append(obj)
                remaining.remove(obj)

        for obj in extracted:
            r = rule.clone()
            r.dst = [obj]
            self.tmp_queue.append(r)

        rule.dst = remaining
        self.tmp_queue.append(rule)
        return True


class SplitIfSrcFWNetwork(PolicyRuleProcessor):
    """Split rule if src contains a network the FW has an interface on.

    Emits an OUTPUT-chain clone in addition to the original FORWARD rule
    when src references a Network object whose subnet covers one of the
    firewall's own interface addresses.

    Gated on ``firewall_is_part_of_any_and_networks`` (rule option, fw
    option fallback), plus ``no_output_chain`` (rule option) and
    ``bridging_fw`` (fw option) early exits — matching fwbuilder
    ``PolicyCompiler_ipt::splitIfSrcFWNetwork`` in
    ``PolicyCompiler_ipt.cpp:2528``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain or rule.is_src_any():
            self.tmp_queue.append(rule)
            return True

        if ipt_comp.fw.get_option('bridging_fw'):
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('no_output_chain', False):
            self.tmp_queue.append(rule)
            return True

        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = ipt_comp.fw.get_option('firewall_is_part_of_any_and_networks')
        if not afpa:
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
    """Split rule if dst contains a network the FW has an interface on.

    Symmetric counterpart to :class:`SplitIfSrcFWNetwork`: emits an
    INPUT-chain clone in addition to the original FORWARD rule when dst
    references a Network object whose subnet covers one of the
    firewall's own interface addresses.

    Gated on the same options (``firewall_is_part_of_any_and_networks``,
    ``no_input_chain``, ``bridging_fw``), matching fwbuilder
    ``PolicyCompiler_ipt::splitIfDstFWNetwork``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.ipt_chain or rule.is_dst_any():
            self.tmp_queue.append(rule)
            return True

        if ipt_comp.fw.get_option('bridging_fw'):
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('no_input_chain', False):
            self.tmp_queue.append(rule)
            return True

        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = ipt_comp.fw.get_option('firewall_is_part_of_any_and_networks')
        if not afpa:
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
        if dst is not None and not isinstance(dst, AddressRange):
            # AddressRange is handled by SplitIfDstMatchingAddressRange,
            # which emits a dedicated INPUT clone and leaves the
            # original rule free to become FORWARD.  Matching it here
            # (fwbuilder #2650) would hijack the only original copy
            # into INPUT and drop the FORWARD variant.
            #
            # Broadcast (255.255.255.255) and multicast (224.0.0.0/4,
            # ff00::/8) destinations must be treated as "matches fw"
            # too so Inbound rules that target them land in INPUT, not
            # FORWARD.  fwbuilder sets b=m=true here (see
            # PolicyCompiler_ipt.cpp, bug #811860).
            direction = rule.direction
            matches_fw = ipt_comp.complex_match(
                dst, ipt_comp.fw,
                recognize_broadcasts=True,
                recognize_multicasts=True,
            )

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
        if src is not None and not isinstance(src, AddressRange):
            # AddressRange is handled by SplitIfSrcMatchingAddressRange,
            # which emits a dedicated OUTPUT clone and leaves the
            # original rule free to become FORWARD.  Matching it here
            # (fwbuilder #2650) would hijack the only original copy
            # into OUTPUT and drop the FORWARD variant.
            direction = rule.direction
            matches_fw = ipt_comp.complex_match(
                src, ipt_comp.fw,
                recognize_broadcasts=True,
                recognize_multicasts=True,
            )

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

            # AddressRange matches the firewall only partially (some of
            # the addresses in the range are on the firewall, others
            # are not).  SplitIfSrc/DstMatchingAddressRange already
            # emitted a dedicated INPUT or OUTPUT clone, so the
            # original rule must stay on the FORWARD chain to keep
            # covering the non-firewall addresses (fwbuilder #2650).
            #
            # Recognise broadcast / multicast destinations as matching
            # the firewall here too: an Inbound rule that allows
            # e.g. DHCPv6 link-local -> ff00::/8 belongs in INPUT,
            # not FORWARD (fwbuilder #811860, b=m=true).
            src_matches = (
                src is not None
                and not isinstance(src, AddressRange)
                and ipt_comp.complex_match(
                    src, ipt_comp.fw,
                    recognize_broadcasts=True,
                    recognize_multicasts=True,
                )
            )
            dst_matches = (
                dst is not None
                and not isinstance(dst, AddressRange)
                and ipt_comp.complex_match(
                    dst, ipt_comp.fw,
                    recognize_broadcasts=True,
                    recognize_multicasts=True,
                )
            )

            if direction == Direction.Inbound:
                if dst_matches:
                    ipt_comp.set_chain(rule, 'INPUT')
            elif direction == Direction.Outbound:
                if src_matches:
                    ipt_comp.set_chain(rule, 'OUTPUT')
            else:
                if dst_matches:
                    ipt_comp.set_chain(rule, 'INPUT')
                elif src_matches:
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


class ExpandMultipleAddressesIfNotFWInSrc(PolicyRuleProcessor):
    """Expand hosts/firewalls with multiple addresses if first src is not Firewall.

    Unlike ``ExpandMultipleAddresses``, this skips expansion when the
    first object in src is a Firewall object itself, which is handled
    specially by later processors.

    Corresponds to C++ ``PolicyCompiler_ipt::expandMultipleAddressesIfNotFWinSrc``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        src = rule.src[0] if rule.src else None
        if not isinstance(src, Firewall):
            self.compiler.expand_addr(rule, 'src')

        self.tmp_queue.append(rule)
        return True


class ExpandMultipleAddressesIfNotFWInDst(PolicyRuleProcessor):
    """Expand hosts/firewalls with multiple addresses if first dst is not Firewall.

    Unlike ``ExpandMultipleAddresses``, this skips expansion when the
    first object in dst is a Firewall object itself.

    Corresponds to C++ ``PolicyCompiler_ipt::expandMultipleAddressesIfNotFWinDst``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        dst = rule.dst[0] if rule.dst else None
        if not isinstance(dst, Firewall):
            self.compiler.expand_addr(rule, 'dst')

        self.tmp_queue.append(rule)
        return True


class ExpandLoopbackInterfaceAddress(PolicyRuleProcessor):
    """Replace loopback interface objects in src/dst with their actual addresses.

    When a loopback interface (e.g., ``lo``) appears in src or dst,
    replace it with the first matching address (IPv4 or IPv6 depending
    on the compiler's address family). Aborts if the loopback interface
    has no addresses.

    Corresponds to C++ ``PolicyCompiler_ipt::expandLoopbackInterfaceAddress``.
    """

    def _replace_loopback(self, rule: CompRule, slot: str) -> None:
        """Replace loopback interfaces with their addresses in the given slot."""
        elements = getattr(rule, slot)
        if not elements:
            return

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        new_elements: list = []
        for obj in elements:
            if isinstance(obj, Interface) and obj.is_loopback():
                addr = None
                for a in obj.addresses:
                    if ipt_comp.ipv6_policy and isinstance(a, IPv6):
                        addr = a
                        break
                    if not ipt_comp.ipv6_policy and isinstance(a, IPv4):
                        addr = a
                        break
                if addr is None:
                    self.compiler.abort(
                        rule,
                        'Loopback interface of the firewall object does not '
                        'have IP address but is used in the rule',
                    )
                    new_elements.append(obj)
                else:
                    new_elements.append(addr)
            else:
                new_elements.append(obj)

        setattr(rule, slot, new_elements)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self._replace_loopback(rule, 'src')
        self._replace_loopback(rule, 'dst')

        self.tmp_queue.append(rule)
        return True


class SpecialCaseAddressRangeInRE(PolicyRuleProcessor):
    """Replace AddressRange with dimension==1 (start==end) by an Address object.

    When an AddressRange has the same start and end address (a single
    address), replace it with an IPv4 or IPv6 address object. This is
    done before ``splitIfSrcMatchingAddressRange`` to simplify matching.

    Corresponds to C++ ``PolicyCompiler_ipt::specialCaseAddressRangeInRE``.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def process_next(self) -> bool:
        import uuid

        rule = self.get_next()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements:
            self.tmp_queue.append(rule)
            return True

        import ipaddress as _ipa

        new_elements: list = []
        for obj in elements:
            # Note: ``is_any()`` on an AddressRange spuriously returns
            # True because AddressRange keeps its addresses in
            # ``start_address`` / ``end_address`` rather than
            # ``inet_addr_mask``; the base Address.is_any() checks the
            # latter and so treats every AddressRange as "any".  Guard
            # the conversion with an explicit start != "" test.
            if (
                isinstance(obj, AddressRange)
                and obj.get_start_address() == obj.get_end_address()
                and obj.get_start_address()
            ):
                # Single address -- replace with IPv4 or IPv6.  The
                # base Address.is_v4() queries ``inet_addr_mask`` which
                # is empty for AddressRange, so derive the family from
                # the start address directly.
                start_addr = obj.get_start_address()
                try:
                    ip_obj = _ipa.ip_address(start_addr)
                    is_v4 = ip_obj.version == 4
                except ValueError:
                    is_v4 = True
                if is_v4:
                    new_addr = IPv4(
                        id=uuid.uuid4(),
                        name=f'{obj.name}_addr',
                    )
                    new_addr.inet_addr_mask = {
                        'address': start_addr,
                        'netmask': '255.255.255.255',
                    }
                else:
                    new_addr = IPv6(
                        id=uuid.uuid4(),
                        name=f'{obj.name}_addr',
                    )
                    new_addr.inet_addr_mask = {
                        'address': start_addr,
                        'netmask': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
                    }
                new_elements.append(new_addr)
            else:
                new_elements.append(obj)

        setattr(rule, self._slot, new_elements)
        self.tmp_queue.append(rule)
        return True


class SpecialCaseAddressRangeInSrc(SpecialCaseAddressRangeInRE):
    """Replace single-address AddressRange in Src with an IPv4/IPv6 object."""

    def __init__(self, name: str) -> None:
        super().__init__(name, 'src')


class SpecialCaseAddressRangeInDst(SpecialCaseAddressRangeInRE):
    """Replace single-address AddressRange in Dst with an IPv4/IPv6 object."""

    def __init__(self, name: str) -> None:
        super().__init__(name, 'dst')


class SplitIfSrcMatchingAddressRange(PolicyRuleProcessor):
    """Split rule if src has AddressRange matching the firewall.

    If src contains an AddressRange that matches the firewall (via
    ``complex_match``), create a copy in the OUTPUT chain. This ensures
    the rule covers both FORWARD and OUTPUT paths.

    Corresponds to C++ ``PolicyCompiler_ipt::splitIfSrcMatchingAddressRange``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None

        if (
            rule.direction != Direction.Inbound
            and src is not None
            and isinstance(src, AddressRange)
            and ipt_comp.complex_match(src, ipt_comp.fw)
            # Skip the OUTPUT clone when the destination is the
            # firewall itself.  The resulting rule would match only
            # self-traffic generated by the firewall and delivered to
            # its own interface IP - in practice the kernel routes
            # that via ``lo`` and never enters OUTPUT, so the rule is
            # dead.  fwbuilder omits these atomic OUTPUT copies too.
            and not (dst is not None and ipt_comp.complex_match(dst, ipt_comp.fw))
        ):
            r = rule.clone()
            ipt_comp.set_chain(r, 'OUTPUT')
            r.direction = Direction.Outbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstMatchingAddressRange(PolicyRuleProcessor):
    """Split rule if dst has AddressRange matching the firewall.

    If dst contains an AddressRange that matches the firewall, create
    a copy in the INPUT chain for the Inbound direction.

    Corresponds to C++ ``PolicyCompiler_ipt::splitIfDstMatchingAddressRange``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None

        if (
            rule.direction != Direction.Outbound
            and dst is not None
            and isinstance(dst, AddressRange)
            and ipt_comp.complex_match(dst, ipt_comp.fw)
            # Skip the INPUT clone when the source is the firewall
            # itself - same rationale as in
            # SplitIfSrcMatchingAddressRange: the rule would only
            # match self-traffic that never hits INPUT.
            and not (src is not None and ipt_comp.complex_match(src, ipt_comp.fw))
        ):
            r = rule.clone()
            ipt_comp.set_chain(r, 'INPUT')
            r.direction = Direction.Inbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SpecialCaseWithFW1(PolicyRuleProcessor):
    """Split rule when both src AND dst match the firewall and direction is Both.

    Creates two rules: one Inbound and one Outbound, so the traffic
    from/to the firewall itself is properly handled.

    Corresponds to C++ ``PolicyCompiler_ipt::specialCaseWithFW1``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None

        if (
            src is not None
            and dst is not None
            and not (isinstance(src, Address) and src.is_any())
            and not (isinstance(dst, Address) and dst.is_any())
            and self.compiler.complex_match(src, self.compiler.fw)
            and self.compiler.complex_match(dst, self.compiler.fw)
            and rule.direction == Direction.Both
        ):
            r1 = rule.clone()
            r1.direction = Direction.Inbound
            self.tmp_queue.append(r1)

            r2 = rule.clone()
            r2.direction = Direction.Outbound
            self.tmp_queue.append(r2)
        else:
            self.tmp_queue.append(rule)

        return True


class CheckForDynamicInterfacesOfOtherObjects(PolicyRuleProcessor):
    """Abort if src/dst contains dynamic interfaces not belonging to this firewall.

    Dynamic interfaces get their addresses at runtime, so they can only
    be used if they belong to the firewall being compiled.

    Corresponds to C++ ``PolicyCompiler_ipt::checkForDynamicInterfacesOfOtherObjects``.
    """

    def _find_dynamic_interfaces(self, rule: CompRule, slot: str) -> bool:
        """Check for dynamic interfaces of other objects in a rule element.

        Returns True if the check passes (no foreign dynamic interfaces found).
        """
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        for obj in getattr(rule, slot):
            if (
                isinstance(obj, Interface)
                and obj.is_dynamic()
                and obj.device_id != ipt_comp.fw.id
            ):
                parent_name = ''
                if obj.device:
                    parent_name = obj.device.name
                self.compiler.abort(
                    rule,
                    f'Can not build rule using dynamic interface '
                    f"'{obj.name}' of the object '{parent_name}' "
                    f'because its address in unknown.',
                )
                return False
        return True

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if self._find_dynamic_interfaces(rule, 'src') and self._find_dynamic_interfaces(
            rule, 'dst'
        ):
            self.tmp_queue.append(rule)

        return True


class CheckForUnnumbered(PolicyRuleProcessor):
    """Abort if src/dst contains unnumbered or bridge-port interfaces.

    Unnumbered and bridge-port interfaces have no IP address and cannot
    be used as address objects in rules.

    Corresponds to C++ ``PolicyCompiler::checkForUnnumbered``.
    """

    @staticmethod
    def _catch_unnumbered(rule: CompRule, slot: str) -> bool:
        """Return True if an unnumbered/bridge-port interface is found."""
        for obj in getattr(rule, slot):
            if isinstance(obj, Interface) and (
                obj.is_unnumbered() or obj.is_bridge_port()
            ):
                return True
        return False

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if self._catch_unnumbered(rule, 'src') or self._catch_unnumbered(rule, 'dst'):
            self.compiler.abort(rule, 'Can not use unnumbered interfaces in rules.')

        self.tmp_queue.append(rule)
        return True


class CheckForZeroAddr(PolicyRuleProcessor):
    """Check src/dst for zero addresses and hosts without interfaces.

    Aborts compilation if:
    - A Host object has no interfaces (no address).
    - An Address object has address 0.0.0.0 with netmask 0.0.0.0
      (equivalent to 'any', likely a mistake).
    - A Network object has non-zero address but /0 netmask (likely typo).

    Corresponds to C++ ``PolicyCompiler::checkForZeroAddr``.
    """

    @staticmethod
    def _find_host_with_no_interfaces(elements: list) -> Host | None:
        """Find a Host object with no interfaces."""
        for obj in elements:
            if (
                isinstance(obj, Host)
                and not isinstance(obj, Firewall)
                and not obj.interfaces
            ):
                return obj
        return None

    @staticmethod
    def _find_zero_address(elements: list) -> Address | None:
        """Find an address with 0.0.0.0 or netmask /0."""
        import ipaddress as _ipaddress

        for obj in elements:
            if not isinstance(obj, Address):
                continue

            # Skip dynamic/unnumbered/bridge-port interfaces
            if isinstance(obj, Interface) and (
                obj.is_dynamic() or obj.is_unnumbered() or obj.is_bridge_port()
            ):
                continue

            # Skip AddressRange -- 0.0.0.0 is acceptable for ranges
            if isinstance(obj, AddressRange):
                continue

            if obj.is_any():
                continue

            addr_str = obj.get_address()
            mask_str = obj.get_netmask()

            if not addr_str:
                continue

            try:
                ip = _ipaddress.ip_address(addr_str)
            except ValueError:
                continue

            # Address 0.0.0.0 with netmask 0.0.0.0 -- equivalent to 'any'
            if int(ip) == 0 and mask_str:
                try:
                    nm = _ipaddress.ip_address(mask_str)
                    if int(nm) == 0:
                        return obj
                except ValueError:
                    pass

            # Network with non-zero address but /0 netmask -- likely typo
            if isinstance(obj, (Network, NetworkIPv6)) and int(ip) != 0 and mask_str:
                try:
                    nm = _ipaddress.ip_address(mask_str)
                    if int(nm) == 0:
                        return obj
                except ValueError:
                    pass

        return None

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Check for hosts with no interfaces
        a = self._find_host_with_no_interfaces(rule.src)
        if a is None:
            a = self._find_host_with_no_interfaces(rule.dst)
        if a is not None:
            self.compiler.abort(
                rule,
                f"Object '{a.name}' has no interfaces, therefore it does "
                f'not have address and can not be used in the rule.',
            )

        # Check for zero addresses
        a2 = self._find_zero_address(rule.src)
        if a2 is None:
            a2 = self._find_zero_address(rule.dst)
        if a2 is not None:
            err = f"Object '{a2.name}'"
            if isinstance(a2, IPv4):
                iface = getattr(a2, 'interface', None)
                if iface is not None:
                    iface_label = iface.name
                    err += f' (an address of interface {iface_label} )'
            err += (
                ' has address or netmask 0.0.0.0, which is equivalent '
                "to 'any'. This is likely an error."
            )
            self.compiler.abort(rule, err)

        self.tmp_queue.append(rule)
        return True


class OptimizeForMinusIOPlus(PolicyRuleProcessor):
    """Remove redundant wildcard interface ('*') in INPUT/OUTPUT chains.

    In INPUT/OUTPUT chains, iptables matches all interfaces by default,
    so specifying ``-i +`` or ``-o +`` (wildcard) is redundant. This
    processor clears the interface element to avoid generating the
    unnecessary match.

    Corresponds to C++ ``PolicyCompiler_ipt::optimizeForMinusIOPlus``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        iface = rule.itf[0] if rule.itf else None
        if iface is not None:
            iface_name = getattr(iface, 'name', '')
            if not iface_name or iface_name == 'nil':
                self.tmp_queue.append(rule)
                return True

            chain = rule.ipt_chain
            if iface_name == '*' and chain in ('INPUT', 'OUTPUT'):
                rule.itf = []

        self.tmp_queue.append(rule)
        return True


class CheckMACInOUTPUTChain(PolicyRuleProcessor):
    """Abort if MAC address (PhysAddress) is used in src in OUTPUT chain.

    iptables cannot match the MAC address of the firewall itself in
    the OUTPUT chain.

    Corresponds to C++ ``PolicyCompiler_ipt::checkMACinOUTPUTChain``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.ipt_chain == 'OUTPUT':
            src = rule.src[0] if rule.src else None
            if isinstance(src, PhysAddress):
                self.compiler.abort(rule, 'Can not match MAC address of the firewall')
                return True

        self.tmp_queue.append(rule)
        return True


class CheckUserServiceInWrongChains(PolicyRuleProcessor):
    """Warn and drop if UserService is used in chain other than OUTPUT.

    iptables ``-m owner`` (UserService) only works in the OUTPUT chain.
    Rules using UserService in other chains are warned about and dropped.

    Corresponds to C++ ``PolicyCompiler_ipt::checkUserServiceInWrongChains``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        srv = rule.srv[0] if rule.srv else None
        chain = rule.ipt_chain

        if (
            isinstance(srv, UserService)
            and chain != 'OUTPUT'
            and not ipt_comp.is_chain_descendant_of_output(chain)
        ):
            self.compiler.warning(
                rule,
                "Iptables does not support module 'owner' in a chain other than OUTPUT",
            )
            return True  # drop rule

        self.tmp_queue.append(rule)
        return True


class CheckInterfaceAgainstAddressFamily(PolicyRuleProcessor):
    """Drop rules where the interface has no addresses matching the address family.

    If the interface is "regular" (not dynamic, unnumbered, or bridge port),
    the compiler requires it to have addresses matching the current address
    family (IPv4 or IPv6). Rules with non-matching interfaces are dropped.

    Dynamic/unnumbered/bridge port interfaces are assumed to acquire
    appropriate addresses at runtime, so their rules are kept.

    Corresponds to C++ ``PolicyCompiler_ipt::checkInterfaceAgainstAddressFamily``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        rule_iface = rule.itf[0] if rule.itf else None
        if not isinstance(rule_iface, Interface):
            self.tmp_queue.append(rule)
            return True

        # Non-regular interfaces (dynamic, unnumbered, bridge port) may get
        # addresses at runtime — keep the rule
        if not rule_iface.is_regular():
            self.tmp_queue.append(rule)
            return True

        # Check if the interface has addresses matching the address family
        has_matching = False
        for addr in rule_iface.addresses:
            if ipt_comp.ipv6_policy and isinstance(addr, IPv6):
                has_matching = True
                break
            if not ipt_comp.ipv6_policy and isinstance(addr, IPv4):
                has_matching = True
                break

        if has_matching:
            self.tmp_queue.append(rule)
        # else: drop rule (interface has no matching addresses)
        return True


class SpecialCaseWithUnnumberedInterface(PolicyRuleProcessor):
    """Drop unnumbered/bridge port interface addresses from rules.

    Handles special cases where unnumbered or bridge port interfaces
    appear in src/dst:
    - Inbound: remove from src (source address is undetermined)
    - Outbound + OUTPUT chain: remove from dst
    - Outbound + other chain: remove from src

    Corresponds to C++ ``PolicyCompiler_ipt::specialCaseWithUnnumberedInterface``.
    """

    @staticmethod
    def _drop_unnumbered(rule: CompRule, slot: str) -> bool:
        """Remove unnumbered/bridge port interfaces from a rule element.

        Returns True if the element still has objects after filtering
        (or was "any" to begin with).
        """
        elements = getattr(rule, slot)
        if not elements:
            return True  # "any" — keep rule

        new_elements = [
            obj
            for obj in elements
            if not (
                isinstance(obj, Interface)
                and (obj.is_unnumbered() or obj.is_bridge_port())
            )
        ]
        setattr(rule, slot, new_elements)
        return bool(new_elements)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        keep_rule = True
        direction = rule.direction

        if direction == Direction.Inbound:
            keep_rule = self._drop_unnumbered(rule, 'src')
        elif direction == Direction.Outbound:
            if rule.ipt_chain == 'OUTPUT':
                keep_rule = self._drop_unnumbered(rule, 'dst')
            else:
                keep_rule = self._drop_unnumbered(rule, 'src')

        if keep_rule:
            self.tmp_queue.append(rule)
        return True


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


class CheckForStatefulICMP6Rules(PolicyRuleProcessor):
    """Force ICMPv6 rules to be stateless.

    Stateful inspection of ICMPv6 is complex and unreliable.
    Any rule matching ICMPv6 services is forced to stateless mode.

    Corresponds to C++ ``PolicyCompiler_ipt::checkForStatefulICMP6Rules``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.srv:
            srv = rule.srv[0]
            if isinstance(srv, ICMP6Service) and not rule.get_option(
                'stateless', False
            ):
                self.compiler.warning(
                    rule,
                    'Making rule stateless because it matches ICMPv6',
                )
                rule.set_option('stateless', True)

        self.tmp_queue.append(rule)
        return True


class Optimize2(PolicyRuleProcessor):
    """Clear service element on final/fallback rules for optimization.

    For rules marked as ``final``, clears the service element to "any"
    since the action applies regardless of service. Exception: Reject
    rules with TCP RST preserve service info (TCP RST needs a TCP match).

    Corresponds to C++ ``PolicyCompiler_ipt::optimize2``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.final:
            ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
            if (
                rule.action == PolicyAction.Reject
                and ipt_comp.is_action_on_reject_tcp_rst(rule)
            ):
                pass  # preserve service — TCP RST requires TCP match
            else:
                rule.srv = []  # clear to "any"

        self.tmp_queue.append(rule)
        return True


class PrepareForMultiport(PolicyRuleProcessor):
    """Prepare rules for multiport matching.

    Corresponds to C++ PolicyCompiler_ipt::prepareForMultiport.
    Sets the ``ipt_multiport`` flag for rules with multiple same-protocol
    TCP/UDP services and splits into chunks when the multiport entry count
    exceeds 15 (the iptables multiport module limit).

    Port ranges (e.g. 8000:8005) count as **2** entries toward the 15-port
    limit (start and end), not one.
    """

    @staticmethod
    def _multiport_entry_count(srv) -> int:
        """Return the number of multiport entries a single service uses.

        A port range (start != end on src or dst) occupies 2 entries;
        a single port occupies 1.
        """
        srs = srv.src_range_start or 0
        sre = srv.src_range_end or 0
        drs = srv.dst_range_start or 0
        dre = srv.dst_range_end or 0
        if srs != 0 and sre == 0:
            sre = srs
        if drs != 0 and dre == 0:
            dre = drs
        return 2 if (srs != sre or drs != dre) else 1

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        from firewallfabrik.core.objects import (
            CustomService,
            ICMPService,
            IPService,
            TagService,
            TCPService,
            UDPService,
        )

        if len(rule.srv) <= 1:
            self.tmp_queue.append(rule)
            return True

        first_srv = rule.srv[0]

        # Non-multiport service types: split into one rule per service
        if isinstance(first_srv, (ICMPService, IPService, CustomService, TagService)):
            for srv in rule.srv:
                r = rule.clone()
                r.srv = [srv]
                self.tmp_queue.append(r)
            return True

        # Only TCP/UDP can use multiport
        if not isinstance(first_srv, (TCPService, UDPService)):
            self.tmp_queue.append(rule)
            return True

        # Verify all services share the same protocol
        first_proto = type(first_srv)
        if not all(type(s) is first_proto for s in rule.srv[1:]):
            self.tmp_queue.append(rule)
            return True

        rule.ipt_multiport = True

        total_entries = sum(self._multiport_entry_count(s) for s in rule.srv)
        if total_entries > 15:
            # Split into chunks respecting the 15-entry limit
            chunk: list = []
            chunk_entries = 0
            for srv in rule.srv:
                entries = self._multiport_entry_count(srv)
                if chunk and chunk_entries + entries > 15:
                    r = rule.clone()
                    r.srv = chunk
                    r.ipt_multiport = True
                    self.tmp_queue.append(r)
                    chunk = []
                    chunk_entries = 0
                chunk.append(srv)
                chunk_entries += entries
            if chunk:
                r = rule.clone()
                r.srv = chunk
                r.ipt_multiport = True
                self.tmp_queue.append(r)
        else:
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


class CheckForObjectsWithErrors(PolicyRuleProcessor):
    """Check for objects marked with compilation errors.

    Iterates all rule elements and checks each object for the
    ``rule_error`` flag. If set, aborts compilation with the stored
    error message.

    In our CompRule model, objects generally don't carry error flags
    directly — instead, errors are recorded via ``compiler.abort()``.
    This processor catches any objects that were flagged with errors
    by earlier processors (e.g., via ``obj.data['rule_error']``).

    Corresponds to C++ ``Compiler::checkForObjectsWithErrors``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        for slot in ('src', 'dst', 'srv', 'itf'):
            for obj in getattr(rule, slot):
                data = getattr(obj, 'data', None) or {}
                if data.get('rule_error', False):
                    error_msg = data.get('error_msg', 'Object has errors')
                    name = getattr(obj, 'name', str(obj))
                    self.compiler.abort(
                        rule,
                        f"Object '{name}' has errors: {error_msg}",
                    )

        self.tmp_queue.append(rule)
        return True


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


# ═══════════════════════════════════════════════════════════════════
# Mangle Table Rule Processors
# ═══════════════════════════════════════════════════════════════════


class CheckActionInMangleTable(PolicyRuleProcessor):
    """Abort if action is Reject in mangle table.

    Only called when compiling for the mangle table. The Reject action
    has no valid target in the mangle table.

    Corresponds to C++ ``PolicyCompiler_ipt::checkActionInMangleTable``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.action == PolicyAction.Reject:
            self.compiler.abort(
                rule,
                'Action Reject is not allowed in mangle table',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class CheckForRestoreMarkInOutput(PolicyRuleProcessor):
    """Set have_connmark_in_output if tagging rule with CONNMARK in OUTPUT chain.

    If a tagging rule (or one that originated from a tagging rule) has
    the ipt_mark_connections option and is in the OUTPUT chain, sets the
    compiler flag so that a CONNMARK --restore-mark rule is generated
    in the OUTPUT chain during epilog.

    Corresponds to C++ ``PolicyCompiler_ipt::checkForRestoreMarkInOutput``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            (
                rule.get_option('tagging', False)
                or rule.originated_from_a_rule_with_tagging
            )
            and rule.get_option('ipt_mark_connections', False)
            and rule.ipt_chain == 'OUTPUT'
        ):
            ipt_comp.have_connmark_in_output = True

        self.tmp_queue.append(rule)
        return True


class CheckForUnsupportedCombinationsInMangle(PolicyRuleProcessor):
    """Abort if rule has routing AND (tagging or classification) with non-Continue action.

    In the mangle table, options Tag/Classify and Route can conflict
    because they require different chains (PREROUTING vs POSTROUTING).
    This combination is only allowed when the action is Continue.

    Corresponds to C++ ``PolicyCompiler_ipt::checkForUnsupportedCombinationsInMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            ipt_comp.my_table == 'mangle'
            and rule.action != PolicyAction.Continue
            and rule.get_option('routing', False)
            and (
                rule.get_option('tagging', False)
                or rule.get_option('classification', False)
            )
        ):
            action_str = rule.action.name if rule.action else 'unknown'
            self.compiler.abort(
                rule,
                'Can not process option Route in combination with '
                f'options Tag or Classify and action {action_str}',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class ClearActionInTagClassifyIfMangle(PolicyRuleProcessor):
    """Set action to Continue for tagging/classification rules in mangle table.

    In the mangle table, rules with tagging or classification options
    use targets MARK/CLASSIFY which are non-terminating. The action is
    forced to Continue so the packet continues through the chain.

    Corresponds to C++ ``PolicyCompiler_ipt::clearActionInTagClassifyIfMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if ipt_comp.my_table == 'mangle' and (
            rule.get_option('tagging', False)
            or rule.get_option('classification', False)
        ):
            rule.action = PolicyAction.Continue

        self.tmp_queue.append(rule)
        return True


class ClearLogInMangle(PolicyRuleProcessor):
    """Turn off logging for rules compiled in the mangle table.

    When a rule generates code in both filter and mangle tables,
    logging should only happen once (in filter). However, if the rule
    belongs to a mangle-only rule set, logging is preserved.

    Corresponds to C++ ``PolicyCompiler_ipt::clearLogInMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        rs = ipt_comp.source_ruleset
        if rs is not None:
            mangle_only = (
                rs.options.get('mangle_only_rule_set', False) if rs.options else False
            )
            if isinstance(mangle_only, str):
                mangle_only = mangle_only.lower() == 'true'
            if mangle_only:
                self.tmp_queue.append(rule)
                return True

        if ipt_comp.my_table == 'mangle':
            rule.set_option('log', False)

        self.tmp_queue.append(rule)
        return True


class ClearTagClassifyInFilter(PolicyRuleProcessor):
    """Clear classification/routing/tagging options when not in mangle table.

    These options only make sense in the mangle table. When compiling
    for the filter table, they are cleared to prevent interference
    with normal filter rule processing.

    Corresponds to C++ ``PolicyCompiler_ipt::clearTagClassifyInFilter``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if ipt_comp.my_table != 'mangle':
            rule.set_option('classification', False)
            rule.set_option('routing', False)
            rule.set_option('tagging', False)

        self.tmp_queue.append(rule)
        return True


class DecideOnChainForClassify(PolicyRuleProcessor):
    """Set chain to POSTROUTING for classification rules.

    Target CLASSIFY is only valid in mangle table, chain POSTROUTING.
    If the rule also has tagging, split it: tagging goes to a separate
    rule (to be placed in PREROUTING by later processors), while
    classification stays in POSTROUTING.

    Corresponds to C++ ``PolicyCompiler_ipt::decideOnChainForClassify``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_option('classification', False):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if not rule.ipt_chain:
            if rule.get_option('tagging', False):
                # Split: tagging rule without classification
                r = rule.clone()
                r.set_option('classification', False)
                r.set_option('routing', False)
                r.action = PolicyAction.Continue
                self.tmp_queue.append(r)

                # Original keeps classification, loses tagging
                rule.set_option('tagging', False)

            ipt_comp.set_chain(rule, 'POSTROUTING')

        self.tmp_queue.append(rule)
        return True


class DeprecateOptionRoute(PolicyRuleProcessor):
    """Abort if rule has routing option set (Route target is deprecated).

    The ROUTE target was removed from modern iptables. Users should
    use Custom Action to generate the command manually if needed.

    Corresponds to C++ ``PolicyCompiler_ipt::deprecateOptionRoute``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_option('routing', False):
            self.compiler.abort(
                rule,
                'Option Route is deprecated. You can use Custom Action '
                "to generate iptables command using '-j ROUTE' target "
                'if it is supported by your firewall OS',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class DropTerminatingTargets(PolicyRuleProcessor):
    """Only keep rules with targets CLASSIFY or MARK, drop all others.

    Used in special mangle passes where only non-terminating mark/classify
    rules should survive.

    Corresponds to C++ ``PolicyCompiler_ipt::dropTerminatingTargets``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        tgt = rule.ipt_target
        if tgt in ('CLASSIFY', 'MARK'):
            self.tmp_queue.append(rule)

        return True


class RouteProcessor(PolicyRuleProcessor):
    """Set chain to PREROUTING/POSTROUTING for routing rules.

    Based on the ipt_iif, ipt_oif, and ipt_gw options, assigns the
    appropriate mangle chain. If ipt_tee is set, creates copies in
    both PREROUTING and POSTROUTING.

    Named RouteProcessor to avoid conflict with Python keyword.

    Corresponds to C++ ``PolicyCompiler_ipt::Route``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_option('routing', False):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        iif = rule.get_option('ipt_iif', '') or ''
        oif = rule.get_option('ipt_oif', '') or ''
        gw = rule.get_option('ipt_gw', '') or ''

        if iif:
            ipt_comp.set_chain(rule, 'PREROUTING')

        if oif or gw:
            ipt_comp.set_chain(rule, 'POSTROUTING')

        if rule.get_option('ipt_tee', False):
            r1 = rule.clone()
            ipt_comp.set_chain(r1, 'PREROUTING')
            self.tmp_queue.append(r1)

            r2 = rule.clone()
            ipt_comp.set_chain(r2, 'POSTROUTING')
            self.tmp_queue.append(r2)

            return True

        self.tmp_queue.append(rule)
        return True


class SetChainForMangle(PolicyRuleProcessor):
    """Set chains based on direction and src matching fw in mangle table.

    In the mangle table, assigns chains based on direction:
    - Inbound -> PREROUTING
    - Outbound -> POSTROUTING
    - If src matches fw (and direction is not Inbound) -> OUTPUT

    Corresponds to C++ ``PolicyCompiler_ipt::setChainForMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if ipt_comp.my_table == 'mangle' and not rule.ipt_chain:
            if rule.direction == Direction.Inbound:
                ipt_comp.set_chain(rule, 'PREROUTING')

            if rule.direction == Direction.Outbound:
                ipt_comp.set_chain(rule, 'POSTROUTING')

            # If src matches fw and direction is not Inbound -> OUTPUT
            src = rule.src[0] if rule.src else None
            if (
                rule.direction != Direction.Inbound
                and not rule.is_src_any()
                and src is not None
                and ipt_comp.complex_match(src, ipt_comp.fw)
            ):
                ipt_comp.set_chain(rule, 'OUTPUT')

        self.tmp_queue.append(rule)
        return True


class SetChainPostroutingForTag(PolicyRuleProcessor):
    """Set chain POSTROUTING for tagging rules with direction Outbound/Both.

    For tagging rules (or rules that originated from tagging rules)
    without a chain assigned, direction Both/Outbound, and no interface:
    set chain to POSTROUTING.

    Must be called after splitIfDstAny.

    Corresponds to C++ ``PolicyCompiler_ipt::setChainPostroutingForTag``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            (
                rule.get_option('tagging', False)
                or rule.originated_from_a_rule_with_tagging
            )
            and not rule.ipt_chain
            and rule.direction in (Direction.Both, Direction.Outbound)
            and rule.is_itf_any()
        ):
            ipt_comp.set_chain(rule, 'POSTROUTING')

        self.tmp_queue.append(rule)
        return True


class SetChainPreroutingForTag(PolicyRuleProcessor):
    """Set chain PREROUTING for tagging rules with direction Both/Inbound.

    For tagging rules (or rules that originated from tagging rules)
    without a chain assigned, direction Both/Inbound, and no interface:
    set chain to PREROUTING.

    Must be called after splitIfSrcAny but before splitIfDstAny.

    Corresponds to C++ ``PolicyCompiler_ipt::setChainPreroutingForTag``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if (
            (
                rule.get_option('tagging', False)
                or rule.originated_from_a_rule_with_tagging
            )
            and not rule.ipt_chain
            and rule.direction in (Direction.Both, Direction.Inbound)
            and rule.is_itf_any()
        ):
            ipt_comp.set_chain(rule, 'PREROUTING')

        self.tmp_queue.append(rule)
        return True


class SpecialCaseWithFWInDstAndOutbound(PolicyRuleProcessor):
    """Drop outbound FORWARD rules where dst matches fw.

    In outbound direction with a non-OUTPUT chain and an interface
    belonging to the firewall: if src does not match fw but dst does,
    the packet would go to INPUT (not be forwarded), so the rule is
    dropped. Preserves rules with negated src or bridging fw with
    broadcast/multicast dst.

    Corresponds to C++ ``PolicyCompiler_ipt::specialCaseWithFWInDstAndOutbound``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        itf = rule.itf[0] if rule.itf else None
        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None
        chain = rule.ipt_chain

        if (
            rule.direction == Direction.Outbound
            and isinstance(itf, Interface)
            and itf.device_id == ipt_comp.fw.id
            and chain != 'OUTPUT'
        ):
            # Bridging fw with broadcast/multicast dst: keep rule
            if (
                dst is not None
                and hasattr(dst, 'is_broadcast')
                and (dst.is_broadcast() or dst.is_multicast())
                and ipt_comp.fw.get_option('bridging_fw')
            ):
                self.tmp_queue.append(rule)
                return True

            # Negated src: keep rule
            if rule.get_neg('src') or rule.src_single_object_negation:
                self.tmp_queue.append(rule)
                return True

            rule_afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)

            src_matches = (
                ipt_comp.complex_match(src, ipt_comp.fw) if src is not None else False
            )
            dst_matches = (
                ipt_comp.complex_match(dst, ipt_comp.fw) if dst is not None else False
            )

            # If afpa is off, network objects don't match unless host mask
            if (
                not rule_afpa
                and src is not None
                and (rule.is_src_any() or isinstance(src, (Network, NetworkIPv6)))
                and not (hasattr(src, 'is_host_mask') and src.is_host_mask())
            ):
                src_matches = False
            if (
                not rule_afpa
                and dst is not None
                and (rule.is_dst_any() or isinstance(dst, (Network, NetworkIPv6)))
                and not (hasattr(dst, 'is_host_mask') and dst.is_host_mask())
            ):
                dst_matches = False

            if not src_matches and dst_matches:
                # src does not match, dst matches: drop the rule
                return True

            self.tmp_queue.append(rule)
            return True

        self.tmp_queue.append(rule)
        return True


class SplitIfTagAndConnmark(PolicyRuleProcessor):
    """Create additional CONNMARK --save-mark rule for tagging with ipt_mark_connections.

    If a rule has tagging and ipt_mark_connections option, appends the
    original rule and creates an additional rule with target CONNMARK
    and --save-mark argument to persist the mark to the connection.

    Corresponds to C++ ``PolicyCompiler_ipt::splitIfTagAndConnmark``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_option('tagging', False) and rule.get_option(
            'ipt_mark_connections', False
        ):
            ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

            # Append original rule first
            self.tmp_queue.append(rule)

            # Create CONNMARK rule
            r = rule.clone()
            r.ipt_target = 'CONNMARK'
            r.action = PolicyAction.Continue
            r.set_option('classification', False)
            r.set_option('routing', False)
            r.set_option('tagging', False)
            r.set_option('log', False)
            r.set_option('CONNMARK_arg', '--save-mark')
            self.tmp_queue.append(r)

            ipt_comp.have_connmark = True
        else:
            self.tmp_queue.append(rule)

        return True


class SplitIfTagClassifyOrRoute(PolicyRuleProcessor):
    """Split rule if it uses tagging, classification, or routing options.

    In the mangle table, if a rule uses more than one of
    (tagging, classification, routing) and has non-any elements, creates
    a jump rule to a temp chain and then separate rules for each option.
    This ensures each option can be placed in its correct chain.

    Corresponds to C++ ``PolicyCompiler_ipt::splitIfTagClassifyOrRoute``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        number_of_options = 0
        if rule.get_option('tagging', False):
            number_of_options += 1
        if rule.get_option('classification', False):
            number_of_options += 1
        if rule.get_option('routing', False):
            number_of_options += 1

        if ipt_comp.my_table == 'mangle' and number_of_options > 0:
            this_chain = rule.ipt_chain
            new_chain = this_chain

            has_non_any = (
                not rule.is_src_any()
                or not rule.is_dst_any()
                or not rule.is_srv_any()
                or not rule.is_itf_any()
            )

            if has_non_any and number_of_options > 1:
                # Create jump rule to temp chain
                new_chain = ipt_comp.get_new_tmp_chain_name(rule)

                r = rule.clone()
                r.subrule_suffix = 'ntt'
                r.ipt_target = new_chain
                r.set_option('classification', False)
                r.set_option('routing', False)
                r.set_option('tagging', False)
                r.set_option('log', False)
                r.action = PolicyAction.Continue
                self.tmp_queue.append(r)

                # Clear elements in original, make stateless
                rule.src = []
                rule.dst = []
                rule.srv = []
                rule.itf = []
                rule.set_option('limit_value', -1)
                rule.set_option('connlimit_value', -1)
                rule.set_option('hashlimit_value', -1)
                rule.set_option('stateless', True)
                rule.set_option('log', False)

            # Create separate rule for tagging
            if rule.get_option('tagging', False):
                r = rule.clone()
                r.set_option('classification', False)
                r.set_option('routing', False)
                rule.set_option('tagging', False)
                r.ipt_chain = new_chain
                r.upstream_rule_chain = this_chain
                r.action = PolicyAction.Continue
                self.tmp_queue.append(r)

            # Create separate rule for classification
            if rule.get_option('classification', False):
                r = rule.clone()
                rule.set_option('classification', False)
                r.set_option('routing', False)
                r.set_option('tagging', False)
                r.ipt_chain = new_chain
                r.upstream_rule_chain = this_chain
                r.action = PolicyAction.Continue
                self.tmp_queue.append(r)

            # Keep original for routing or if action is not Continue
            if (
                rule.get_option('routing', False)
                or rule.action != PolicyAction.Continue
            ):
                rule.set_option('classification', False)
                rule.set_option('tagging', False)
                rule.ipt_chain = new_chain
                rule.upstream_rule_chain = this_chain
                self.tmp_queue.append(rule)

        else:
            self.tmp_queue.append(rule)

        return True
