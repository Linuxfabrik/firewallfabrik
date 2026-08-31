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

import hashlib
from collections import defaultdict
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    CheckForTCPEstablished,
    ConvertToAtomicForAddresses,
    DropIPv4Rules,
    DropIPv6Rules,
    DropRuleWithEmptyRE,
    EliminateDuplicatesInDST,
    EliminateDuplicatesInSRC,
    EliminateDuplicatesInSRV,
    EmptyGroupsInRE,
    ExpandGroups,
    PrintTotalNumberOfRules,
    RecursiveGroupsInRE,
    ReplaceClusterInterfaceInItfRE,
    ResolveMultiAddress,
    SimplePrintProgress,
    SingleRuleFilter,
    VerifyAddresses,
    VerifyAddressRanges,
    VerifyMacAddresses,
    VerifyScriptLiterals,
    VerifyTimeIntervals,
)
from firewallfabrik.compiler.processors._policy import (
    AddressRangesInDst,
    AddressRangesInSrc,
    DropRuleWithImpossibleInterface,
    ExpandMultipleAddressesIfNotFWInDst,
    ExpandMultipleAddressesIfNotFWInSrc,
    ItfNegation,
    SingleObjectNegationItf,
    SpecialCaseAddressRangeInDst,
    SpecialCaseAddressRangeInSrc,
    SpecialCaseWithFWInDstAndOutbound,
    assumes_fw_is_part_of_any,
    branches_into_mangle_only,
    dst_is_a_cluster_this_firewall_is_in,
    is_mangle_only_rule_set,
)
from firewallfabrik.compiler.processors._service import (
    SeparateSrcPort,
    SeparateTCPWithFlags,
    SeparateUserServices,
    VerifyCustomServices,
    VerifyIcmpTypes,
    VerifyIpProtocols,
    VerifyPortRanges,
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
    PolicyAction,
    TagService,
    TCPService,
    UDPService,
    UserService,
    get_address_table_source,
    is_run_time_address_table,
    netmask_prefix_length,
)
from firewallfabrik.platforms.iptables._utils import (
    MATCH_FIRST_RELEASE,
    bridge_port_matches_inbound_in_postrouting,
    get_iptables_version,
    single_negation_qualifies,
    version_compare,
)
from firewallfabrik.platforms.linux._netfilter import (
    ANY_INTERFACE,
    INVALID_STATE_LOG_PREFIX,
    branch_closes_a_loop,
    count_bridge_interfaces,
    custom_service_code,
    custom_service_matches_state,
    forwarding_is_off,
    get_log_copy_range,
    get_log_netlink_group,
    get_log_queue_threshold,
    interface_direction_problem,
    is_valid_mgmt_address,
    make_any_tcp_service,
    mgmt_address_family,
    reset_srv_preserving_tcp,
    strip_mac_objects,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator

# Chain names PrintRule must never try to create: the built-in chains and
# every target the compiler can put into ``ipt_target``.  iptables refuses a
# chain whose name is one of its targets ("chain name may not clash with
# target name", assert_valid_chain_name in netfilter iptables/xshared.c), so
# a missing entry here produces a `-N` command that always fails.  NFLOG and
# ULOG are missing from the same list in fwbuilder
# (PolicyCompiler_ipt::getStandardChains).
STANDARD_CHAINS = [
    'INPUT',
    'OUTPUT',
    'FORWARD',
    'PREROUTING',
    'POSTROUTING',
    'RETURN',
    'LOG',
    'NFLOG',
    'ULOG',
    'ACCEPT',
    'DROP',
    'REJECT',
    'MARK',
    'CONNMARK',
    'QUEUE',
    'CLASSIFY',
    'ROUTE',
]


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

        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False
        self.my_table: str = 'filter'
        self.minus_n_commands: dict[str, bool] | None = minus_n_commands
        self.bridge_count: int = 0

        # Hash tables a rate limit kept per source, destination or port
        # counts in, keyed by table name and holding the settings the first
        # rule gave it. The kernel keeps those for every later rule naming
        # the same table.  The driver replaces this with one dict shared by
        # every rule set and by both table passes, because the collision it
        # has to catch happens between compiler instances just as often as
        # inside one.
        self.hashlimit_tables: dict[str, tuple[int, str, str]] = {}

        # Chain management
        self.chain_usage_counter: dict[str, int] = defaultdict(int)
        self.upstream_chains: dict[str, list[str]] = defaultdict(list)
        self.tmp_chain_counters: dict[str, int] = {}

        # The chain a branch rule set writes into, set by the driver through
        # `register_rule_set_chain()`. Empty for the top rule set.
        self.rule_set_chain: str = ''

        # The names of the rule sets a Branch rule can jump to, filled by
        # the driver.  Every rule set is compiled by a compiler of its own,
        # so the one holding the branching rule has no other way to tell
        # whether the target is compiled into this script at all.
        self.branch_chains: set[str] = set()
        # The branch jumps that close a cycle, as (source, target) rule set
        # names; filled by the driver, which is the only place that sees
        # every rule set of the script.
        self.branch_loop_edges: set[tuple[str, str]] = set()

        # Print rule processor reference
        self.print_rule_processor = None

        # iptables version
        self.version: str = get_iptables_version(fw)

        # Chain prefix for coexistence mode (e.g. 'fwf' → fwf_INPUT)
        self.chain_prefix: str = ''

        # ipset usage flag
        self.using_ipset: bool = False
        if version_compare(self.version, '1.4.1.1') >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set'))

    @staticmethod
    def get_standard_chains() -> list[str]:
        return STANDARD_CHAINS

    def my_platform_name(self) -> str:
        return 'iptables'

    def can_match_inbound_in_postrouting(self, rule) -> bool:
        """Only a bridge port, which is written as ``-m physdev``.

        See :func:`bridge_port_matches_inbound_in_postrouting` for why, and
        for the two cases that take the answer away again.
        """
        obj = rule.itf[0] if rule.itf else None
        return bridge_port_matches_inbound_in_postrouting(self, obj)

    def prolog(self) -> int:
        """Initialize compiler: verify platform, set up interfaces."""
        for chain in self.get_standard_chains():
            self.chain_usage_counter[chain] = 1

        n = super().prolog()

        # A branch rule set is only reached through the jump of the rule that
        # branches into it, so its rules live in a chain of their own.  Every
        # chain decision downstream keeps a chain that is already set, so
        # presetting it here is all it takes (fwbuilder
        # CompilerDriver_ipt::assignRuleSetChain).  Without it the rules end
        # up in INPUT, OUTPUT and FORWARD and apply to all traffic.
        if self.rule_set_chain:
            for rule in self.rules:
                rule.ipt_chain = self.rule_set_chain

        # PrintRule names the parent bridge next to a wildcard bridge port
        # only when there is more than one bridge to tell apart, so count
        # them here (C++ PolicyCompiler_ipt::prolog).
        self.bridge_count = count_bridge_interfaces(self.fw)

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

        # Run separate shadowing detection pass before the main pipeline
        if self.fw.get_option('check_shading') and not self.single_rule_compile_mode:
            self.run_shadowing_pass()

        # -- Full processor pipeline --
        self.add(Begin('Begin compilation'))
        self.add(PrintTotalNumberOfRules())
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

        # Before the expansion, not after: an interface group nothing is
        # left in expands to an empty element, an empty element is "any"
        # everywhere downstream, and the rule then applies to every
        # interface the firewall has instead of being reported.  fwbuilder
        # asks the same question in the same place
        # (PolicyCompiler_ipt.cpp: emptyGroupsInItf ahead of
        # expandGroupsInItf); the other three elements are already checked
        # ahead of `ExpandGroups` further down.
        self.add(EmptyGroupsInRE('check for empty groups in ITF', 'itf'))
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

        self.add(TimeNegation('process negation in Time'))

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

        # fwbuilder switches pipelines at iptables 1.2.11: below it an
        # address range has to be written out as the networks covering it
        # (PolicyCompiler_ipt::compile picks addressRanges over
        # specialCaseAddressRangeInRE below that release).  ip6tables needs
        # the same fallback much longer: there never was a
        # libip6t_iprange.c, the match only became family neutral with
        # libxt_iprange.c in 1.4.1, and its NFPROTO_IPV6 registration sits
        # in revision 1 of that file.  Before that the generated
        # `-m iprange --src-range` command fails to load and stops the
        # activation script.
        first_iprange = MATCH_FIRST_RELEASE['iprange'][bool(self.ipv6_policy)]
        no_iprange = (
            version_compare(self.version, '1.2.11') < 0
            or version_compare(self.version, first_iprange) < 0
        )
        if no_iprange:
            self.add(AddressRangesInSrc('process address ranges in Src'))
            self.add(AddressRangesInDst('process address ranges in Dst'))
        else:
            self.add(
                SpecialCaseAddressRangeInSrc('replace single address range in Src')
            )
            self.add(
                SpecialCaseAddressRangeInDst('replace single address range in Dst')
            )
            self.add(
                SplitIfSrcMatchingAddressRange(
                    'split if Src has matching address range'
                )
            )
            self.add(
                SplitIfDstMatchingAddressRange(
                    'split if Dst has matching address range'
                )
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
        # Everything from here on decides a chain, and a chain decision
        # that reads a Host object instead of the addresses behind it
        # answers a different question.  fwbuilder expands both elements
        # here, before the loopback check and `finalizeChain`
        # (PolicyCompiler_ipt.cpp:4566), and drops a rule the expansion
        # emptied right after.
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
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))
        # A rule may still name several interfaces here, and every chain
        # decision below reads the first one.  fwbuilder splits the rule
        # per interface first and then asks whether that one interface has
        # an address of the family being compiled
        # (PolicyCompiler_ipt.cpp:4580).
        self.add(InterfacePolicyRulesWithOptimization('process interface policy rules'))
        self.add(
            CheckInterfaceAgainstAddressFamily(
                'check if interface matches address family'
            )
        )
        self.add(DecideOnChainIfLoopback('any-any rule on loopback'))
        self.add(FinalizeChain('assign chain'))

        self.add(SpecialCaseWithFWInDstAndOutbound('drop outbound with fw in dst'))

        self.add(DecideOnTarget('set target'))

        self.add(CheckForRestoreMarkInOutput('check for CONNMARK restore in OUTPUT'))

        self.add(RemoveFW('remove fw'))
        # Expand any remaining Firewall objects in src/dst to all of their
        # interface addresses (one rule per address). Required so that
        # anti-spoofing rules whose source is the firewall object itself
        # cover every own IP, not just the address of the rule's own
        # interface. Mirrors fwbuilder's PolicyCompiler_ipt.cpp:4616
        # ``ExpandMultipleAddresses("expand multiple addresses")``.
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(
            ExpandLoopbackInterfaceAddress(
                'check for loopback interface in rule objects'
            )
        )
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))

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

        self.add(Optimize1('optimization 1, pass 1'))
        self.add(Optimize1('optimization 1, pass 2'))
        self.add(Optimize1('optimization 1, pass 3'))

        self.add(GroupServicesByProtocol('split on services'))
        self.add(SeparateTCPWithFlags('split on TCP services with flags'))
        self.add(VerifyCustomServices('verify custom services'))
        self.add(VerifyPortRanges('verify port ranges'))
        self.add(VerifyIcmpTypes('verify ICMP types'))
        self.add(VerifyIpProtocols('verify IP protocols'))
        self.add(VerifyAddressRanges('verify address ranges'))
        self.add(VerifyScriptLiterals('verify names reaching the script'))
        self.add(VerifyAddresses('verify addresses'))
        self.add(VerifyMacAddresses('verify MAC addresses'))
        self.add(VerifyTimeIntervals('verify time intervals'))
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

        # Before CountChainUsage: a rule left out here may be the only
        # jump to a temporary chain, which then must not be created.
        self.add(DropRuleWithImpossibleInterface())

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

        # An imported .fwb stores these as strings, so compare them as
        # numbers the way the print rule does instead of against 0.
        def _positive(key: str) -> bool:
            try:
                return int(rule.options.get(key, 0)) > 0
            except (TypeError, ValueError):
                return False

        if _positive('limit_value'):
            meta += ' limit'
        if _positive('connlimit_value'):
            meta += ' connlimit'
        if _positive('hashlimit_value'):
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
        """Generate a new temporary chain name.

        fwbuilder derives the chain name from the rule's persistent XML
        string ID.  fwf regenerates Rule UUIDs on every `.fwb` / `.fwf`
        load, so deriving the hash from `rule.id` would give a different
        iptables script on every run -- breaking byte-level idempotency.
        Instead we hash the stable rule metadata (ruleset name, rule
        position, subrule suffix).  The name alone does not tell two rule
        sets apart, which is what `rule_set_key` is for.
        """
        stable_key = (
            f'{self.rule_set_key()}:{rule.position}:{rule.subrule_suffix}'
            f'{":c" if rule.classify_half else ""}'
        )
        chain_id = hashlib.md5(  # nosec B324
            stable_key.encode(),
            usedforsecurity=False,
        ).hexdigest()[:12]
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
        # fwbuilder is handed `Interface::cast(...)`, which answers null for
        # the "every interface" group, so that group contributes no prefix.
        if isinstance(iface, Interface):
            iface_name = iface.name.replace('*', '')
            parts.append(f'{iface_name}_')

        direction = rule.direction
        if direction == Direction.Inbound:
            parts.append('In_')
        elif direction == Direction.Outbound:
            parts.append('Out_')

        ruleset_name = self.get_rule_set_name()
        if self.rule_set_chain:
            # Firewall Builder asks whether the name is "Policy" and
            # writes "RULE_" when it is (`getNewChainName`), which is the
            # right answer for the firewall's own top rule set and the
            # wrong one for an imported rule set that happens to carry
            # that name too: both then build a chain called RULE_<n> and
            # the rules of the two land in one.  See `rule_set_key`.
            parts.append(f'{self.rule_set_chain}_')
        elif ruleset_name != 'Policy':
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
        if rule.classify_half:
            parts.append('_c')

        return ''.join(parts)

    def insert_upstream_chain(self, parent: str, child: str) -> None:
        self.upstream_chains[parent].append(child)

    def register_rule_set_chain(self, chain_name: str) -> None:
        self.chain_usage_counter[chain_name] = 1
        # Every rule of this rule set belongs into that chain, not into a
        # built-in one; `prolog()` puts it there.  Only the first call names
        # this compiler's own rule set.
        if not self.rule_set_chain:
            self.rule_set_chain = chain_name

    def set_chain(self, rule: CompRule, chain: str) -> None:
        rule.ipt_chain = chain

    def is_chain_descendant_of(
        self, chain: str, ancestor: str, seen: set[str] | None = None
    ) -> bool:
        """Is *chain* reachable from *ancestor* by following the jumps?

        What the kernel allows in a rule is decided by the hook, not by the
        name of the chain the rule is in: a match that registers for
        PREROUTING, INPUT and FORWARD is refused just as much in a chain
        the POSTROUTING chain jumps to.  Every processor that moves a rule
        into a temporary chain records the jump
        (`insert_upstream_chain`), so the question can be asked of the
        chain the rule ended up in.

        A chain can be reached from more than one place, so every parent is
        followed rather than the first one found, and `seen` keeps a jump
        graph that leads back on itself from looping here.
        """
        if chain == ancestor:
            return True
        if seen is None:
            seen = set()
        if chain in seen:
            return False
        seen.add(chain)
        return any(
            chain in children and self.is_chain_descendant_of(parent, ancestor, seen)
            for parent, children in self.upstream_chains.items()
        )

    def is_chain_descendant_of_input(self, chain: str) -> bool:
        return self.is_chain_descendant_of(chain, 'INPUT')

    def is_chain_descendant_of_output(self, chain: str) -> bool:
        return self.is_chain_descendant_of(chain, 'OUTPUT')

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

        # The counters are quoted: unquoted, `[0:0]` is a bracket glob
        # and the shell replaces it with a file named `0` or `:` if one
        # happens to sit in the directory the script runs from.  The
        # line then reads `:INPUT DROP 0`, which iptables-restore
        # refuses (netfilter iptables-restore.c: parse_counters wants
        # `[%llu:%llu]`), and the restore stops at the first chain with
        # the built-in policies already set to DROP.
        result = ''
        result += 'echo ":INPUT DROP [0:0]"\n'
        result += 'echo ":FORWARD DROP [0:0]"\n'
        result += 'echo ":OUTPUT DROP [0:0]"\n'
        return result

    def clamp_tcp_to_mss_rule(self) -> str:
        """Return the TCPMSS clamping rule, or a comment, or nothing.

        Ports ``PolicyCompiler_ipt::PrintRule::_clampTcpToMssRule``
        (iptlib/PolicyCompiler_PrintRule.cpp:1717).  Which table the rule
        goes into is the caller's question and depends on the release:
        fwbuilder puts it in the filter table below 1.3.0
        (``PolicyCompiler_ipt::printAutomaticRules``) and in the mangle
        table from 1.3.0 on
        (``MangleTableCompiler_ipt::printAutomaticRulesForMangleTable``),
        with the same comment above both call sites - "iptables accepted
        TCPMSS target in filter table, FORWARD chain in the older
        versions, but requires it to be in mangle filter starting
        somewhere 1.3.x".  Current kernels take the target in either
        table (``xt_TCPMSS`` registers no ``.table``, verified against
        iptables 1.8.11), so the old form still loads.

        The rule only makes sense on a firewall that forwards, and
        ip6tables has no TCPMSS target before 1.3.8 (fwbuilder bug
        #2477775; ``libip6t_TCPMSS.c`` first ships in that release).
        Saying so is what tells the administrator that path MTU discovery
        is not being helped along, which is the whole point of the option.
        """
        if not self.fw.get_option('clamp_mss_to_mtu'):
            return ''

        ipv6 = self.ipv6_policy
        version = self.version
        forwards = not forwarding_is_off(self.fw, ipv6)

        if ipv6 and version_compare(version, '1.3.8') < 0:
            if not forwards:
                return ''
            message = 'target TCPMSS is not supported by ip6tables before v1.3.8'
            self.warning(message)
            return f'# {message}\n\n'

        if not forwards:
            return ''

        # In coexistence mode this rule belongs in the firewall's own
        # chain like every other one.  Written into the real FORWARD it
        # cannot be told apart from another tool's afterwards, so
        # `reset_fwf_chains` leaves it there and the next activation
        # appends a second copy - measured against real iptables, one more
        # every time the script runs.
        chain = f'{self.chain_prefix}_FORWARD' if self.chain_prefix else 'FORWARD'
        return (
            f'{chain} -p tcp -m tcp --tcp-flags SYN,RST SYN '
            '-j TCPMSS --clamp-mss-to-pmtu'
        )

    def print_automatic_rules(self) -> str:
        """Generate automatic rules using the automatic_rules configlet."""
        from firewallfabrik.driver._configlet import Configlet

        if self.single_rule_compile_mode:
            return ''

        version = self.version
        ipv6 = self.ipv6_policy
        iptables_cmd = '$IP6TABLES' if ipv6 else '$IPTABLES'

        use_restore = bool(self.fw.get_option('use_iptables_restore'))

        # iptables-restore mode: each rule must be emitted as
        # ``echo "-A CHAIN ..."`` so the heredoc piped to
        # ``iptables-restore`` contains a valid ``-A`` line. Mirrors
        # fwbuilder's PolicyCompiler_PrintRuleIptRstEcho semantics.
        # Shell mode: each rule is a direct ``$IPTABLES -A CHAIN ...``
        # invocation.
        if use_restore:
            begin_rule = 'echo "-A'
            end_rule = '"'
        else:
            begin_rule = f'{iptables_cmd} -A'
            end_rule = ''

        if version_compare(version, '1.4.4') >= 0:
            state_module_option = 'conntrack --ctstate'
        else:
            state_module_option = 'state --state'

        # ip6tables learnt to match on connection state in 1.3.5, the
        # release libip6t_state.c first shipped in; before that neither
        # `state` nor `conntrack` exists for IPv6 and the command answers
        # "Couldn't load match", which stops the activation script.  The
        # automatic rules that need one are left out, all of them accepts
        # or drops of traffic that cannot be recognised without state, so
        # the firewall ends up stricter rather than more permissive.
        stateful = not (ipv6 and version_compare(version, '1.3.5') < 0)
        if not stateful:
            self.warning(
                'ip6tables before 1.3.5 has no connection state match; the '
                'automatic rules that need one are left out'
            )

        conf = Configlet('linux24', 'automatic_rules')
        conf.collapse_empty_strings(True)

        conf.set_variable('begin_rule', begin_rule)
        conf.set_variable('end_rule', end_rule)
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
        # iptables-restore only knows a chain it has seen declared, so the
        # chain the invalid-state rules jump to needs its own `:name - [0:0]`
        # line, the same one the rule set chains already get.  Without it
        # restore stops at the first jump with "Chain 'drop_invalid' does not
        # exist" and the firewall keeps the ruleset it had.
        create_cmd = (
            f'echo ":{drop_inv} - [0:0]"'
            if use_restore
            else f'{iptables_cmd} -N {drop_inv} 2>/dev/null'
        )
        conf.set_variable('create_drop_invalid_chain', create_cmd)

        conf.set_variable(
            'accept_established',
            1 if (stateful and self.fw.get_option('accept_established')) else 0,
        )

        # The IPv6 pass has to ask the IPv6 setting: a host may route one
        # family and not the other, and reading the IPv4 switch here decided
        # the IPv6 automatic rules by something unrelated to them.
        conf.set_variable('ipforw', 0 if forwarding_is_off(self.fw, ipv6) else 1)

        # The rule that keeps the way in open.  fwbuilder writes it into the
        # automatic rules of the ruleset itself
        # (PolicyCompiler_ipt::PrintRule::_printBackupSSHAccessRules, called
        # from _printAutomaticRules), which is the whole point of the option:
        # a policy activated over ssh from the management station must not cut
        # the session that is activating it.  It belongs to the pass whose
        # family the address has - iptables answers an IPv6 address with
        # "host/network not found" and stops the script right there.
        mgmt_addr = str(self.fw.get_option('mgmt_addr') or '')
        mgmt_access = (
            bool(self.fw.get_option('mgmt_ssh'))
            and bool(mgmt_addr)
            and is_valid_mgmt_address(mgmt_addr)
            and mgmt_address_family(mgmt_addr) == ('ip6' if ipv6 else 'ip')
        )
        conf.set_variable('mgmt_access', 1 if mgmt_access else 0)
        conf.set_variable('ssh_management_address', mgmt_addr)
        conf.set_variable(
            'bridging_firewall', 1 if self.fw.get_option('bridging_fw') else 0
        )
        conf.set_variable(
            'drop_new_tcp_with_no_syn',
            1
            if (stateful and not self.fw.get_option('accept_new_tcp_with_no_syn'))
            else 0,
        )
        conf.set_variable(
            'add_rules_for_ipv6_neighbor_discovery',
            1
            if (ipv6 and self.fw.get_option('add_rules_for_ipv6_neighbor_discovery'))
            else 0,
        )

        drop_invalid = stateful and self.fw.get_option('drop_invalid')
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
            nlgroup = int(get_log_netlink_group(self) or 1)
            cprange = get_log_copy_range(self)
            qthreshold = get_log_queue_threshold(self)

        # The configlet writes `--nflog-size`, which is the only option that
        # actually shortens what NFLOG copies: `--nflog-range` sets the length
        # but not XT_NFLOG_F_COPY_LEN, so the kernel ignores it and iptables
        # warns about it on every activation (netfilter
        # extensions/libxt_NFLOG.c).  `--nflog-size` arrived in iptables 1.6.1;
        # an older target has no way to say this at all.  Same rule and same
        # warning as the per-rule NFLOG parameters in the print rule.
        if cprange > 0 and version_compare(version, '1.6.1') < 0:
            self.warning(
                'iptables before 1.6.1 cannot limit how much of a packet NFLOG '
                'copies to userspace; the "Copy range" setting is left out of '
                'the rule that logs invalid packets and the whole packet is '
                'copied',
            )
            cprange = 0

        conf.set_variable('nlgroup', nlgroup)
        conf.set_variable('cprange', cprange)
        conf.set_variable('qthreshold', qthreshold)
        conf.set_variable('use_nlgroup', 1 if nlgroup else 0)
        conf.set_variable('use_cprange', 1 if cprange > 0 else 0)
        conf.set_variable('use_qthreshold', 1 if qthreshold > 1 else 0)
        # In iptables-restore mode the rule is wrapped in `echo "..."`, so the
        # quotes around the prefix have to be escaped for the shell, the same
        # way the print rule quotes a per-rule log prefix.
        quote = '\\"' if use_restore else '"'
        conf.set_variable(
            'invalid_match_log_prefix',
            f'{quote}{INVALID_STATE_LOG_PREFIX}{quote}',
        )

        # Below 1.3.0 the TCPMSS clamp belongs to the filter table, above the
        # rest of the automatic rules, which is where the reference output
        # for firewall10 and firewall2-1 carries it.  From 1.3.0 on the mangle
        # compiler emits it instead.
        clamp = ''
        if version_compare(version, '1.3.0') < 0:
            clamp = self.clamp_tcp_to_mss_rule()
            if clamp and not clamp.startswith('#'):
                clamp = f'{begin_rule} {clamp}{end_rule}\n\n'

        return clamp + conf.expand()

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
                code = custom_service_code(srv, platform)
                if custom_service_matches_state(code):
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
        interface iteration logic, including its ``hasInetAddress()`` guard:
        a rule element may still hold an Interface or another object that
        carries no address of its own, and asking such an object for one
        would end the compile with no script written at all.
        """
        import ipaddress as _ipa

        if not isinstance(addr, Address):
            return False
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
    """Drop rules that belong in the mangle table.

    Corresponds to C++ ``PolicyCompiler_ipt::dropMangleTableRules``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if is_mangle_only_rule_set(self.compiler.source_ruleset):
            return True  # drop

        # A branch into a mangle-only rule set has nothing to jump to here:
        # that rule set's chain lives in the mangle table.  Left in, the
        # jump goes into an empty chain of the same name in the filter table
        # and the branch does nothing at all.
        if branches_into_mangle_only(rule, self.compiler):
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

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self._reported_no_nflog = False

    def _log_target(self) -> str:
        """Return 'NFLOG' when the firewall option is set, otherwise 'LOG'.

        The NFLOG target arrived in iptables 1.3.7 (netfilter
        extensions/libipt_NFLOG.c and libip6t_NFLOG.c, merged into
        libxt_NFLOG.c in 1.4.0).  An older binary answers "Couldn't load
        target 'NFLOG'", which stops the activation script, so such a
        firewall keeps the LOG target it has always had.
        """
        if self.compiler.fw.get_option('use_NFLOG'):
            ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
            if version_compare(ipt_comp.version, '1.3.7') >= 0:
                return 'NFLOG'
            if not self._reported_no_nflog:
                self._reported_no_nflog = True
                self.compiler.warning(
                    'iptables before 1.3.7 has no NFLOG target; logging goes '
                    'through LOG instead'
                )
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

        # 1) Jump rule: from current chain to new_chain.  A rule that is
        # already in that chain and matches on nothing would jump to
        # itself, which the kernel refuses with "Loop found in table" and
        # which stops the activation with every chain at DROP
        # (PolicyCompiler_ipt::Logging2 calls that `need_new_chain`).
        needs_jump_rule = not (
            this_chain == new_chain
            and not rule.src
            and not rule.dst
            and not rule.srv
            and not rule.when
        )
        if needs_jump_rule:
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
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        r2.ipt_target = log_target
        r2.action = PolicyAction.Continue
        r2.direction = Direction.Both
        r2.set_option('log', False)
        r2.set_option('classification', False)
        r2.set_option('routing', False)
        r2.set_option('tagging', False)
        r2.set_option('stateless', True)
        # A packet crosses the log rule and the action rule below it, so a
        # rate limit left on both is a second bucket the same packet has to
        # pay: only half the packets a "20 per second" rule admits reach
        # its action.  The jump rule keeps the limits
        # (PolicyCompiler_ipt::Logging2 clears all three here).
        r2.set_option('limit_value', -1)
        r2.set_option('connlimit_value', -1)
        r2.set_option('hashlimit_value', -1)
        r2.force_state_check = False
        self.tmp_queue.append(r2)

        # 3) Action rule in new_chain: all elements reset, inherits action
        r3 = rule.clone()
        r3.src = []
        r3.dst = []
        reset_srv_preserving_tcp(r3)
        r3.itf = []
        r3.when = []
        r3.ipt_chain = new_chain
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        r3.iface_label = 'nil'
        r3.direction = Direction.Both
        r3.set_option('log', False)
        r3.final = True
        r3.set_option('stateless', True)
        r3.set_option('limit_value', -1)
        r3.set_option('connlimit_value', -1)
        r3.set_option('hashlimit_value', -1)
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


class SingleRENegation(PolicyRuleProcessor):
    """Negate a rule element holding one object with iptables' own ``!``.

    Ports ``PolicyCompiler_ipt::SingleRENegation``
    (fwbuilder iptlib/PolicyCompiler_ipt.cpp).  Everything else that is
    negated needs the three-rule temporary chain of ``SrcNegation`` and its
    siblings; what can be said in one ``!`` is said in one ``!``.

    Which objects qualify is :func:`single_negation_qualifies`, shared with
    the NAT pipeline.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def _qualifies(self, obj) -> bool:
        return single_negation_qualifies(self.compiler, obj)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        elements = getattr(rule, self._slot)
        if (
            rule.get_neg(self._slot)
            and len(elements) == 1
            and self._qualifies(elements[0])
        ):
            setattr(rule, f'{self._slot}_single_object_negation', True)
            rule.set_neg(self._slot, False)
        self.tmp_queue.append(rule)
        return True


class SingleSrcNegation(SingleRENegation):
    """Handle single-object src negation with inline '!' syntax."""

    def __init__(self, name: str = 'single src negation') -> None:
        super().__init__(name, 'src')


class SingleDstNegation(SingleRENegation):
    """Handle single-object dst negation with inline '!' syntax."""

    def __init__(self, name: str = 'single dst negation') -> None:
        super().__init__(name, 'dst')


class SingleSrvNegation(SingleRENegation):
    """Handle single-object srv negation with inline '!' syntax.

    Only a Tag or a User service: every other service is matched by more
    than one option, and iptables has no ``!`` for a whole match.
    """

    def __init__(self, name: str = 'single srv negation') -> None:
        super().__init__(name, 'srv')


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
        # Every copy below inherits it: `removeFW` must not collapse a
        # rule the negation expansion built (PolicyCompiler_ipt::SrcNegation
        # sets it on the rule the three copies are duplicated from).
        rule.set_option('upstream_rule_neg', True)

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except src
        r_jump = rule.clone()
        r_jump.subrule_suffix = '1'
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
        r_return.subrule_suffix = '2'
        r_return.dst = []
        r_return.srv = []
        r_return.itf = []
        r_return.when = []
        r_return.ipt_chain = new_chain
        r_return.action = PolicyAction.Return
        # A rule already carrying a target is the jump rule of an outer
        # negation, and a copy of it would jump on instead of returning
        # (PolicyCompiler_ipt::SrcNegation and its three siblings all clear
        # it).  `DecideOnTarget` fills RETURN in afterwards.
        r_return.ipt_target = ''
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything
        # https://github.com/Linuxfabrik/firewallfabrik/issues/16
        r_action = rule.clone()
        r_action.subrule_suffix = '3'
        r_action.src = []
        r_action.dst = []
        reset_srv_preserving_tcp(r_action)
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_action)

        return True


class TimeNegation(PolicyRuleProcessor):
    """Expand a negated time restriction into a temporary chain.

    iptables has no way to negate ``-m time``: the match module takes a
    window and matches inside it, and there is no ``!`` for the whole set of
    its options (netfilter extensions/libxt_time.c).  So the rule is turned
    into the same three-rule shape the address negations use, which says
    "outside this window" by excluding the window instead of negating it:

    1. a jump rule carrying the original conditions into a new chain,
    2. a RETURN rule in that chain matching the interval, so traffic *inside*
       the window leaves again without being acted on,
    3. the action rule, which everything that did not return reaches.

    Corresponds to C++ ``PolicyCompiler_ipt::TimeNegation``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('when'):
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        rule.set_neg('when', False)
        # Every copy below inherits it: `removeFW` must not collapse a rule
        # the negation expansion built
        # (PolicyCompiler_ipt::TimeNegation sets it on the rule the copies
        # are duplicated from).
        rule.set_option('upstream_rule_neg', True)

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)

        # Jump rule: everything except the time, which is checked in the chain
        r_jump = rule.clone()
        r_jump.subrule_suffix = '1'
        r_jump.when = []
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

        # Return rule: keep only the interval, which is what is excluded
        r_return = rule.clone()
        r_return.subrule_suffix = '2'
        r_return.src = []
        r_return.dst = []
        r_return.srv = []
        r_return.itf = []
        r_return.ipt_chain = new_chain
        r_return.action = PolicyAction.Return
        # A rule already carrying a target is the jump rule of an outer
        # negation, and a copy of it would jump on instead of returning
        # (PolicyCompiler_ipt::SrcNegation and its three siblings all clear
        # it).  `DecideOnTarget` fills RETURN in afterwards.
        r_return.ipt_target = ''
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: everything was matched already
        r_action = rule.clone()
        r_action.subrule_suffix = '3'
        r_action.src = []
        r_action.dst = []
        reset_srv_preserving_tcp(r_action)
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
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
        # Every copy below inherits it: `removeFW` must not collapse a
        # rule the negation expansion built (PolicyCompiler_ipt::SrcNegation
        # sets it on the rule the three copies are duplicated from).
        rule.set_option('upstream_rule_neg', True)

        this_chain = rule.ipt_chain
        new_chain = ipt_comp.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except dst
        r_jump = rule.clone()
        r_jump.subrule_suffix = '1'
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
        r_return.subrule_suffix = '2'
        r_return.src = []
        r_return.srv = []
        r_return.itf = []
        r_return.when = []
        r_return.ipt_chain = new_chain
        r_return.action = PolicyAction.Return
        # A rule already carrying a target is the jump rule of an outer
        # negation, and a copy of it would jump on instead of returning
        # (PolicyCompiler_ipt::SrcNegation and its three siblings all clear
        # it).  `DecideOnTarget` fills RETURN in afterwards.
        r_return.ipt_target = ''
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything
        # https://github.com/Linuxfabrik/firewallfabrik/issues/16
        r_action = rule.clone()
        r_action.subrule_suffix = '3'
        r_action.src = []
        r_action.dst = []
        reset_srv_preserving_tcp(r_action)
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
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
        r_jump.subrule_suffix = '1'
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
        r_return.subrule_suffix = '2'
        r_return.src = []
        r_return.dst = []
        r_return.itf = []
        r_return.when = []
        r_return.ipt_chain = new_chain
        r_return.action = PolicyAction.Return
        # A rule already carrying a target is the jump rule of an outer
        # negation, and a copy of it would jump on instead of returning
        # (PolicyCompiler_ipt::SrcNegation and its three siblings all clear
        # it).  `DecideOnTarget` fills RETURN in afterwards.
        r_return.ipt_target = ''
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        ipt_comp.insert_upstream_chain(this_chain, new_chain)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything.  The service was already matched by
        # the jump rule and the RETURN rules above.
        def make_action_rule() -> CompRule:
            r = rule.clone()
            r.subrule_suffix = '3'
            r.src = []
            r.dst = []
            r.srv = []
            r.itf = []
            r.when = []
            r.ipt_chain = new_chain
            r.set_option('stateless', True)
            r.force_state_check = False
            r.final = True
            # `removeFW` must not collapse a rule the negation expansion
            # built (PolicyCompiler_ipt::SrvNegation sets it here).
            r.set_option('upstream_rule_neg', True)
            return r

        ipt_comp.insert_upstream_chain(this_chain, new_chain)

        if rule.action == PolicyAction.Reject and ipt_comp.is_action_on_reject_tcp_rst(
            rule
        ):
            # `--reject-with tcp-reset` needs `-p tcp`; iptables refuses the
            # rule without it, and clearing the service element takes that
            # match away.  Split the action the way
            # SplitRuleIfSrvAnyActionReject does for a service-any Reject
            # rule: TCP is reset, everything else gets the default ICMP
            # unreachable.  The TCP rule has to come first, otherwise the
            # general one already caught the packet.
            r_tcp = make_action_rule()
            r_tcp.srv = [make_any_tcp_service()]
            self.tmp_queue.append(r_tcp)

            r_other = make_action_rule()
            ipt_comp.reset_action_on_reject(r_other)
            self.tmp_queue.append(r_other)
        else:
            self.tmp_queue.append(make_action_rule())

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

        if rule.is_itf_any():
            # A direction and no interface: the rule still has to say which
            # of the two it is, and the element is where fwbuilder says it
            # (see ANY_INTERFACE).  Putting it here rather than inferring it
            # in the print rule is what makes it disappear again wherever a
            # processor resets the element - a rule moved into a temporary
            # chain has already been narrowed by the rule that jumps there.
            rule.itf = [ANY_INTERFACE]
            return True

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
            # A chain that is already assigned rules out one of the two
            # directions, because its hook only knows one of the two devices.
            if not interface_direction_problem(rule.ipt_chain, inbound=True):
                r1 = rule.clone()
                r1.direction = Direction.Inbound
                self.tmp_queue.append(r1)

            if not interface_direction_problem(rule.ipt_chain, inbound=False):
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

        tcp_services: list = []
        other_services: list = []
        for srv in rule.srv:
            # Use protocol name (more reliable — CustomService can set protocol)
            if srv.get_protocol_name() == 'tcp':
                tcp_services.append(srv)
            else:
                other_services.append(srv)

        if not rule.srv:
            # "any" is every protocol, so it belongs with the non-TCP ones.
            # fwbuilder reaches the same branch because its service element
            # holds a reference to the "Any" object, which does not report
            # protocol "tcp"; fwf stores "any" as an empty list, so the case
            # has to be named.  Leaving the TCP reset in place produces a
            # rule the kernel refuses outright (netfilter linux
            # net/ipv4/netfilter/ipt_REJECT.c: reject_tg_check returns
            # -EINVAL unless the rule pins IPPROTO_TCP), which stops the
            # activation script with the built-in policies already set to
            # DROP.  nftables takes the same rule and silently narrows it to
            # TCP instead, so the traffic the rule was written to reject
            # passes.
            other_services = [None]

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
        afpa = assumes_fw_is_part_of_any(rule)
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        if rule.get_option('no_output_chain', False):
            self.tmp_queue.append(rule)
            return True

        # A bridge port is matched with `-m physdev --physdev-out`, which
        # iptables does not allow in the OUTPUT chain (fwbuilder #2008), so
        # the copy this processor would make is a command that stops the
        # activation.
        itf = rule.itf[0] if rule.itf else None
        if (
            self.compiler.fw.get_option('bridging_fw')
            and itf is not None
            and getattr(itf, 'is_bridge_port', lambda: False)()
        ):
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

            # CLASSIFY registers for LOCAL_OUT, FORWARD and POST_ROUTING
            # (net/netfilter/xt_CLASSIFY.c), and the copy above went into
            # OUTPUT alone, so a classifying rule never reached the chain
            # where a forwarded packet is classified.
            if ipt_comp.my_table == 'mangle' and rule.get_option(
                'classification', False
            ):
                r = rule.clone()
                ipt_comp.set_chain(r, 'POSTROUTING')
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
        afpa = assumes_fw_is_part_of_any(rule)
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

            # The mangle counterpart of the OUTPUT copy above: a marking
            # target that only works before the routing decision needs the
            # prerouting chain, which INPUT is not.
            if ipt_comp.my_table == 'mangle' and rule.get_option(
                'classification', False
            ):
                r = rule.clone()
                ipt_comp.set_chain(r, 'PREROUTING')
                r.direction = Direction.Inbound
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

        afpa = assumes_fw_is_part_of_any(rule)

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

        afpa = assumes_fw_is_part_of_any(rule)

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

        # Find runtime MultiAddress objects.  A run-time AddressTable is one
        # of them: ResolveMultiAddress leaves it alone because its addresses
        # are only known on the firewall.
        runtime_objs = [
            obj
            for obj in elements
            if isinstance(obj, MultiAddressRunTime) or is_run_time_address_table(obj)
        ]

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
        """Register a runtime MultiAddress object with the OS configurator.

        The registration is what puts the table into the script's
        ``check_run_time_address_table_files`` (and, with ipset, into
        ``load_run_time_address_table_files``), so the activation stops with
        a clear message when the file is gone instead of loading a ruleset
        that matches nothing.
        """
        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        source_name = get_address_table_source(mart, self.compiler.fw) or getattr(
            mart, 'source_name', ''
        )
        if ipt_comp.oscnf is not None and source_name:
            ipt_comp.oscnf.register_multi_address_object(
                mart.name, source_name, ipt_comp.ipv6_policy
            )
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

        afpa = assumes_fw_is_part_of_any(rule)
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

        afpa = assumes_fw_is_part_of_any(rule)
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
    """Replace fw with its interface addresses when src==dst==fw.

    A bridge port is left out along with an unnumbered interface
    (``PolicyCompiler_ipt::specialCaseWithFW2``,
    ``if (iface->isUnnumbered() || iface->isBridgePort()) continue``).  A
    port of a bridge carries the bridge's traffic, not its own; an address
    configured on it belongs to the bridge, and taking it in here would
    make the rule match packets the port never terminates.
    """

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
                if iface.is_unnumbered() or iface.is_bridge_port():
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

        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None
        # A bridging firewall sees the traffic to its own addresses in
        # FORWARD as well, whenever it arrives over a bridged path, and a
        # rule that is not tied to a routing interface cannot tell the two
        # apart.  fwbuilder therefore emits both copies (bugs #811860,
        # #934949 and #1231 in PolicyCompiler_ipt::decideOnChainIf{Src,Dst}FW);
        # the interface test is what keeps it from duplicating a rule that
        # already names a routing interface.  Broadcasts and multicasts are
        # deliberately not recognised for this test, unlike the chain
        # decision below.
        if (
            dst is not None
            and ipt_comp.fw.get_option('bridging_fw')
            and ipt_comp.complex_match(
                dst,
                ipt_comp.fw,
                recognize_broadcasts=False,
                recognize_multicasts=False,
            )
        ):
            rule_iface = rule.itf[0] if rule.itf else None
            # "Every interface" is not an interface: fwbuilder asks
            # `Interface::cast(getFirstItf(rule))`, which answers null for
            # the group it puts there, so a rule that names a direction and
            # no interface has to take the same branch it always did.
            if not isinstance(rule_iface, Interface) or rule_iface.is_bridge_port():
                forward_copy = rule.clone()
                ipt_comp.set_chain(forward_copy, 'FORWARD')
                self.tmp_queue.append(forward_copy)

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
            # FORWARD (fwbuilder bug #811860).
            direction = rule.direction
            matches_fw = ipt_comp.complex_match(
                dst,
                ipt_comp.fw,
                recognize_broadcasts=True,
                recognize_multicasts=True,
            ) or dst_is_a_cluster_this_firewall_is_in(dst, ipt_comp.fw)

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

        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        # A bridging firewall sees the traffic to its own addresses in
        # FORWARD as well, whenever it arrives over a bridged path, and a
        # rule that is not tied to a routing interface cannot tell the two
        # apart.  fwbuilder therefore emits both copies (bugs #811860,
        # #934949 and #1231 in PolicyCompiler_ipt::decideOnChainIf{Src,Dst}FW);
        # the interface test is what keeps it from duplicating a rule that
        # already names a routing interface.  Broadcasts and multicasts are
        # deliberately not recognised for this test, unlike the chain
        # decision below.
        if (
            src is not None
            and ipt_comp.fw.get_option('bridging_fw')
            and ipt_comp.complex_match(
                src,
                ipt_comp.fw,
                recognize_broadcasts=False,
                recognize_multicasts=False,
            )
        ):
            rule_iface = rule.itf[0] if rule.itf else None
            # "Every interface" is not an interface: fwbuilder asks
            # `Interface::cast(getFirstItf(rule))`, which answers null for
            # the group it puts there, so a rule that names a direction and
            # no interface has to take the same branch it always did.
            if not isinstance(rule_iface, Interface) or rule_iface.is_bridge_port():
                forward_copy = rule.clone()
                ipt_comp.set_chain(forward_copy, 'FORWARD')
                self.tmp_queue.append(forward_copy)

        if src is not None and not isinstance(src, AddressRange):
            # AddressRange is handled by SplitIfSrcMatchingAddressRange,
            # which emits a dedicated OUTPUT clone and leaves the
            # original rule free to become FORWARD.  Matching it here
            # (fwbuilder #2650) would hijack the only original copy
            # into OUTPUT and drop the FORWARD variant.
            direction = rule.direction
            matches_fw = ipt_comp.complex_match(
                src,
                ipt_comp.fw,
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
        # Not on a bridging firewall: a bridge forwards a broadcast
        # frame, so there the question is the plain one.  fwbuilder
        # writes both as `b=m= !bridging_fw`.
        bridging = bool(ipt_comp.fw.get_option('bridging_fw'))

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
            if rule.action == PolicyAction.Accept:
                # fwbuilder overrides the direction for an accepting mangle
                # rule and puts it in prerouting whatever it says
                # (PolicyCompiler_ipt::finalizeChain).  Prerouting is the
                # first mangle hook a packet crosses, so an accept there
                # covers every path through the box.
                ipt_comp.set_chain(rule, 'PREROUTING')
        else:
            src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
            dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None
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
            # not FORWARD (fwbuilder #811860).
            src_matches = (
                src is not None
                and not isinstance(src, AddressRange)
                and ipt_comp.complex_match(
                    src,
                    ipt_comp.fw,
                    recognize_broadcasts=not bridging,
                    recognize_multicasts=not bridging,
                )
            )
            dst_matches = (
                dst is not None
                and not isinstance(dst, AddressRange)
                and ipt_comp.complex_match(
                    dst,
                    ipt_comp.fw,
                    recognize_broadcasts=not bridging,
                    recognize_multicasts=not bridging,
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

        # A rule that ended up in FORWARD only because nothing claimed it
        # for INPUT or OUTPUT has no traffic to see on a firewall that does
        # not forward.  fwbuilder drops it here (PolicyCompiler_ipt.cpp,
        # bug #1040599 "unnecessary FORWARD rules"), reading "no change" as
        # "on" because the kernel setting is then whatever the host already
        # has.  The rule is only dropped when this processor chose the
        # chain: one that was pinned earlier was pinned for a reason.
        if rule.ipt_chain == 'FORWARD' and forwarding_is_off(
            self.compiler.fw, bool(ipt_comp.ipv6_policy)
        ):
            self.compiler.warning(
                rule,
                'the firewall is configured not to forward packets, so the '
                'rule has no traffic to match and is left out',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class DecideOnTarget(PolicyRuleProcessor):
    """Set the iptables target based on rule action."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if branch_closes_a_loop(self.compiler, rule):
            return True

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
        if action == PolicyAction.Branch:
            # The branch rule set compiles into a chain named after itself,
            # so branching is a jump to that chain
            # (PolicyCompiler_ipt::decideOnTarget).
            branch_name = rule.get_option('branch_name', '')
            if not branch_name:
                self.compiler.error(
                    rule, 'Branching rule refers to a rule set that does not exist'
                )
                return True
            rule.ipt_target = branch_name
            # What is left after `find_imported_rule_sets` has pulled in the
            # rule sets of other firewall objects is the firewall's own top
            # rule set: it compiles into the built-in chains, so there is no
            # chain of that name to jump to.  The print rule creates one and
            # jumps into it, iptables takes both commands, and the chain
            # stays empty: the packet returns and the rule does nothing.
            # Without a word about it the administrator has a script that
            # activates cleanly and a policy that is not the one in the
            # file.  Firewall Builder emits the same empty chain there,
            # which is why its reference output never showed it.
            if branch_name not in self.compiler.branch_chains:
                self.compiler.error(
                    rule,
                    f'Rule branches to "{branch_name}", which is not a rule '
                    'set this firewall compiles; the chain stays empty and '
                    'the rule has no effect',
                )
            return True

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

    It is only safe where the firewall object really stands for every
    address the firewall answers on.  Two cases where it does not, both
    from ``PolicyCompiler_ipt::removeFW`` (fwbuilder bug #685947):

    * The script adds virtual addresses for NAT.  Those belong to a
      translation and not to the firewall as the editor shows it, so a
      rule "to the firewall, port 22" collapsed to ``-A INPUT --dport 22``
      would permit the whole world to them as well.
    * The rule came out of a negation expansion.  The temporary chain the
      negation builds already decides on the firewall's addresses, and
      dropping the object here changes what the rule means.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        oscnf = getattr(ipt_comp, 'oscnf', None)
        if (oscnf is not None and oscnf.virtual_addresses) or rule.get_option(
            'upstream_rule_neg', False
        ):
            self.tmp_queue.append(rule)
            return True

        chain = rule.ipt_chain

        if chain == 'INPUT' or ipt_comp.is_chain_descendant_of_input(chain):
            rule.dst = [
                obj for obj in rule.dst if not self.compiler.is_firewall_or_cluster(obj)
            ]
        elif chain == 'OUTPUT' or ipt_comp.is_chain_descendant_of_output(chain):
            rule.src = [
                obj for obj in rule.src if not self.compiler.is_firewall_or_cluster(obj)
            ]

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

        # A chain that is already decided is not one to override: the
        # rule that carries the traffic class of a classifying rule is
        # pinned to postrouting, where the qdisc reads it, and a copy of
        # it in another chain is a `-j CLASSIFY` the kernel refuses
        # (`xt_CLASSIFY` registers for LOCAL_OUT and POST_ROUTING alone).
        # `decideOnChainIf{Src,Dst}FW` and `finalizeChain` ask this first;
        # the two address-range splitters are the only chain decisions in
        # either compiler that did not, in Firewall Builder as well.
        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        # Not on a bridging firewall: a bridge forwards a broadcast
        # frame, so there the question is the plain one.  fwbuilder
        # writes both as `b=m= !bridging_fw`.
        bridging = bool(ipt_comp.fw.get_option('bridging_fw'))
        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None

        if (
            rule.direction != Direction.Inbound
            and src is not None
            and isinstance(src, AddressRange)
            and ipt_comp.complex_match(src, ipt_comp.fw, not bridging, not bridging)
            # Skip the OUTPUT clone when the destination is the
            # firewall itself.  The resulting rule would match only
            # self-traffic generated by the firewall and delivered to
            # its own interface IP - in practice the kernel routes
            # that via ``lo`` and never enters OUTPUT, so the rule is
            # dead.  fwbuilder omits these atomic OUTPUT copies too.
            and not (
                dst is not None
                and ipt_comp.complex_match(dst, ipt_comp.fw, not bridging, not bridging)
            )
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

        # A chain that is already decided is not one to override: the
        # rule that carries the traffic class of a classifying rule is
        # pinned to postrouting, where the qdisc reads it, and a copy of
        # it in another chain is a `-j CLASSIFY` the kernel refuses
        # (`xt_CLASSIFY` registers for LOCAL_OUT and POST_ROUTING alone).
        # `decideOnChainIf{Src,Dst}FW` and `finalizeChain` ask this first;
        # the two address-range splitters are the only chain decisions in
        # either compiler that did not, in Firewall Builder as well.
        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        # Not on a bridging firewall: a bridge forwards a broadcast
        # frame, so there the question is the plain one.  fwbuilder
        # writes both as `b=m= !bridging_fw`.
        bridging = bool(ipt_comp.fw.get_option('bridging_fw'))
        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None

        if (
            rule.direction != Direction.Outbound
            and dst is not None
            and isinstance(dst, AddressRange)
            and ipt_comp.complex_match(dst, ipt_comp.fw, not bridging, not bridging)
            # Skip the INPUT clone when the source is the firewall
            # itself - same rationale as in
            # SplitIfSrcMatchingAddressRange: the rule would only
            # match self-traffic that never hits INPUT.
            and not (
                src is not None
                and ipt_comp.complex_match(src, ipt_comp.fw, not bridging, not bridging)
            )
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
                # A dynamic *cluster* interface is answerable after all,
                # as long as this firewall is a member of that cluster:
                # the address comes from the member's own interface, which
                # the failover group names
                # (`PolicyCompiler_ipt::checkForDynamicInterfacesOfOtherObjects`).
                if (
                    obj.is_failover_interface()
                    and obj.get_failover_group().get_interface_for_member(ipt_comp.fw)
                    is not None
                ):
                    continue
                parent_name = ''
                if obj.device:
                    parent_name = obj.device.name
                self.compiler.abort(
                    rule,
                    f"Can not build rule using dynamic interface '{obj.name}' "
                    f"of the object '{parent_name}' because its address is "
                    'unknown. The rule is left out',
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
            # The interface has no address, so there is nothing to match on.
            # Keeping the rule would widen it to every address on that side,
            # which is the opposite of naming an interface.  The C++ throws
            # here and emits nothing at all.
            self.compiler.abort(
                rule,
                'Can not use unnumbered interfaces in rules. The rule is left out',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class CheckForZeroAddr(PolicyRuleProcessor):
    """Check src/dst for zero addresses and hosts without interfaces.

    Aborts compilation if:
    - A Host object has no interfaces (no address).
    - An Address object has address 0.0.0.0 with netmask 0.0.0.0
      (equivalent to 'any', likely a mistake).
    - A Network object has non-zero address but /0 netmask (likely typo).

    The rule is kept, unlike the other checks of this kind.  Nothing is
    lost by compiling it: an object whose netmask is /0 really does mean
    "any", so the rule matches what it says and the message is about the
    address probably being a typo rather than about a condition the
    compiler cannot express.  The C++ regression output, produced in test
    mode where ``abort()`` returns instead of throwing, carries these rules
    for the same reason.

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
        """Find an address with 0.0.0.0 or netmask /0.

        The C++ guards both tests with ``!addr->isAny()``, and
        ``Address::isAny()`` (libfwbuilder Address.cpp) asks for the *id* of
        the predefined "Any" object, not for the value: the check is written
        to report exactly the object whose address and netmask are both
        zero.  fwf has no such predefined object - an element that says
        "any" is empty and never reaches here - so there is nothing to skip,
        and skipping by value made the first of the two branches dead code.

        The netmask goes through :func:`netmask_prefix_length` because
        Firewall Builder writes an IPv6 one as a bit length, which reading
        it as an address answers with a raise.
        """
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

            addr_str = obj.get_address()
            mask_str = obj.get_netmask()

            if not addr_str or not mask_str:
                continue

            try:
                ip = _ipaddress.ip_address(addr_str)
            except ValueError:
                continue

            if netmask_prefix_length(addr_str, mask_str) != 0:
                continue

            # Address 0.0.0.0 with a zero netmask -- equivalent to 'any'
            if int(ip) == 0:
                return obj

            # Network with non-zero address but /0 netmask -- likely typo
            if isinstance(obj, (Network, NetworkIPv6)):
                return obj

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
    """Abort if a MAC address is matched where the kernel cannot see one.

    The mac match registers for PREROUTING, INPUT and FORWARD only
    (netfilter ``net/netfilter/xt_mac.c``, ``.hooks``), because by the time
    a packet reaches OUTPUT or POSTROUTING it has no source MAC yet.
    iptables refuses such a rule, which stops the activation script.

    Corresponds to C++ ``PolicyCompiler_ipt::checkMACinOUTPUTChain``, which
    only guards OUTPUT; POSTROUTING is reachable through the mangle pass and
    the kernel rejects it just the same.

    A host with "MAC address matching" turned on expands to a
    ``CombinedAddress``, not to a bare ``PhysAddress``, and the print rule
    renders a ``-m mac`` for it as well, so both shapes have to be looked
    for - and in every object of the element, not only the first.

    The two shapes do not deserve the same answer, which the C++ makes and
    the port did not: a bare physAddress is nothing but a MAC, so removing
    it empties the element and the rule has to go, but a combined address
    keeps its IP half and loses only the MAC
    (``setPhysAddress("")``).  Dropping such a rule instead loses a rule
    the administrator wrote - fail-closed on an Accept, fail-open on a
    Deny - and the reference output carries it
    (``firewall.fw.orig:1059``).
    """

    #: The chains the mac match cannot be used in.
    FORBIDDEN_CHAINS = ('OUTPUT', 'POSTROUTING')

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        # The hook decides, not the name of the chain: three passes of
        # `Optimize1` run in front of this check and each of them may have
        # moved the rule into a temporary chain the built-in one jumps to.
        # The kernel refuses the match there just the same, and the
        # activation stops at that command with every policy at DROP.
        hook = next(
            (
                name
                for name in self.FORBIDDEN_CHAINS
                if ipt_comp.is_chain_descendant_of(rule.ipt_chain, name)
            ),
            '',
        )
        if not hook:
            self.tmp_queue.append(rule)
            return True

        kept, mac_name = strip_mac_objects(rule.src)
        if not mac_name:
            self.tmp_queue.append(rule)
            return True

        if not kept:
            self.compiler.abort(
                rule,
                f'Can not match a MAC address in the {hook} chain, '
                f'where the packet no longer carries one',
            )
            return True

        rule.src = kept
        self.compiler.warning(
            rule,
            f'Can not match the MAC address of "{mac_name}" in the '
            f'{hook} chain, where the packet no longer carries one; '
            f'the rule matches on the address alone',
        )
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

        # `Optimize1` may have moved the rule into a temporary chain, and a
        # chain the OUTPUT or the POSTROUTING chain jumps to is as good a
        # place for `-m owner` as the built-in one itself.
        if isinstance(srv, UserService) and not any(
            ipt_comp.is_chain_descendant_of(chain, name)
            for name in ('OUTPUT', 'POSTROUTING')
        ):
            self.compiler.warning(
                rule,
                "Iptables matches module 'owner' only in the OUTPUT and "
                'POSTROUTING chains, where the packet still has the socket '
                'that produced it',
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
            return True

        # A cluster interface with no address of this family is asked
        # about the member's own interface instead (fwbuilder ticket
        # #1172): the two stand for the same NIC, and the shared address
        # is not the only one it carries.  A cluster interface that maps
        # onto no interface of this firewall is said out loud - the rule
        # cannot be tied to it at all.
        # Not when the cluster itself is what is being compiled: its
        # interfaces then stand for themselves.
        if (
            rule_iface.is_failover_interface()
            and rule_iface.device_id != ipt_comp.fw.id
        ):
            other = rule_iface.get_failover_group().get_interface_for_member(
                ipt_comp.fw
            )
            if other is None:
                self.compiler.warning(
                    rule,
                    f'cluster interface "{rule_iface.name}" does not map onto '
                    f'any interface of "{ipt_comp.fw.name}" but is used in the '
                    f'Interface rule element, so the rule is left out',
                )
                return True
            if any(
                isinstance(addr, IPv6 if ipt_comp.ipv6_policy else IPv4)
                for addr in other.addresses
            ):
                self.tmp_queue.append(rule)
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
    the Cartesian product (Src x Dst x Srv x Interval) by factoring out
    common elements.

    The time interval counts as a fourth element, the way
    ``PolicyCompiler_ipt::optimize1`` counts it: a rule naming several
    intervals is factored into one chain reached by one jump per interval,
    and an interval that is not being factored leaves the rule that moves
    into the temporary chain.  Otherwise every level of the cascade repeats
    the same ``-m time``, and `ConvertToAtomicForIntervals` further down
    multiplies every level by the number of intervals.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        srcn = len(rule.src)
        dstn = len(rule.dst)
        srvn = len(rule.srv)
        intn = len(rule.when)
        srcany = srcn == 0
        dstany = dstn == 0
        srvany = srvn == 0
        intany = intn == 0

        # If all services are TCP or UDP, multiport can collapse them
        if srvn > 0 and not srvany:
            all_tcp_or_udp = all(
                isinstance(s, (TCPService, UDPService)) for s in rule.srv
            )
            if all_tcp_or_udp:
                srvn = 1

        # Guard: can't optimize if all elements have <=1 objects or
        # three of the four are "any".  A rule with no time restriction has
        # an "any" interval, which is why two "any" elements are enough to
        # stop there in the common case.
        if (
            (srcn <= 1 and dstn <= 1 and srvn <= 1 and intn <= 1)
            or (srcany and dstany and srvany)
            or (srcany and dstany and intany)
            or (srcany and srvany and intany)
            or (dstany and srvany and intany)
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
        if intany:
            intn = _MAXSIZE

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)

        # Pick element with fewest objects to optimize by
        if (
            not srvany
            and srvn <= dstn
            and srvn <= srcn
            and srvn <= intn
            and not rule.get_option('do_not_optimize_by_srv', False)
        ):
            self._optimize(rule, 'srv', ipt_comp)
            return True

        if not srcany and srcn <= dstn and srcn <= srvn and srcn <= intn:
            self._optimize(rule, 'src', ipt_comp)
            return True

        if not dstany and dstn <= srcn and dstn <= srvn and dstn <= intn:
            self._optimize(rule, 'dst', ipt_comp)
            return True

        if not intany and intn <= srcn and intn <= dstn and intn <= srvn:
            self._optimize(rule, 'when', ipt_comp)
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
        for attr in ('src', 'dst', 'srv', 'when'):
            items = getattr(r, attr)
            if attr != element and len(items) > 1:
                # Multi-element non-optimized: clear in jump rule
                setattr(r, attr, [])
            elif (
                attr == 'srv'
                and rule.action == PolicyAction.Reject
                and ipt_comp.is_action_on_reject_tcp_rst(rule)
            ):
                # Keep the protocol on the rule that carries the REJECT:
                # --reject-with tcp-reset needs a preceding -p tcp match.
                # Substituting "any TCP" also means there is nothing left
                # to optimize by service.
                srv = rule.srv[0] if rule.srv else None
                if isinstance(srv, TCPService):
                    rule.srv = [make_any_tcp_service()]
                    rule.set_option('do_not_optimize_by_srv', True)
                    r.set_option('do_not_optimize_by_srv', True)
                else:
                    rule.srv = []
            else:
                # Optimized element, or single/any: keep in jump, clear
                # in original
                setattr(rule, attr, [])

        # Jump rule: keep state matching, just change target.  The mark,
        # traffic class or route belongs to the rule that moves into the
        # temp chain; leaving the option on the jump rule would make
        # _print_target write `-j MARK` instead of the jump, so the temp
        # chain would never run and the mark would be set on everything the
        # jump rule matches (C++ optimizeForRuleElement clears all three).
        r.ipt_target = new_chain
        r.action = PolicyAction.Continue
        r.set_option('classification', False)
        r.set_option('routing', False)
        r.set_option('tagging', False)
        self.tmp_queue.append(r)

        # Original rule: moved to temp chain, made stateless.  The rate
        # limits stay on the jump rule alone: a packet passes both rules, so
        # a limit left on this one is a second bucket the same packet has to
        # pay, which halves the rate the editor shows (C++
        # optimizeForRuleElement clears all three here).
        rule.set_option('stateless', True)
        rule.set_option('limit_value', -1)
        rule.set_option('connlimit_value', -1)
        rule.set_option('hashlimit_value', -1)
        rule.force_state_check = False
        rule.ipt_chain = new_chain
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
    """Remove duplicate commands generated for the *same* high level rule.

    Two different rules of the rule set may well compile to the same
    iptables command and still both be needed, because the chains they set
    up around that command differ.  The rule label is therefore part of the
    dedup key, exactly as in C++ ``PolicyCompiler_ipt::optimize3``.  A
    fallback or hidden rule is never a duplicate of anything.
    """

    def __init__(self, name: str = '') -> None:
        super().__init__(name)
        self._seen: set[str] = set()

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        pr = getattr(self.compiler, 'print_rule_processor', None)
        if pr is None or rule.fallback or rule.hidden:
            self.tmp_queue.append(rule)
            return True

        # Building the command again would record every message of this
        # rule a second time and set the compiler status even on the rules
        # dropped right below.
        with self.compiler.muted():
            command = pr.policy_rule_to_string(rule)
        rule_str = f'{rule.label} {command}'
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
                    # An object that failed to resolve renders to nothing,
                    # and an element that renders to nothing is "any".  The
                    # rule has to go with the message.
                    self.compiler.abort(
                        rule,
                        f"Object '{name}' has errors: {error_msg}. "
                        f'The rule is left out',
                    )
                    return True

        self.tmp_queue.append(rule)
        return True


class CountChainUsage(PolicyRuleProcessor):
    """Count how often each chain is jumped to.

    Ports C++ ``PolicyCompiler_ipt::countChainUsage``: a chain is used
    when a rule names it as its target, so the count is keyed on
    ``ipt_target``, not on the chain the rule sits in.  The built-in
    chains and the chains of the rule sets are seeded to 1 beforehand
    (``prolog`` and ``register_rule_set_chain``), so they always count as
    used.

    The second pass propagates: a rule inside a chain nothing jumps to
    cannot run either, so its own target does not count as used.
    ``PrintRule`` then leaves the whole chain out, ``-N`` included.
    """

    def process_next(self) -> bool:
        if not self.slurp():
            return False

        ipt_comp = cast('PolicyCompiler_ipt', self.compiler)
        for rule in self.tmp_queue:
            target = rule.ipt_target
            if target:
                ipt_comp.chain_usage_counter[target] = (
                    ipt_comp.chain_usage_counter.get(target, 0) + 1
                )

        for rule in self.tmp_queue:
            if ipt_comp.chain_usage_counter.get(rule.ipt_chain, 0) == 0:
                ipt_comp.chain_usage_counter[rule.ipt_target] = 0

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

        # The same question `DropMangleTableRules` asks, so it has to be
        # asked by the same helper: a second spelling of "is this rule set
        # mangle only" is a second answer waiting to drift.
        if is_mangle_only_rule_set(ipt_comp.source_ruleset):
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

    The two halves go into different chains, so they must not ask for the
    same chain *name*.  ``getNewChainName`` builds it out of the
    direction, the rule set, the position and ``subrule_suffix``, and the
    first three are the same for both - so a rule that tags, classifies
    and logs had `Logging2` build one chain for both halves and put the
    MARK and the CLASSIFY in it.  Whichever jump rule survives then
    carries both targets, and ``-j CLASSIFY`` outside postrouting is
    refused by the kernel (``xt_CLASSIFY`` registers for
    ``NF_INET_POST_ROUTING`` and ``NF_INET_LOCAL_OUT`` alone), which stops
    the activation script with every built-in policy already at DROP.
    Firewall Builder sets no suffix here either; nothing there drops the
    postrouting half, so the shared chain is reachable from both hooks and
    the kernel refuses it just the same.

    The mark is `classify_half` and not `subrule_suffix`, because the four
    negation expansions run between here and `Logging2` and write their
    own 1/2/3 into that field: a rule that is negated *and* classified had
    both halves back in one chain.
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
                # And a chain name of its own; see the class docstring.
                rule.classify_half = True

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
                r.action = PolicyAction.Continue
                self.tmp_queue.append(r)

            # Create separate rule for classification
            if rule.get_option('classification', False):
                r = rule.clone()
                rule.set_option('classification', False)
                r.set_option('routing', False)
                r.set_option('tagging', False)
                r.ipt_chain = new_chain
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
                self.tmp_queue.append(rule)

        else:
            self.tmp_queue.append(rule)

        return True
