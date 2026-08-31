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

"""PolicyCompiler_nft: nftables filter chain compilation.

Compiles firewall policy rules into nftables filter chain rules.
Unlike iptables, nftables does not need:
- multiport optimization (native set support)
- mangle table splitting
- temp chain hacks for negation (native != support)
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._combined_address import CombinedAddress
from firewallfabrik.compiler._interval_helpers import interval_is_a_conjunction
from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    CheckForTCPEstablished,
    ConvertToAtomicForInterfaces,
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
from firewallfabrik.compiler.processors._policy import (
    KeepMangleTableRules as SharedKeepMangleTableRules,
)
from firewallfabrik.compiler.processors._service import (
    SeparateTCPWithFlags,
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
    TCPService,
    UDPService,
    UserService,
    is_run_time_address_table,
)
from firewallfabrik.platforms.linux._netfilter import (
    ANY_INTERFACE,
    branch_closes_a_loop,
    custom_service_code,
    custom_service_matches_state,
    forwarding_is_off,
    get_mac_only_address,
    interface_direction_problem,
    reset_srv_preserving_tcp,
    strip_mac_objects,
)
from firewallfabrik.platforms.nftables._identifiers import (
    is_valid_nft_identifier,
    nft_object_name,
    nft_set_reference_name,
)
from firewallfabrik.platforms.nftables._print_rule import (
    OTHER_PROTOCOLS_OPTION,
    other_protocols_for,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.compiler._os_configurator import OSConfigurator


class PolicyCompiler_nft(PolicyCompiler):
    """nftables policy compiler.

    Simpler than iptables because nftables has:
    - Native set/map support (no multiport hack)
    - Native negation (no temp chains for !)
    - User-defined tables/chains (no fixed filter/mangle split)
    - Inline logging (log + verdict in same rule)
    - inet family for dual-stack
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
        oscnf: OSConfigurator | None = None,
    ) -> None:
        super().__init__(session, fw, ipv6_policy)
        self.oscnf = oscnf

        # Which of the two tables this run fills.  nftables needs the same
        # split as iptables: a packet mark has to be set in a chain that
        # runs before the routing decision, so tagging and classification
        # rules go into a mangle table of their own.
        self.my_table: str = 'filter'

        # Set by the driver: the table this run writes into is `inet` and
        # therefore shared with the other address family's pass.  The print
        # rule then has to pin each rule to its family, because nftables
        # would otherwise let a family-neutral match apply to both.
        self.shared_inet_table: bool = False

        # Set by the mangle run when a rule saves its packet mark to the
        # connection; the driver then prepends the matching restore rules.
        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False

        # Named counter objects the accounting rules count into. The driver
        # declares them at the top of the table.
        self.counters: list[str] = []
        # Dynamic sets a per-source limit counts in, keyed by set name and
        # holding the address type of the key.
        self.dynamic_sets: dict[str, str] = {}
        # Named sets an address table is rendered as, keyed by set name and
        # holding the file the activation script reads the elements from.
        self.address_tables: dict[str, tuple[str, bool, str]] = {}
        # Meters a rate limit kept per source, destination or port counts in,
        # keyed by meter name and holding the shape the first rule gave it.
        # The driver replaces this with one dict shared by every rule set and
        # by both table passes: a meter is an object of the table, so two
        # rule sets naming the same one have to agree on its shape.
        self.meters: dict[str, tuple[str, str, str, str]] = {}

        # Per-chain rule collection for nftables output assembly.
        # Unlike iptables (where -A CHAIN is part of each command),
        # nftables rules are placed inside chain blocks, so we need
        # to track which chain each rule belongs to.
        self.chain_rules: dict[str, list[str]] = {
            'input': [],
            'forward': [],
            'output': [],
        }

        # The chain a branch rule set writes into, set by the driver.
        # Empty for the top rule set.
        self.rule_set_chain: str = ''

        # The temporary chains this run built, and the counter their names
        # are numbered from.  nftables says almost every negation with
        # `!=` and needs none of these; a negation that is a disjunction
        # is the exception, and it is expanded the way the iptables
        # compiler expands every one of them.
        self.temp_chains: set[str] = set()
        self.tmp_chain_counters: dict[str, int] = {}

        # The chains of all branch rule sets of this firewall, set by the
        # driver so a jump into one is recognised as a branch rather than a
        # jump into a chain nobody declares.
        self.branch_chains: set[str] = set()
        # The branch jumps that close a cycle, as (source, target) rule set
        # names; filled by the driver, which is the only place that sees
        # every rule set of the script.
        self.branch_loop_edges: set[tuple[str, str]] = set()

    def my_platform_name(self) -> str:
        return 'nftables'

    def can_match_inbound_in_postrouting(self, rule) -> bool:
        """nftables always can, on every kernel it otherwise needs.

        `iifname` in a postrouting chain loads and matches the device a
        routed packet came in on; the kernel has offered it since v5.5
        (commit 28f8bfd1ac94), and the constructs this compiler already
        emits need a newer kernel than that.  Verified by loading such a
        rule in a network namespace, in a filter and in a nat chain.
        """
        return True

    def register_rule_set_chain(self, chain_name: str) -> None:
        """Give this branch rule set a regular chain of its own."""
        self.rule_set_chain = chain_name
        self.chain_rules.setdefault(chain_name, [])

    def get_new_tmp_chain_name(self, rule: CompRule) -> str:
        """Name a temporary chain for *rule* and declare it.

        The name is built the way ``PolicyCompiler_ipt`` builds it, out of
        the rule set, the position and the subrule suffix, so a second
        compile of the same policy produces the same script.  A chain
        nothing declares costs nftables the whole ruleset, so the name is
        entered into ``chain_rules`` here rather than where the first rule
        happens to be printed, and into ``temp_chains`` so the print rule
        knows the jump is one of ours.
        """
        stable_key = f'{self.rule_set_key()}:{rule.position}:{rule.subrule_suffix}'
        chain_id = hashlib.md5(  # nosec B324
            stable_key.encode(),
            usedforsecurity=False,
        ).hexdigest()[:12]
        n = self.tmp_chain_counters.get(chain_id, 0)
        name = f'C{chain_id}.{n}'
        self.tmp_chain_counters[chain_id] = n + 1
        self.temp_chains.add(name)
        self.chain_rules.setdefault(name, [])
        return name

    def prolog(self) -> int:
        """Initialize compiler."""
        n = super().prolog()

        # A branch rule set runs only where a rule with the Branch action
        # jumps to it, so its rules belong in a regular chain, not in one
        # that a hook feeds.  Every chain decision downstream keeps a chain
        # that is already set, so presetting it here is all it takes
        # (fwbuilder CompilerDriver_ipt::assignRuleSetChain).
        if self.rule_set_chain:
            for rule in self.rules:
                rule.ipt_chain = self.rule_set_chain

        return n

    def compile(self) -> None:
        """Main compilation: sets up the rule processor pipeline.

        Much simpler than iptables — no mangle splitting, multiport
        optimization, or temp chain management needed.
        """
        banner = (
            f' Compiling policy ruleset {self.get_rule_set_name()} for nftables'
            f", '{self.my_table}' table"
        )
        if self.ipv6_policy:
            banner += ', IPv6'
        self.info(banner)

        super().compile()

        # Run the shared shadowing detection pass before the main pipeline,
        # exactly like iptables. It runs before negation processing so negated
        # rule elements are still flagged and correctly skipped (issue #136).
        # The mangle run sees a subset of the same rule set, so letting it
        # detect shadowing again would only repeat every warning.
        if (
            self.my_table != 'mangle'
            and self.fw.get_option('check_shading')
            and not self.single_rule_compile_mode
        ):
            self.run_shadowing_pass()

        # -- Processor pipeline --
        self.add(Begin('Begin compilation'))
        self.add(PrintTotalNumberOfRules())
        self.add(SingleRuleFilter('single rule filter'))

        self.add_rule_filter()

        self.add(DeprecateOptionRoute('deprecate option Route'))

        self.add(
            ClearTagClassifyInFilter('clear Tag and Classify options in filter table')
        )
        # Ahead of `Logging1`, the way `PolicyCompiler_ipt::compile` orders
        # the two (clearLogInMangle:4406, Logging1:4412) and the iptables
        # pipeline here does.  Behind it the global "log everything" setting
        # is cleared again in the mangle pass, and a firewall that tags or
        # classifies logs on one platform and not on the other.
        self.add(ClearLogInMangle('clear logging in rules in mangle table'))
        self.add(
            ClearActionInTagClassifyIfMangle(
                'clear action in rules with Tag and Classify in mangle'
            )
        )

        # Store original action
        self.add(StoreAction('store action'))
        self.add(Logging1('apply global log_all'))

        # Interface and direction
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
        # "Not these interfaces" is the firewall's *other* protected
        # interfaces, not every interface there is: `iifname != { ... }`
        # would also match the loopback, an interface the object tree does
        # not know and one the admin marked unprotected.  Same two steps,
        # in the same order, as the iptables pipeline and as this
        # platform's own NAT pipeline (fwbuilder
        # Compiler::fullInterfaceNegationInRE, bug #2710034).
        self.add(SingleObjectNegationItf('single object negation in Itf'))
        self.add(ItfNegation('process negation in Itf'))
        self.add(DecideOnChainForClassify('set chain for action is Classify'))

        self.add(InterfaceAndDirection('interface+dir'))
        self.add(
            SplitIfIfaceAndDirectionBoth('split interface rule with direction both')
        )

        self.add(ResolveMultiAddress('resolve compile-time MultiAddress'))

        # Check for recursive and empty groups before expansion
        self.add(RecursiveGroupsInRE('check for recursive groups in SRC', 'src'))
        self.add(RecursiveGroupsInRE('check for recursive groups in DST', 'dst'))
        self.add(RecursiveGroupsInRE('check for recursive groups in SRV', 'srv'))
        self.add(EmptyGroupsInRE('check for empty groups in SRC', 'src'))
        self.add(EmptyGroupsInRE('check for empty groups in DST', 'dst'))
        self.add(EmptyGroupsInRE('check for empty groups in SRV', 'srv'))

        # Expand groups and clean up
        self.add(ExpandGroups('expand all groups'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))
        self.add(EliminateDuplicatesInSRC('eliminate duplicates in SRC'))
        self.add(EliminateDuplicatesInDST('eliminate duplicates in DST'))
        self.add(EliminateDuplicatesInSRV('eliminate duplicates in SRV'))

        self.add(CheckForTCPEstablished('check for TCP established flag'))

        # Reject settings.  Match fwbuilder iptables order: split
        # srv=any reject into tcp-reset + generic, then fill
        # action_on_reject from global option, then split tcp-reset
        # rules with mixed tcp/non-tcp services.
        self.add(
            SplitRuleIfSrvAnyActionReject('split if srv is any and action is Reject')
        )
        self.add(FillActionOnReject('fill action_on_reject'))
        self.add(
            SplitServicesIfRejectWithTCPReset('split if action on reject is TCP reset')
        )
        self.add(FillActionOnReject('fill action_on_reject 2'))
        self.add(
            SplitServicesIfRejectWithTCPReset(
                'split if action on reject is TCP reset (pass 2)'
            )
        )

        # "Not this service" also covers every protocol the service does
        # not name, which nftables needs a second rule for.  It runs behind
        # the reject block, whose processors read the service element as
        # "any" when it is empty, and ahead of everything else, so the
        # extra rule is an ordinary rule from here on.
        self.add(AddOtherProtocolsForNegatedService('negated service: other protocols'))

        # Logging — inline in nftables, no temp chain needed
        self.add(Logging_nft('process logging'))
        self.add(SplitIfTagAndConnmark('Tag+CONNMARK combo'))
        self.add(Accounting('handle accounting rules'))

        # Negation processors
        self.add(SplitIfSrcNegAndFw('split if src negated and fw'))
        self.add(SplitIfDstNegAndFw('split if dst negated and fw'))
        self.add(NftNegation('process negation'))
        self.add(TimeNegation('process time negation'))

        # Chain assignment.  The action check runs before the rule is split
        # on "any", so an unusable action is reported once and not once per
        # copy.
        if self.my_table == 'mangle':
            self.add(CheckActionInMangleTable('check allowed actions in mangle table'))
        self.add(SplitIfSrcAny('split rule if src is any'))
        self.add(SetChainForMangle('set chain for mangle rules'))
        self.add(SetChainPreroutingForTag('chain prerouting for Tag'))
        self.add(SplitIfDstAny('split rule if dst is any'))
        self.add(SetChainPostroutingForTag('chain postrouting for Tag'))
        self.add(ProcessMultiAddressObjectsInRE('process MultiAddress in Src', 'src'))
        self.add(ProcessMultiAddressObjectsInRE('process MultiAddress in Dst', 'dst'))
        self.add(SpecialCaseAddressRangeInSrc('replace single address range in Src'))
        self.add(SpecialCaseAddressRangeInDst('replace single address range in Dst'))
        self.add(
            SplitIfSrcMatchingAddressRange('split if Src has matching address range')
        )
        self.add(
            SplitIfDstMatchingAddressRange('split if Dst has matching address range')
        )
        self.add(SplitIfSrcMatchesFw('split if src matches FW'))
        self.add(SplitIfDstMatchesFw('split if dst matches FW'))
        self.add(SpecialCaseWithFW1('split fw-to-fw rules'))
        self.add(DecideOnChainIfDstFW('decide chain if dst is fw'))
        self.add(SplitIfSrcFWNetwork('split rule if src has a net fw has interface on'))
        self.add(DecideOnChainIfSrcFW('decide chain if src is fw'))
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
        self.add(ConvertToAtomicForInterfaces('convert to atomic by interfaces'))
        self.add(
            CheckInterfaceAgainstAddressFamily(
                'check if interface matches address family'
            )
        )
        self.add(DecideOnChainIfLoopback('any-any rule on loopback'))
        self.add(FinalizeChain('assign chain'))
        self.add(SpecialCaseWithFWInDstAndOutbound('drop impossible outbound fw dst'))
        self.add(DecideOnTarget('set target'))
        self.add(CheckForRestoreMarkInOutput('check for CONNMARK restore in output'))

        # Clean up firewall object in src/dst
        self.add(RemoveFW('remove fw'))
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(ExpandLoopbackInterfaceAddress('replace loopback with address'))
        self.add(SplitIfMacAndAddressInRE('split MAC from address in Src', 'src'))
        self.add(SplitIfMacAndAddressInRE('split MAC from address in Dst', 'dst'))
        self.add(SplitIfSeveralSetsInRE('split named sets in Src', 'src'))
        self.add(SplitIfSeveralSetsInRE('split named sets in Dst', 'dst'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))

        # Address family filtering
        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))
        self.add(DropRuleWithEmptyRE('drop rules after AF filter'))

        self.add(CheckForUnnumbered('check for unnumbered interfaces'))
        self.add(CheckForDynamicInterfacesOfOtherObjects('check dynamic interfaces'))

        # Bridging firewall support
        if self.fw.get_option('bridging_fw'):
            self.add(BridgingFw('bridging firewall broadcast/multicast'))

        # Convert to atomic
        self.add(ConvertToAtomicForIntervals('convert to atomic by intervals'))
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
        self.add(
            SpecialCasesWithCustomServices('handle custom service ESTABLISHED/RELATED')
        )

        self.add(CheckForStatefulICMP6Rules('check for stateful ICMPv6 rules'))

        self.add(Optimize3('optimization 3'))
        self.add(CheckMACInOUTPUTChain('check MAC in output chain'))
        self.add(CheckUserServiceInWrongChains('check for UserService in wrong chains'))

        self.add(CheckForZeroAddr('check for zero addresses'))
        self.add(CheckForObjectsWithErrors('check for objects with errors'))
        self.add(DropRuleWithImpossibleInterface())

        # Print rule
        self.add(self.create_print_rule_processor())
        self.add(SimplePrintProgress())

        self.run_rule_processors()

        # Post-processing: merge consecutive rules that differ only in
        # source or destination address into nftables anonymous sets.
        from firewallfabrik.platforms.nftables._print_rule import (
            optimize_chain_rules,
        )

        optimize_chain_rules(self.chain_rules)

    def new_counter_name(self, rule) -> str:
        """Return the name of the counter that stands for *rule*.

        The rule set and position identify the rule the same way the
        iptables compiler names the chain it sends accounting traffic
        through.
        """
        ruleset_name = self.get_rule_set_name()
        prefix = 'RULE' if ruleset_name == 'Policy' else ruleset_name
        position = rule.position if rule.position >= 0 else 0
        name = f'{prefix}_{position}'
        suffix = rule.subrule_suffix
        if suffix:
            name += f'_{suffix}'
        return name

    def register_counter(self, name: str) -> None:
        """Remember a counter object so the driver can declare it."""
        if name not in self.counters:
            self.counters.append(name)

    def register_dynamic_set(self, name: str, addr_type: str) -> None:
        """Remember a dynamic set so the driver can declare it.

        A rule that adds elements to a set can only do so once the set is an
        object of the table (netfilter nftables doc/sets.txt), the same way
        a named counter has to exist before a rule counts into it.
        """
        self.dynamic_sets.setdefault(name, addr_type)

    def register_meter(
        self, name: str, keys: str, timeout: str, size: str, rate: str
    ) -> tuple[bool, bool]:
        """Remember a meter, and say how it compares to the one already there.

        The answer has two halves, because the two disagreements have
        different consequences.

        The shape - the type of the key, whether the elements time out and
        how many there are - has to match.  nftables refuses the whole
        ruleset over the timeout ("existing set '%s' has/lacks timeout
        flag", netfilter nftables src/evaluate.c) and answers the key by
        silently keeping the shape the first rule gave the set, which
        leaves the later rule counting something other than what it says.

        The rate is a different matter: nftables takes the ruleset, because
        the rate lives in the element rather than in the set.  It is the
        element that then decides, and the element is created by whichever
        rule sees a given key first: `nft_dynset_eval` hands back the
        existing entry and evaluates the expression stored in *it*
        (net/netfilter/nft_dynset.c, via the set's `update` op), so the
        second rule's rate never applies to a source the first one has
        already seen.  That is the same hazard the iptables side reports
        for a shared hash table, so it is reported here too - as a warning,
        since the ruleset does load.
        """
        shape = (keys, timeout, size)
        first = self.meters.setdefault(name, (*shape, rate))
        return first[:3] == shape, first[3] == rate

    def add_rule_filter(self) -> None:
        """Add the processor that selects the rules of this table.

        The filter run drops the rules the mangle run takes care of; the
        mangle compiler overrides this with the opposite filter.
        """
        self.add(DropMangleTableRules('drop rules that require the mangle table'))

    def create_print_rule_processor(self):
        """Create the nftables PrintRule processor."""
        from firewallfabrik.platforms.nftables._print_rule import PrintRule_nft

        pr = PrintRule_nft('generate nftables rules')
        pr.set_context(self)
        pr.initialize()
        self.print_rule_processor = pr
        return pr

    def get_rule_set_name(self) -> str:
        if self.source_ruleset:
            return self.source_ruleset.name
        return 'Policy'

    # -- Action helpers (mirror PolicyCompiler_ipt) --

    def get_action_on_reject(self, rule) -> str:
        return rule.get_option('action_on_reject', '') or ''

    def is_action_on_reject_tcp_rst(self, rule) -> bool:
        s = self.get_action_on_reject(rule)
        return bool(s and 'TCP ' in s)

    def reset_action_on_reject(self, rule) -> None:
        """Reset action_on_reject to a non-TCP value."""
        go = self.fw.get_option('action_on_reject') or ''
        if go and 'TCP ' in go:
            go = ''
        rule.set_option('action_on_reject', go)


# ═══════════════════════════════════════════════════════════════════
# Rule Processors
# ═══════════════════════════════════════════════════════════════════


class ConvertToAtomicForIntervals(PolicyRuleProcessor):
    """Split rules with multiple time intervals."""

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


class SpecialCaseWithFW1(PolicyRuleProcessor):
    """Split fw-to-fw rules into Inbound + Outbound.

    A negated element does not name the firewall, it names everything
    else, so such a rule is not a firewall-to-firewall rule.  The
    iptables sibling needs no such test because ``SrcNegation`` /
    ``DstNegation`` have already moved the negated objects into a
    temporary chain by the time it runs; ``NftNegation`` leaves them in
    the element and only sets a flag, so the test has to be made here.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None
        if (
            src is not None
            and dst is not None
            and not rule.src_single_object_negation
            and not rule.dst_single_object_negation
            and nft_comp.complex_match(src, nft_comp.fw)
            and nft_comp.complex_match(dst, nft_comp.fw)
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
            # A direction and no interface still has to say which of the
            # two it is; see ANY_INTERFACE.  The iptables compiler does
            # exactly the same, and a rule whose element a later processor
            # resets loses the match with it.
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

    Mirrors ``PolicyCompiler_ipt::splitRuleIfSrvAnyActionReject``.  When
    a Reject rule has no explicit ``action_on_reject`` and its service
    element is "any", emit an additional TCP-only clone with
    ``action_on_reject='TCP RST'`` so TCP connections get a reset while
    other protocols fall back to the generic reject action.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        aor = nft_comp.get_action_on_reject(rule)

        if rule.action == PolicyAction.Reject and not aor and rule.is_srv_any():
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
    """Split Reject + TCP RST rules with mixed TCP/non-TCP services.

    Mirrors ``PolicyCompiler_ipt::splitServicesIfRejectWithTCPReset``.
    When the action is Reject and ``action_on_reject`` is a TCP reset:

    - only non-TCP services: warn and clear ``action_on_reject``
    - only TCP services: pass through unchanged
    - both: split into a non-TCP clone (without TCP RST) and a TCP
      clone (keeps TCP RST)
    """

    def __init__(self, name: str = '') -> None:
        super().__init__(name)
        self._seen_rules: set[int] = set()

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if (
            rule.action != PolicyAction.Reject
            or not nft_comp.is_action_on_reject_tcp_rst(rule)
        ):
            self.tmp_queue.append(rule)
            return True

        tcp_services: list = []
        other_services: list = []
        for srv in rule.srv:
            if srv.get_protocol_name() == 'tcp':
                tcp_services.append(srv)
            else:
                other_services.append(srv)

        if not rule.srv:
            # "any" is every protocol, so it belongs with the non-TCP ones.
            # A TCP reset on such a rule is not the rule the admin wrote:
            # nftables adds the missing `meta l4proto tcp` itself (netfilter
            # nftables src/evaluate.c, the reject statement needs the
            # transport protocol), so everything that is not TCP passes,
            # and iptables refuses the same rule outright.
            other_services = [None]

        if other_services and not tcp_services:
            if rule.position not in self._seen_rules:
                self.compiler.warning(
                    rule,
                    "Rule action 'Reject' with TCP RST can be used "
                    'only with TCP services.',
                )
            nft_comp.reset_action_on_reject(rule)
            self.tmp_queue.append(rule)
            self._seen_rules.add(rule.position)
            return True

        if not other_services and tcp_services:
            self.tmp_queue.append(rule)
            return True

        r1 = rule.clone()
        r1.srv = other_services
        r1.set_option('action_on_reject', '')
        r1.subrule_suffix = '1'
        self.tmp_queue.append(r1)

        r2 = rule.clone()
        r2.srv = tcp_services
        r2.subrule_suffix = '2'
        self.tmp_queue.append(r2)

        return True


class CheckInterfaceAgainstAddressFamily(PolicyRuleProcessor):
    """Drop rules whose interface has no addresses in the active family.

    Mirrors ``PolicyCompiler_ipt::checkInterfaceAgainstAddressFamily``.
    Rules on regular (non-dynamic, non-unnumbered, non-bridge-port)
    interfaces that lack any IPv4 / IPv6 address for the compile target
    are dropped, matching fwbuilder behaviour.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        rule_iface = rule.itf[0] if rule.itf else None
        if not isinstance(rule_iface, Interface):
            self.tmp_queue.append(rule)
            return True

        if not rule_iface.is_regular():
            self.tmp_queue.append(rule)
            return True

        has_matching = False
        for addr in rule_iface.addresses:
            if nft_comp.ipv6_policy and isinstance(addr, IPv6):
                has_matching = True
                break
            if not nft_comp.ipv6_policy and isinstance(addr, IPv4):
                has_matching = True
                break

        if has_matching:
            self.tmp_queue.append(rule)
            return True

        # A cluster interface with no address of this family is asked
        # about the member's own interface instead (fwbuilder ticket
        # #1172): the two stand for the same NIC, and the shared address
        # is not the only one it carries.
        # Not when the cluster itself is what is being compiled: its
        # interfaces then stand for themselves.
        if (
            rule_iface.is_failover_interface()
            and rule_iface.device_id != nft_comp.fw.id
        ):
            other = rule_iface.get_failover_group().get_interface_for_member(
                nft_comp.fw
            )
            if other is None:
                self.compiler.warning(
                    rule,
                    f'cluster interface "{rule_iface.name}" does not map onto '
                    f'any interface of "{nft_comp.fw.name}" but is used in the '
                    f'Interface rule element, so the rule is left out',
                )
                return True
            if any(
                isinstance(addr, IPv6 if nft_comp.ipv6_policy else IPv4)
                for addr in other.addresses
            ):
                self.tmp_queue.append(rule)
        return True


class CheckUserServiceInWrongChains(PolicyRuleProcessor):
    """Warn and drop rules with UserService outside OUTPUT.

    Mirrors ``PolicyCompiler_ipt::checkUserServiceInWrongChains``.  The
    Linux ``meta skuid`` match (corresponding to iptables ``-m owner``)
    is only meaningful on locally-generated traffic, so UserService
    rules must be placed in the OUTPUT chain.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        srv = rule.srv[0] if rule.srv else None
        chain = (rule.ipt_chain or '').upper()

        # "meta skuid" reads the socket that produced the packet, which only
        # exists once the packet is on its way out; elsewhere the match
        # simply never fires (netfilter net/netfilter/nft_meta.c,
        # nft_meta_get_eval).  The iptables owner match is restricted to the
        # same two hooks, so the rule is dropped rather than shipped as one
        # that can never match.
        # Unlike iptables there is no temporary-chain hierarchy to walk here:
        # the nftables rules live in the hook chains themselves.
        if isinstance(srv, UserService) and chain not in ('OUTPUT', 'POSTROUTING'):
            self.compiler.warning(
                rule,
                "nftables matches 'meta skuid' only in the output and "
                'postrouting chains, where the packet still has the socket '
                'that produced it',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class Logging_nft(PolicyRuleProcessor):
    """Process logging for nftables.

    In nftables, logging is an inline statement that can be combined
    with a verdict, so we don't need temp chains like iptables does.
    We just mark the rule so PrintRule knows to add `log`.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_option('log', False):
            self.tmp_queue.append(rule)
            return True

        # For Continue+log, set target to LOG
        if rule.action == PolicyAction.Continue:
            # A rule asking for policy routing never gets here: it is
            # reported and left out by DeprecateOptionRoute, at the head of
            # the pipeline, for every action rather than for this one.
            if rule.get_option('tagging', False) or rule.get_option(
                'classification', False
            ):
                # A rule that also sets a mark or a traffic class carries
                # that statement plus the log message in one nft rule; the
                # standalone LOG target is for the pure log rule.
                rule.nft_log = True
            else:
                rule.ipt_target = 'LOG'
            self.tmp_queue.append(rule)
            return True

        # For other actions with log, nftables can do it in one rule:
        #   log prefix "..." accept
        # We mark the rule so PrintRule emits both log and verdict
        rule.nft_log = True
        self.tmp_queue.append(rule)
        return True


class NftNegation(PolicyRuleProcessor):
    """Convert negation flags to single_object_negation flags.

    nftables has native != support for both single and multi-object,
    so we just convert all negation flags directly — no temp chains needed.

    The interface element is *not* one of them.  It is handled far
    upstream by `SingleObjectNegationItf` and `ItfNegation`, because "not
    these interfaces" means the firewall's other protected interfaces and
    not every interface there is - `iifname != { ... }` would also match
    the loopback and whatever the object tree does not know about.

    The service element needs a second rule on top of the ``!=``, which
    :class:`AddOtherProtocolsForNegatedService` adds.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('src'):
            rule.src_single_object_negation = True
            rule.set_neg('src', False)
        if rule.get_neg('dst'):
            rule.dst_single_object_negation = True
            rule.set_neg('dst', False)
        if rule.get_neg('srv'):
            rule.srv_single_object_negation = True
            rule.set_neg('srv', False)
        self.tmp_queue.append(rule)
        return True


class TimeNegation(PolicyRuleProcessor):
    """Say "outside this window" for an interval nftables cannot invert.

    nftables inverts a single ``meta hour``, ``meta time`` or ``meta day``
    match with ``!=``, so unlike iptables most negated intervals need no
    chain and the flag simply stays on the rule for
    ``PrintRule_nft._print_time_interval`` to apply.

    An interval that names both a window of the day and a set of weekdays
    is the exception: its opposite is "outside those hours *or* on another
    day", and one nftables rule holds no disjunction.  Such a rule is
    expanded into the same three-rule shape
    ``PolicyCompiler_ipt::TimeNegation`` uses for every negated interval,
    which says the same thing by excluding the window instead of negating
    it:

    1. a jump rule carrying the original conditions into a new chain,
    2. a return rule in that chain matching the interval, so traffic
       *inside* the window leaves again without being acted on,
    3. the action rule, which everything that did not return reaches.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('when') or not rule.when:
            self.tmp_queue.append(rule)
            return True

        # Several intervals are an "or", so their negation is an "and" of
        # negations - which the atomizing split downstream would turn back
        # into an "or", one rule per interval.  Only a rule naming one
        # interval that says one thing can be inverted where it stands.
        if len(rule.when) == 1 and not interval_is_a_conjunction(
            rule.when[0].data or {}
        ):
            self.tmp_queue.append(rule)
            return True

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        rule.set_neg('when', False)
        new_chain = nft_comp.get_new_tmp_chain_name(rule)

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
        # `Logging_nft` has already run and put the log statement on the
        # rule, so clearing the option alone would still log a packet once
        # per copy.  Only the rule that carries the action logs.
        r_jump.nft_log = False
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
        r_return.ipt_target = 'RETURN'
        r_return.action = PolicyAction.Return
        r_return.set_option('classification', False)
        r_return.set_option('routing', False)
        r_return.set_option('tagging', False)
        r_return.set_option('log', False)
        r_return.nft_log = False
        r_return.set_option('stateless', True)
        r_return.set_option('limit_value', -1)
        r_return.set_option('connlimit_value', -1)
        r_return.set_option('hashlimit_value', -1)
        r_return.force_state_check = False
        self.tmp_queue.append(r_return)

        # Action rule: everything else was matched by the jump already
        r_action = rule.clone()
        r_action.subrule_suffix = '3'
        r_action.src = []
        r_action.dst = []
        # A Reject rule keeps "any TCP" so `reject with tcp reset` still
        # names a protocol, the way the iptables expansion does - one
        # reader for both platforms, and it asks by protocol name, so a
        # Custom Service that is TCP is one too.
        reset_srv_preserving_tcp(r_action)
        r_action.itf = []
        r_action.when = []
        r_action.ipt_chain = new_chain
        r_action.set_option('stateless', True)
        r_action.force_state_check = False
        r_action.final = True
        self.tmp_queue.append(r_action)

        return True


class AddOtherProtocolsForNegatedService(PolicyRuleProcessor):
    """Give a negated service the protocols it does not name.

    "Not this service" covers every packet the service does not describe,
    and a UDP packet is not TCP port 80.  iptables says exactly that: the
    rule jumps into a temporary chain, a rule matching the service returns,
    and the action follows, so a packet of any other protocol reaches the
    action (``PolicyCompiler_ipt::SrvNegation``).

    nftables writes the negation into the rule, and a port, a TCP flag or
    an ICMP type is a payload match that carries a protocol dependency with
    it: ``tcp dport != 80`` compiles to ``meta l4proto tcp`` followed by
    the port comparison (verified with ``nft --debug=netlink``), so it
    never sees a UDP packet at all.  Half the traffic the rule is written
    for is therefore missing, and on a Deny rule that is a hole.

    nftables cannot say "or" inside a rule, so the other half becomes a
    rule of its own, matching every protocol the element does not name.
    The two are disjoint - one asks for a protocol, the other asks for
    anything but - so a packet is still seen by exactly one of them.

    What is left alone, and why, is in :func:`other_protocols_for`.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)

        protocols = self._other_protocols(rule)
        if not protocols:
            return True

        other = rule.clone()
        other.srv = []
        other.set_neg('srv', False)
        other.set_option(OTHER_PROTOCOLS_OPTION, protocols)
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        if 'tcp' in protocols and nft_comp.is_action_on_reject_tcp_rst(other):
            # This rule is the one for everything that is *not* TCP, and a
            # TCP reset needs a TCP packet: nftables narrows such a rule to
            # `meta l4proto tcp` on its own (netfilter nftables
            # src/evaluate.c), which contradicts the match and leaves a rule
            # no packet can reach.  `SplitServicesIfRejectWithTCPReset`
            # answers the same question the same way for a rule that names
            # only non-TCP services.
            nft_comp.reset_action_on_reject(other)
        self.tmp_queue.append(other)
        return True

    def _other_protocols(self, rule) -> list[str]:
        """Return the protocols to exclude, or an empty list to do nothing."""
        if not rule.get_neg('srv'):
            return []
        return other_protocols_for(rule.srv, self.compiler.ipv6_policy)


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

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        fw_likes: list = []
        not_fw_likes: list = []
        for obj in rule.src:
            if nft_comp.complex_match(obj, nft_comp.fw):
                fw_likes.append(obj)
            else:
                not_fw_likes.append(obj)

        if not fw_likes:
            self.tmp_queue.append(rule)
            return True

        # Rule A: OUTPUT chain with FW objects (still negated)
        r = rule.clone()
        r.src = fw_likes
        r.ipt_chain = 'output'
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

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        fw_likes: list = []
        not_fw_likes: list = []
        for obj in rule.dst:
            if nft_comp.complex_match(obj, nft_comp.fw):
                fw_likes.append(obj)
            else:
                not_fw_likes.append(obj)

        if not fw_likes:
            self.tmp_queue.append(rule)
            return True

        # Rule A: INPUT chain with FW objects (still negated)
        r = rule.clone()
        r.dst = fw_likes
        r.ipt_chain = 'input'
        r.direction = Direction.Inbound
        self.tmp_queue.append(r)

        # Rule B: original with non-FW objects only
        rule.dst = not_fw_likes
        if not not_fw_likes:
            rule.set_neg('dst', False)
        rule.set_option('no_input_chain', True)
        self.tmp_queue.append(rule)
        return True


class SplitIfSrcAny(PolicyRuleProcessor):
    """Split rule if src is 'any' — may need INPUT and OUTPUT chains."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Check per-rule option first, then fall back to global firewall option
        afpa = assumes_fw_is_part_of_any(rule)
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('no_output_chain', False):
            self.tmp_queue.append(rule)
            return True

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # The C++ splits on `single_object_negation` too, and asks for one
        # object because that is the only shape it ever sets the flag on:
        # `SrcNegation` turns several into a temporary chain whose jump rule
        # has "any" as its source, and that half is caught by `is_src_any`
        # above.  nftables writes them all as `!=` in one rule, so the count
        # has to come out of the test - "not one of these two" contains the
        # firewall exactly as "not this one" does, and asking for a single
        # object left every such rule without its output copy
        # (PolicyCompiler_ipt::splitIfSrcAny).
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        src_neg_split = rule.src_single_object_negation and not any(
            nft_comp.complex_match(obj, nft_comp.fw) for obj in rule.src
        )
        if rule.direction != Direction.Inbound and (rule.is_src_any() or src_neg_split):
            r = rule.clone()
            r.ipt_chain = 'output'
            r.direction = Direction.Outbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstAny(PolicyRuleProcessor):
    """Split rule if dst is 'any' — may need INPUT and OUTPUT chains."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Check per-rule option first, then fall back to global firewall option
        afpa = assumes_fw_is_part_of_any(rule)
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('no_input_chain', False):
            self.tmp_queue.append(rule)
            return True

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # Same as in `SplitIfSrcAny`: the count the C++ asks for is an
        # artefact of its temporary chains, which nftables does not build.
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        dst_neg_split = rule.dst_single_object_negation and not any(
            nft_comp.complex_match(obj, nft_comp.fw) for obj in rule.dst
        )
        if rule.direction != Direction.Outbound and (
            rule.is_dst_any() or dst_neg_split
        ):
            r = rule.clone()
            r.ipt_chain = 'input'
            r.direction = Direction.Inbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcMatchingAddressRange(PolicyRuleProcessor):
    """Split rule if src has an AddressRange matching the firewall.

    Mirrors iptables' ``SplitIfSrcMatchingAddressRange``.  If src
    contains an AddressRange whose range includes a firewall interface
    address, clone the rule into the ``output`` chain so the policy
    also covers traffic the firewall sends out itself.  The original
    rule stays in place and eventually lands in ``forward``.

    Skipped when the destination already matches the firewall: the
    resulting output->fw self-loop rule would never actually match
    (kernel routes such packets via ``lo``) and fwbuilder omits it too.
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

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        # Not on a bridging firewall: a bridge forwards a broadcast
        # frame, so there the question is the plain one.  fwbuilder
        # writes both as `b=m= !bridging_fw`.
        bridging = bool(nft_comp.fw.get_option('bridging_fw'))
        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None

        if (
            rule.direction != Direction.Inbound
            and src is not None
            and isinstance(src, AddressRange)
            and nft_comp.complex_match(src, nft_comp.fw, not bridging, not bridging)
            and not (
                dst is not None
                and nft_comp.complex_match(dst, nft_comp.fw, not bridging, not bridging)
            )
        ):
            r = rule.clone()
            r.ipt_chain = 'output'
            r.direction = Direction.Outbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfDstMatchingAddressRange(PolicyRuleProcessor):
    """Split rule if dst has an AddressRange matching the firewall.

    See :class:`SplitIfSrcMatchingAddressRange`; this is the
    destination-side counterpart.  Creates an ``input`` clone so
    firewall-directed traffic covered by the range is not missed.
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

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        # Not on a bridging firewall: a bridge forwards a broadcast
        # frame, so there the question is the plain one.  fwbuilder
        # writes both as `b=m= !bridging_fw`.
        bridging = bool(nft_comp.fw.get_option('bridging_fw'))
        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None

        if (
            rule.direction != Direction.Outbound
            and dst is not None
            and isinstance(dst, AddressRange)
            and nft_comp.complex_match(dst, nft_comp.fw, not bridging, not bridging)
            and not (
                src is not None
                and nft_comp.complex_match(src, nft_comp.fw, not bridging, not bridging)
            )
        ):
            r = rule.clone()
            r.ipt_chain = 'input'
            r.direction = Direction.Inbound
            self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcMatchesFw(PolicyRuleProcessor):
    """Split rule if src contains the firewall object.

    Mirrors C++ ``Compiler::splitIfRuleElementMatchesFW``: iterate src
    objects, splitting each firewall-matching object into its own
    clone, but stop once only one element remains in the original
    src (``nre > 1`` guard).  Without that guard an AddressRange
    overlapping a firewall interface IP would be pulled out together
    with the firewall object, leaving the original rule with an empty
    src.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if len(rule.src) <= 1:
            self.tmp_queue.append(rule)
            return True

        remaining = list(rule.src)
        extracted = []
        for obj in list(remaining):
            if len(remaining) <= 1:
                break
            if nft_comp.complex_match(obj, nft_comp.fw):
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

    See :class:`SplitIfSrcMatchesFw` for the rationale behind the
    ``len(remaining) > 1`` guard.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if len(rule.dst) <= 1:
            self.tmp_queue.append(rule)
            return True

        remaining = list(rule.dst)
        extracted = []
        for obj in list(remaining):
            if len(remaining) <= 1:
                break
            if nft_comp.complex_match(obj, nft_comp.fw):
                extracted.append(obj)
                remaining.remove(obj)

        for obj in extracted:
            r = rule.clone()
            r.dst = [obj]
            self.tmp_queue.append(r)

        rule.dst = remaining
        self.tmp_queue.append(rule)
        return True


class DecideOnChainIfDstFW(PolicyRuleProcessor):
    """Set chain to input if dst matches the firewall."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None
        # A bridging firewall sees the traffic to its own addresses in the
        # forward chain as well, whenever it arrives over a bridged path,
        # and a rule that is not tied to a routing interface cannot tell
        # the two apart, so both copies are emitted (fwbuilder bugs
        # #811860, #934949 and #1231 in
        # PolicyCompiler_ipt::decideOnChainIf{Src,Dst}FW).  Broadcasts and
        # multicasts are deliberately not recognised for this test, unlike
        # the chain decision below.
        if (
            dst is not None
            and nft_comp.fw.get_option('bridging_fw')
            and nft_comp.complex_match(
                dst,
                nft_comp.fw,
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
                forward_copy.ipt_chain = 'forward'
                self.tmp_queue.append(forward_copy)

        if dst is not None and not isinstance(dst, AddressRange):
            # AddressRange handling is delegated to
            # SplitIfDstMatchingAddressRange so the original rule can
            # still become FORWARD.  Hijacking it into INPUT here
            # would drop the FORWARD variant (fwbuilder #2650).
            #
            # Broadcast (255.255.255.255) and multicast (224.0.0.0/4,
            # ff00::/8) destinations must count as "matches fw" so
            # Inbound rules targeting them land in input rather than
            # forward (fwbuilder #811860).
            direction = rule.direction
            matches_fw = nft_comp.complex_match(
                dst,
                nft_comp.fw,
                recognize_broadcasts=True,
                recognize_multicasts=True,
            ) or dst_is_a_cluster_this_firewall_is_in(dst, nft_comp.fw)

            if direction == Direction.Inbound:
                if matches_fw:
                    rule.ipt_chain = 'input'
            elif direction == Direction.Both and matches_fw:
                rule.ipt_chain = 'input'
                rule.direction = Direction.Inbound

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcFWNetwork(PolicyRuleProcessor):
    """Split rule if src contains a network the FW has an interface on.

    Gated on ``firewall_is_part_of_any_and_networks`` (rule then fw
    option), plus ``no_output_chain`` (rule) and ``bridging_fw`` (fw) —
    matching fwbuilder ``PolicyCompiler_ipt::splitIfSrcFWNetwork``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if rule.ipt_chain or rule.is_src_any():
            self.tmp_queue.append(rule)
            return True

        if nft_comp.fw.get_option('bridging_fw'):
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
                    and nft_comp.find_address_for(obj, nft_comp.fw) is not None
                ):
                    has_match = True
                    break

            if has_match:
                r = rule.clone()
                r.ipt_chain = 'output'
                r.direction = Direction.Outbound
                self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class DecideOnChainIfSrcFW(PolicyRuleProcessor):
    """Set chain to output if src contains the firewall."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        # See :class:`DecideOnChainIfDstFW` for why a bridging firewall
        # gets a forward copy as well.
        if (
            src is not None
            and nft_comp.fw.get_option('bridging_fw')
            and nft_comp.complex_match(
                src,
                nft_comp.fw,
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
                forward_copy.ipt_chain = 'forward'
                self.tmp_queue.append(forward_copy)

        if src is not None and not isinstance(src, AddressRange):
            # See :class:`DecideOnChainIfDstFW` for the AddressRange
            # exclusion rationale (fwbuilder #2650) and the broadcast /
            # multicast recognition (#811860).
            direction = rule.direction
            matches_fw = nft_comp.complex_match(
                src,
                nft_comp.fw,
                recognize_broadcasts=True,
                recognize_multicasts=True,
            )

            if direction == Direction.Outbound:
                if matches_fw:
                    rule.ipt_chain = 'output'
            elif direction == Direction.Both and matches_fw:
                rule.ipt_chain = 'output'
                rule.direction = Direction.Outbound

        self.tmp_queue.append(rule)
        return True


class SplitIfDstFWNetwork(PolicyRuleProcessor):
    """Split rule if dst contains a network the FW has an interface on.

    Gated on the same options as :class:`SplitIfSrcFWNetwork`
    (``firewall_is_part_of_any_and_networks``, ``no_input_chain``,
    ``bridging_fw``), matching fwbuilder
    ``PolicyCompiler_ipt::splitIfDstFWNetwork``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if rule.ipt_chain or rule.is_dst_any():
            self.tmp_queue.append(rule)
            return True

        if nft_comp.fw.get_option('bridging_fw'):
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
                    and nft_comp.find_address_for(obj, nft_comp.fw) is not None
                ):
                    has_match = True
                    break

            if has_match:
                r = rule.clone()
                r.ipt_chain = 'input'
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

    A negated element does not name the firewall either, for the reason
    spelled out in :class:`SpecialCaseWithFW1`.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        src_obj = rule.src[0] if rule.src else None
        dst_obj = rule.dst[0] if rule.dst else None

        if (
            src_obj is not None
            and dst_obj is not None
            and not rule.src_single_object_negation
            and not rule.dst_single_object_negation
            and isinstance(src_obj, Firewall)
            and src_obj.id == nft_comp.fw.id
            and isinstance(dst_obj, Firewall)
            and dst_obj.id == nft_comp.fw.id
        ):
            all_addrs = []
            for iface in nft_comp.fw.interfaces:
                if iface.is_unnumbered() or iface.is_bridge_port():
                    continue
                for addr in iface.addresses:
                    if (nft_comp.ipv6_policy and isinstance(addr, IPv6)) or (
                        not nft_comp.ipv6_policy and isinstance(addr, IPv4)
                    ):
                        all_addrs.append(addr)

            rule.src = list(all_addrs)
            rule.dst = list(all_addrs)

        self.tmp_queue.append(rule)
        return True


class DecideOnChainIfLoopback(PolicyRuleProcessor):
    """Assign input/output chain for any-any rules on loopback interface."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

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
                    rule.ipt_chain = 'input'
                elif direction == Direction.Outbound:
                    rule.ipt_chain = 'output'
                elif direction == Direction.Both:
                    r = rule.clone()
                    r.ipt_chain = 'output'
                    r.direction = Direction.Outbound
                    self.tmp_queue.append(r)

                    rule.ipt_chain = 'input'
                    rule.direction = Direction.Inbound

        self.tmp_queue.append(rule)
        return True


class FinalizeChain(PolicyRuleProcessor):
    """Finalize chain assignment: input/output/forward."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # Default to forward
        rule.ipt_chain = 'forward'

        src = self.compiler.correct_for_cluster(rule.src[0]) if rule.src else None
        dst = self.compiler.correct_for_cluster(rule.dst[0]) if rule.dst else None
        direction = rule.direction
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        # Not on a bridging firewall: a bridge forwards a broadcast
        # frame, so there the question is the plain one.  fwbuilder
        # writes both as `b=m= !bridging_fw`.
        bridging = bool(nft_comp.fw.get_option('bridging_fw'))

        if nft_comp.my_table == 'mangle':
            # The mangle chains sit in front of the routing decision, so a
            # rule that was not pinned to a chain earlier follows its
            # direction: inbound traffic is seen in prerouting, outbound in
            # postrouting (fwbuilder PolicyCompiler_ipt::finalizeChain).
            if direction == Direction.Inbound:
                rule.ipt_chain = 'prerouting'
            elif direction == Direction.Outbound:
                rule.ipt_chain = 'postrouting'
            if rule.action == PolicyAction.Accept:
                # fwbuilder overrides the direction for an accepting mangle
                # rule and puts it in prerouting whatever it says.
                # Prerouting is the first mangle hook a packet crosses, so
                # an accept there covers every path through the box.
                rule.ipt_chain = 'prerouting'
            self.tmp_queue.append(rule)
            return True

        # Exclude AddressRange from chain hijacking - same reasoning
        # as in DecideOnChainIfSrcFW / DecideOnChainIfDstFW
        # (fwbuilder #2650).  The dedicated split processor emits the
        # INPUT or OUTPUT clone; leave the original free for FORWARD.
        #
        # Recognise broadcast / multicast destinations as matching the
        # firewall so e.g. DHCPv6 link-local -> ff00::/8 with
        # direction=Inbound ends up in ``input`` rather than
        # ``forward`` (fwbuilder #811860).
        src_matches = (
            src is not None
            and not isinstance(src, AddressRange)
            and nft_comp.complex_match(
                src,
                nft_comp.fw,
                recognize_broadcasts=not bridging,
                recognize_multicasts=not bridging,
            )
        )
        dst_matches = (
            dst is not None
            and not isinstance(dst, AddressRange)
            and nft_comp.complex_match(
                dst,
                nft_comp.fw,
                recognize_broadcasts=not bridging,
                recognize_multicasts=not bridging,
            )
        )

        if direction == Direction.Inbound:
            if dst_matches:
                rule.ipt_chain = 'input'
        elif direction == Direction.Outbound:
            if src_matches:
                rule.ipt_chain = 'output'
        else:
            if dst_matches:
                rule.ipt_chain = 'input'
            elif src_matches:
                rule.ipt_chain = 'output'

        # A rule that ended up in the forward chain only because nothing
        # claimed it for input or output has no traffic to see on a firewall
        # that does not forward.  Same reading as the iptables compiler
        # (fwbuilder PolicyCompiler_ipt::finalizeChain, bug #1040599): only
        # an explicit "off" counts, "no change" leaves the kernel setting
        # alone and is read as forwarding.
        if rule.ipt_chain == 'forward' and forwarding_is_off(
            nft_comp.fw, bool(nft_comp.ipv6_policy)
        ):
            self.compiler.warning(
                rule,
                'the firewall is configured not to forward packets, so the '
                'rule has no traffic to match and is left out',
            )
            return True

        self.tmp_queue.append(rule)
        return True


def _names_a_port(srv) -> bool:
    """Return whether a TCP/UDP service restricts the ports at all.

    All four bounds at zero is how "All TCP" and "All UDP" are stored; the
    iptables ``SeparatePortRanges`` reads that as the full range 0-65535.
    """
    return any(
        (
            srv.src_range_start or 0,
            srv.src_range_end or 0,
            srv.dst_range_start or 0,
            srv.dst_range_end or 0,
        )
    )


class DropMangleTableRules(PolicyRuleProcessor):
    """Drop the rules the mangle run takes care of.

    A rule that only tags, classifies or routes carries no verdict, so it
    has nothing to say in the filter table.  Every other rule stays: its
    verdict belongs here and the mangle run contributes the mark.

    Corresponds to C++ ``PolicyCompiler_ipt::dropMangleTableRules``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if is_mangle_only_rule_set(self.compiler.source_ruleset):
            return True

        # A branch into a mangle-only rule set has nothing to jump to here:
        # that rule set's chain lives in the mangle table.  Left in, the
        # jump goes into an empty chain of the same name in this table and
        # the branch does nothing at all.
        if branches_into_mangle_only(rule, self.compiler):
            return True

        if (
            rule.action == PolicyAction.Continue
            and not rule.get_option('log', False)
            and (
                rule.get_option('tagging', False)
                or rule.get_option('routing', False)
                or rule.get_option('classification', False)
            )
        ):
            return True

        self.tmp_queue.append(rule)
        return True


class KeepMangleTableRules(SharedKeepMangleTableRules):
    """Keep only the rules that set a mark or a traffic class.

    nftables spells its built-in chains in lower case.
    """

    PREROUTING = 'prerouting'
    POSTROUTING = 'postrouting'
    FORWARD = 'forward'


class ClearTagClassifyInFilter(PolicyRuleProcessor):
    """Drop the mangle-only options from a rule compiled for filter.

    Corresponds to C++ ``PolicyCompiler_ipt::clearTagClassifyInFilter``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if cast('PolicyCompiler_nft', self.compiler).my_table != 'mangle':
            rule.set_option('classification', False)
            rule.set_option('routing', False)
            rule.set_option('tagging', False)

        self.tmp_queue.append(rule)
        return True


class ClearActionInTagClassifyIfMangle(PolicyRuleProcessor):
    """Let a tagging or classifying rule fall through in the mangle table.

    ``meta mark set`` and ``meta priority set`` are statements, not
    verdicts; a verdict on the same rule would end the traversal before the
    filter chains see the packet.

    Corresponds to C++ ``PolicyCompiler_ipt::clearActionInTagClassifyIfMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if cast('PolicyCompiler_nft', self.compiler).my_table == 'mangle' and (
            rule.get_option('tagging', False)
            or rule.get_option('classification', False)
        ):
            rule.action = PolicyAction.Continue

        self.tmp_queue.append(rule)
        return True


class ClearLogInMangle(PolicyRuleProcessor):
    """Log a rule once, in the filter table.

    A rule that tags and filters is compiled into both tables; without this
    the packet would be logged twice.  A mangle-only rule set has no filter
    half, so its logging stays.

    Corresponds to C++ ``PolicyCompiler_ipt::clearLogInMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if cast(
            'PolicyCompiler_nft', self.compiler
        ).my_table == 'mangle' and not is_mangle_only_rule_set(
            self.compiler.source_ruleset
        ):
            rule.set_option('log', False)

        self.tmp_queue.append(rule)
        return True


class SplitIfTagAndConnmark(PolicyRuleProcessor):
    """Add the rule that saves a packet mark to its connection.

    Corresponds to C++ ``PolicyCompiler_ipt::splitIfTagAndConnmark``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.get_option('tagging', False) and rule.get_option(
            'ipt_mark_connections', False
        ):
            save_rule = rule.clone()
            save_rule.ipt_target = 'CONNMARK'
            save_rule.action = PolicyAction.Continue
            save_rule.set_option('classification', False)
            save_rule.set_option('routing', False)
            save_rule.set_option('tagging', False)
            save_rule.set_option('log', False)
            save_rule.set_option('CONNMARK_arg', '--save-mark')
            self.tmp_queue.append(save_rule)

            cast('PolicyCompiler_nft', self.compiler).have_connmark = True

        return True


class CheckForRestoreMarkInOutput(PolicyRuleProcessor):
    """Note that the output chain needs the mark restored from the connection.

    Corresponds to C++ ``PolicyCompiler_ipt::checkForRestoreMarkInOutput``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if (
            (
                rule.get_option('tagging', False)
                or rule.originated_from_a_rule_with_tagging
            )
            and rule.get_option('ipt_mark_connections', False)
            and rule.ipt_chain == 'output'
        ):
            cast('PolicyCompiler_nft', self.compiler).have_connmark_in_output = True

        self.tmp_queue.append(rule)
        return True


class CheckActionInMangleTable(PolicyRuleProcessor):
    """Refuse a Reject rule in the mangle table.

    Corresponds to C++ ``PolicyCompiler_ipt::checkActionInMangleTable``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.action == PolicyAction.Reject:
            self.compiler.abort(rule, 'Action Reject is not allowed in mangle table')
            return True

        self.tmp_queue.append(rule)
        return True


class SetChainForMangle(PolicyRuleProcessor):
    """Assign the mangle chain that matches the rule's direction.

    Corresponds to C++ ``PolicyCompiler_ipt::setChainForMangle``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if nft_comp.my_table == 'mangle' and not rule.ipt_chain:
            if rule.direction == Direction.Inbound:
                rule.ipt_chain = 'prerouting'
            elif rule.direction == Direction.Outbound:
                rule.ipt_chain = 'postrouting'

            src = rule.src[0] if rule.src else None
            if (
                rule.direction != Direction.Inbound
                and not rule.is_src_any()
                and src is not None
                and nft_comp.complex_match(src, nft_comp.fw)
            ):
                rule.ipt_chain = 'output'

        self.tmp_queue.append(rule)
        return True


class SetChainPreroutingForTag(PolicyRuleProcessor):
    """Tag inbound traffic in prerouting, before the routing decision.

    Corresponds to C++ ``PolicyCompiler_ipt::setChainPreroutingForTag``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if (
            (
                rule.get_option('tagging', False)
                or rule.originated_from_a_rule_with_tagging
            )
            and not rule.ipt_chain
            and rule.direction in (Direction.Both, Direction.Inbound)
            and rule.is_itf_any()
        ):
            rule.ipt_chain = 'prerouting'

        self.tmp_queue.append(rule)
        return True


class SetChainPostroutingForTag(PolicyRuleProcessor):
    """Tag outbound traffic in postrouting.

    Corresponds to C++ ``PolicyCompiler_ipt::setChainPostroutingForTag``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if (
            (
                rule.get_option('tagging', False)
                or rule.originated_from_a_rule_with_tagging
            )
            and not rule.ipt_chain
            and rule.direction in (Direction.Both, Direction.Outbound)
            and rule.is_itf_any()
        ):
            rule.ipt_chain = 'postrouting'

        self.tmp_queue.append(rule)
        return True


class DecideOnChainForClassify(PolicyRuleProcessor):
    """Set the traffic class in postrouting, where the qdisc reads it.

    A rule that both tags and classifies is split, because the mark wants
    prerouting and the class wants postrouting.

    Corresponds to C++ ``PolicyCompiler_ipt::decideOnChainForClassify``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_option('classification', False) or rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('tagging', False):
            tag_rule = rule.clone()
            tag_rule.set_option('classification', False)
            tag_rule.set_option('routing', False)
            tag_rule.action = PolicyAction.Continue
            self.tmp_queue.append(tag_rule)

            rule.set_option('tagging', False)

        rule.ipt_chain = 'postrouting'
        self.tmp_queue.append(rule)
        return True


class DecideOnTarget(PolicyRuleProcessor):
    """Set the nftables verdict based on rule action."""

    def _custom_text_is_for_nftables(self) -> bool:
        """Was the custom statement of a rule written for this platform?"""
        return self.compiler.fw.platform == 'nftables'

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
            # The branch rule set compiles into a regular chain named after
            # itself, so branching is a jump to that chain
            # (PolicyCompiler_ipt::decideOnTarget).
            branch_name = rule.get_option('branch_name', '')
            if branch_name:
                # The chain carries the sanitised name, so the jump has to
                # name it the same way; the raw name would not be found in
                # `branch_chains` and the rule would be reported as pointing
                # at a rule set that cannot be jumped to.
                rule.ipt_target = nft_object_name(branch_name)
            else:
                self.compiler.error(
                    rule, 'Branching rule refers to a rule set that does not exist'
                )
            return True

        target = target_map.get(action) if isinstance(action, PolicyAction) else None
        if target == '.CUSTOM' and not self._custom_text_is_for_nftables():
            # A rule carries its custom statement as one string, with no
            # platform beside it, so the firewall's own platform says what
            # the administrator wrote it in - the way a Custom Service says
            # it per platform.  A firewall that names another one carries
            # text nftables cannot parse, and nft refuses the whole ruleset
            # over it rather than the rule.
            self.compiler.error(
                rule,
                'Custom action holds a command written for '
                f'"{self.compiler.fw.platform or "another platform"}"; set the '
                "firewall's platform to nftables and write the statement in "
                'nftables syntax. The rule is left out',
            )
            # Leaving `ipt_target` unset is what leaves the rule out: the
            # print rule finds no verdict for the Custom action and answers
            # None, the way it does for Modify, Scrub and Skip.
        elif target is not None:
            rule.ipt_target = target
        else:
            action_name = action.name if action else str(action)
            not_yet = {
                PolicyAction.Branch,
                PolicyAction.Modify,
            }
            if rule.action in not_yet:
                self.compiler.error(
                    rule,
                    f'{action_name} action not yet supported by nftables compiler',
                )
            else:
                self.compiler.error(
                    rule, f'{action_name} action not supported in nftables'
                )

        return True


class RemoveFW(PolicyRuleProcessor):
    """Remove firewall object from src/dst after chain decision.

    When dst/src is negated, we must keep the fw addresses so that
    ``daddr != { addr1, addr2 }`` / ``saddr != { ... }`` is emitted.

    And it is only safe at all where the firewall object stands for every
    address the firewall answers on.  A script that adds virtual addresses
    for NAT breaks that: those belong to a translation, not to the firewall
    as the editor shows it, so a rule "to the firewall, port 22" collapsed
    to a rule with no destination would permit the whole world to them too
    (``PolicyCompiler_ipt::removeFW``, fwbuilder bug #685947).
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        oscnf = getattr(nft_comp, 'oscnf', None)
        if oscnf is not None and oscnf.virtual_addresses:
            self.tmp_queue.append(rule)
            return True

        chain = rule.ipt_chain

        if chain == 'input' and not rule.dst_single_object_negation:
            rule.dst = [
                obj for obj in rule.dst if not self.compiler.is_firewall_or_cluster(obj)
            ]
        elif chain == 'output' and not rule.src_single_object_negation:
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


class Optimize3(PolicyRuleProcessor):
    """Remove duplicate commands generated for the *same* high level rule.

    Two different rules of the rule set may well compile to the same
    nftables rule and still both be needed, so the rule label is part of
    the dedup key (C++ ``PolicyCompiler_ipt::optimize3`` does the same).
    Unlike iptables, an nftables rule does not name its chain, so the chain
    goes into the key as well.  A fallback or hidden rule is never a
    duplicate of anything.
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

        chain = rule.ipt_chain or ''
        # Building the command again would record every message of this
        # rule a second time and set the compiler status even on the rules
        # dropped right below.
        with self.compiler.muted():
            command = pr.policy_rule_to_string(rule)
        rule_str = f'{rule.label} {chain}:{command}'
        if rule_str in self._seen:
            return True  # duplicate, drop

        self._seen.add(rule_str)
        self.tmp_queue.append(rule)
        return True


class GroupServicesByProtocol(PolicyRuleProcessor):
    """Split rule when services belong to different protocols.

    Special case: if only TCP (proto 6) and UDP (proto 17) groups
    exist with identical port sets, merge them into a single rule
    using ``meta l4proto { tcp, udp } th dport ...`` syntax.

    Within one protocol the rule is split further, because a single nft
    rule can only carry one destination port set: services that differ in
    anything else, and every service that is not TCP or UDP, need a rule of
    their own.  This is what the iptables compiler does in
    ``PrepareForMultiport``.
    """

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

        if len(groups) > 1 and self._can_merge_tcp_udp(groups):
            rule.merged_tcp_udp = True
            self.tmp_queue.append(rule)
            return True

        chunks = [
            chunk
            for _proto, srvs in sorted(groups.items())
            for chunk in self._printable_chunks(srvs)
        ]

        if len(chunks) == 1:
            # Everything fits into one rule, keep the rule as it is.
            self.tmp_queue.append(rule)
            return True

        for chunk in chunks:
            r = rule.clone()
            r.srv = chunk
            self.tmp_queue.append(r)

        return True

    @staticmethod
    def _printable_chunks(srvs: list) -> list[list]:
        """Split a same-protocol service list into per-rule chunks.

        The print rule renders several TCP/UDP services as one destination
        port set, which only describes the services correctly when they
        agree on the source port.  Any other service type carries its own
        match (ICMP type, IP options, custom code, mark, uid) that cannot be
        expressed as a set, so it gets a rule of its own.

        A service that names no port at all ("All TCP") describes every
        port, which no member of a port set can say.  Merged into a set it
        simply disappears, and on a Deny rule that means the traffic it was
        written to stop passes.  It gets a rule of its own, where the print
        rule falls back to the bare ``meta l4proto`` match - the same split
        the iptables ``SeparatePortRanges`` performs, which reads all-zero
        bounds as the full range.
        """
        if all(isinstance(s, (TCPService, UDPService)) for s in srvs):
            any_port = [s for s in srvs if not _names_a_port(s)]
            with_port = [s for s in srvs if _names_a_port(s)]
            by_src_port: dict[tuple[int, int], list] = {}
            for srv in with_port:
                key = (srv.src_range_start or 0, srv.src_range_end or 0)
                by_src_port.setdefault(key, []).append(srv)
            chunks = [chunk for _key, chunk in sorted(by_src_port.items())]
            return [[srv] for srv in any_port] + chunks
        return [[srv] for srv in srvs]

    @staticmethod
    def _can_merge_tcp_udp(groups: dict[int, list]) -> bool:
        """Check whether TCP and UDP describe the same ports and fit one rule.

        The source and destination ports have to be compared as **pairs**.
        Comparing the two sets on their own says yes to
        ``{sport A, dport 80}`` next to ``{sport B, dport 25}``, and the
        merged rule then reads ``th sport { A, B } th dport { 80, 25 }`` -
        the cross product, which lets through what only one of the two
        services allowed and blocks what neither did.

        The merged form also carries exactly one destination port set, so
        the services have to fit into a single printable chunk; otherwise
        the split the non-merged path performs would be skipped.
        """
        if set(groups.keys()) != {6, 17}:
            return False

        tcp_srvs = groups[6]
        udp_srvs = groups[17]

        def port_pairs(srvs: list) -> set[tuple[int, int, int, int]]:
            return {
                (
                    s.src_range_start or 0,
                    s.src_range_end or 0,
                    s.dst_range_start or 0,
                    s.dst_range_end or 0,
                )
                for s in srvs
            }

        if port_pairs(tcp_srvs) != port_pairs(udp_srvs):
            return False

        chunks = GroupServicesByProtocol._printable_chunks
        return len(chunks(tcp_srvs)) == 1 and len(chunks(udp_srvs)) == 1


class CheckForDynamicInterfacesOfOtherObjects(PolicyRuleProcessor):
    """Leave out a rule naming a dynamic interface of another object.

    A dynamic interface has no address until the firewall runs, and the
    generated script can only ask the host it runs on.  So an interface of
    another object cannot be resolved at all: nftables renders it as a
    named set whose loader reads the *local* interface of that name, which
    turns "accept from the other cluster member" into "accept from myself".

    The rule therefore goes, the way the iptables policy pipeline has
    always dropped it (``PolicyCompiler_ipt::checkForDynamicInterfacesOfOtherObjects``,
    whose C++ abort() throws).  Reporting and compiling it anyway put a
    rule into the ruleset that matches something else than it says.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        fw = self.compiler.fw
        for slot in ('src', 'dst'):
            for obj in getattr(rule, slot):
                if not isinstance(obj, Interface) or not obj.is_dynamic():
                    continue
                if any(iface.id == obj.id for iface in fw.interfaces):
                    continue
                # A dynamic *cluster* interface is answerable after all, as
                # long as this firewall is a member of that cluster: the
                # address comes from the member's own interface, which the
                # failover group names.  The iptables half has had this
                # since the cluster work landed
                # (`PolicyCompiler_ipt::checkForDynamicInterfacesOfOtherObjects`).
                if (
                    obj.is_failover_interface()
                    and obj.get_failover_group().get_interface_for_member(fw)
                    is not None
                ):
                    continue
                # `device` is the host or firewall the interface belongs to;
                # the iptables half names it the same way.  Asking for a
                # `parent` or a `parent_name` answered "unknown" for every
                # interface there is.
                device = getattr(obj, 'device', None)
                parent_name = getattr(device, 'name', '') or 'another object'
                self.compiler.abort(
                    rule,
                    f"Can not build rule using dynamic interface '{obj.name}' "
                    f"of the object '{parent_name}' because its address is "
                    'unknown. The rule is left out',
                )
                return True
        self.tmp_queue.append(rule)
        return True


class CheckForObjectsWithErrors(PolicyRuleProcessor):
    """Check for objects marked with compilation errors."""

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


class CheckForStatefulICMP6Rules(PolicyRuleProcessor):
    """Force ICMPv6 rules to be stateless."""

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
                    rule, 'Making rule stateless because it matches ICMPv6'
                )
                rule.set_option('stateless', True)
        self.tmp_queue.append(rule)
        return True


class CheckForUnnumbered(PolicyRuleProcessor):
    """Check for unnumbered interfaces in src/dst."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        for slot in ('src', 'dst'):
            for obj in getattr(rule, slot):
                if isinstance(obj, Interface) and (
                    obj.is_unnumbered() or obj.is_bridge_port()
                ):
                    self.compiler.abort(
                        rule, 'Can not use unnumbered interfaces in rules.'
                    )
        self.tmp_queue.append(rule)
        return True


class CheckForZeroAddr(PolicyRuleProcessor):
    """Check for zero addresses and hosts without interfaces.

    A /0 netmask is detected family-independently: ``int(netmask) == 0``
    catches both the IPv4 literal ``0.0.0.0`` and the IPv6 literal ``::``.
    """

    @staticmethod
    def _is_zero(value: str) -> bool:
        """Return True if an address/netmask string is numerically zero (any family)."""
        if not value:
            return False
        import ipaddress as _ipa

        # Numeric zero check, not a socket bind; detects the 'any' address/mask.
        try:
            return int(_ipa.ip_address(value)) == 0  # nosec B104
        except ValueError:
            return False

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        for slot in ('src', 'dst'):
            for obj in getattr(rule, slot):
                if isinstance(obj, Host) and not obj.interfaces:
                    self.compiler.abort(rule, f"Object '{obj.name}' has no interfaces")
                if isinstance(obj, Address):
                    addr_zero = self._is_zero(obj.get_address())
                    mask_zero = self._is_zero(obj.get_netmask())
                    if addr_zero and mask_zero:
                        self.compiler.abort(
                            rule,
                            f"Object '{obj.name}' has address 0.0.0.0/0.0.0.0",
                        )
                    if (
                        isinstance(obj, (Network, NetworkIPv6))
                        and obj.get_address()
                        and not addr_zero
                        and mask_zero
                    ):
                        self.compiler.abort(
                            rule,
                            f"Object '{obj.name}' has netmask 0.0.0.0"
                            f" (equivalent to 'any')",
                        )
        self.tmp_queue.append(rule)
        return True


class ExpandLoopbackInterfaceAddress(PolicyRuleProcessor):
    """Replace loopback interface objects with their actual addresses."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        for slot in ('src', 'dst'):
            elements = getattr(rule, slot)
            if not elements:
                continue
            new_elements = []
            changed = False
            for obj in elements:
                if isinstance(obj, Interface) and obj.is_loopback():
                    if not obj.addresses:
                        # Address-less loopback used in a rule is a
                        # misconfiguration; abort instead of silently
                        # dropping the rule (parity with iptables).
                        self.compiler.abort(
                            rule,
                            'Loopback interface of the firewall object does '
                            'not have IP address but is used in the rule',
                        )
                        new_elements.append(obj)
                    else:
                        # Append all addresses; the wrong address family is
                        # removed downstream by DropIPv4Rules/DropIPv6Rules.
                        for addr in obj.addresses:
                            new_elements.append(addr)
                    changed = True
                else:
                    new_elements.append(obj)
            if changed:
                setattr(rule, slot, new_elements)
        self.tmp_queue.append(rule)
        return True


class DeprecateOptionRoute(PolicyRuleProcessor):
    """Report a rule that asks for policy routing, and leave it out.

    The "Route" rule option sends matching packets to a gateway of the
    rule's choosing.  On iptables that was the ROUTE target, which left the
    mainline kernel long ago, and ``DeprecateOptionRoute`` there refuses
    the rule.  nftables can express the same thing with ``fib`` plus a
    mark, but this compiler does not build it yet (issue #125).

    Until it does, the rule has to be reported here.  Without this the rule
    reached the mangle chains as an ordinary rule carrying nothing but its
    verdict: the packet was accepted and then followed the ordinary routing
    table, so the policy route the administrator configured was gone and
    nothing said so.  The same file compiled for iptables refused the rule,
    which means one policy behaved differently on the two platforms and
    only one of them mentioned it.

    ``Logging_nft`` reported the same thing, but only for a rule that is
    Continue *and* logs - the rare case.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_option('routing', False):
            self.compiler.error(
                rule,
                'Policy routing is not yet supported by the nftables '
                'compiler; the rule is left out. Use a Custom Action to '
                'write the nftables statement by hand if you need it',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class Accounting(PolicyRuleProcessor):
    """Count the traffic of an accounting rule in a named counter.

    iptables has no target that only counts, so it sends the traffic
    through a chain of its own that immediately returns and reads the
    counters of that chain.  nftables has the counter as a named object
    (netfilter nftables doc/stateful-objects.txt), so the rule counts into
    it and falls through, which is the same effect without the detour.

    The counter is named after the rule unless the rule carries an explicit
    accounting name, matching what the iptables compiler does with the
    chain name.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.action != PolicyAction.Accounting or rule.ipt_target:
            self.tmp_queue.append(rule)
            return True

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        name = rule.get_option('rule_name_accounting', '') or nft_comp.new_counter_name(
            rule
        )
        if not is_valid_nft_identifier(name):
            # Refusing here would turn a name into a compile failure, so the
            # counter is renamed instead; nft would refuse the whole ruleset
            # over the name, which is the worse of the two.
            renamed = nft_object_name(name)
            self.compiler.warning(
                rule,
                f'Accounting name "{name}" cannot name an nftables counter; '
                f'the counter is called "{renamed}" instead',
            )
            name = renamed
        nft_comp.register_counter(name)
        rule.set_option('nft_counter_name', name)

        # Counting does not decide anything, so the packet has to carry on
        # to the rules below.
        rule.action = PolicyAction.Continue
        rule.ipt_target = '.CONTINUE'

        self.tmp_queue.append(rule)
        return True


class BridgingFw(PolicyRuleProcessor):
    """Handle bridging firewall cases.

    For rules in the input chain whose destination is a broadcast or
    multicast address, split the rule so that a copy goes into the forward
    chain as well.  This handles broadcasts forwarded by a bridge that must
    also be accepted by the firewall itself.

    If the rule's interface is unnumbered or a bridge port, the rule is
    simply moved to forward (no split needed).

    Corresponds to C++ ``PolicyCompiler_ipt::bridgingFw`` (kept in parity
    with the iptables compiler's ``BridgingFw``).
    """

    @staticmethod
    def _is_broadcast_or_multicast(addr: Address) -> bool:
        """Check if an address is broadcast (255.255.255.255) or multicast (224.0.0.0/4)."""
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
    def _matches_interface_broadcast(addr: Address, fw) -> bool:
        """Check if address matches the network or broadcast address of a firewall interface."""
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
                    if obj_addr in (net.network_address, net.broadcast_address):
                        return True
                except ValueError:
                    continue
        return False

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        dst = rule.dst[0] if rule.dst else None

        if rule.ipt_chain == 'input' and isinstance(dst, Address):
            is_bcast_mcast = self._is_broadcast_or_multicast(
                dst
            ) or self._matches_interface_broadcast(dst, self.compiler.fw)

            if is_bcast_mcast:
                rule_iface = rule.itf[0] if rule.itf else None

                if isinstance(rule_iface, Interface) and (
                    rule_iface.is_unnumbered() or rule_iface.is_bridge_port()
                ):
                    # Unnumbered or bridge port: just move to forward.
                    rule.ipt_chain = 'forward'
                else:
                    # Regular interface: split into input + forward copy.
                    r = rule.clone()
                    r.ipt_chain = 'forward'
                    self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class CheckMACInOUTPUTChain(PolicyRuleProcessor):
    """Abort if a MAC address is matched where the kernel cannot see one.

    A locally generated packet has no link-layer header when it reaches
    the output hook, and ``nft_payload_eval`` gives up on any
    ``NFT_PAYLOAD_LL_HEADER`` read without one
    (``net/netfilter/nft_payload.c``: ``if (!skb_mac_header_was_set(skb)
    || skb_mac_header_len(skb) == 0) goto err``).  The rule loads and then
    never matches, which lets through what a Deny rule was written to stop
    and drops what an Accept rule was written to allow, with nothing said
    about it anywhere.

    Postrouting is not on the list, and that is the one place nftables can
    do what iptables cannot: a forwarded packet still carries the header it
    arrived with, so an ``ether saddr`` there is a real match.  The iptables
    mac match has no such distinction - ``xt_mac`` does not register for the
    hook at all (``net/netfilter/xt_mac.c``) - so the two platforms
    deliberately differ on that chain.

    Both rule elements are searched, and all three shapes a MAC arrives in:
    a bare ``PhysAddress``, a ``CombinedAddress`` pairing one with an
    address, and an interface or host whose only address is a MAC.  The
    print rule renders an ``ether`` match for every one of them.

    A combined address keeps its IP half and loses only the MAC, which is
    what the iptables sibling and both NAT guards do; only an object that
    is nothing but a MAC takes the rule with it, because removing that one
    leaves an element that means "any".
    """

    #: The chains an ethernet address cannot be matched in.
    FORBIDDEN_CHAINS = ('output',)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.ipt_chain not in self.FORBIDDEN_CHAINS:
            self.tmp_queue.append(rule)
            return True

        for slot in ('src', 'dst'):
            kept, mac_name = strip_mac_objects(getattr(rule, slot))
            if not mac_name:
                continue
            if not kept:
                self.compiler.abort(
                    rule,
                    f'Can not match the MAC address of "{mac_name}" in the '
                    f'{rule.ipt_chain} chain, where the packet does not carry '
                    f'one yet',
                )
                return True
            setattr(rule, slot, kept)
            self.compiler.warning(
                rule,
                f'Can not match the MAC address of "{mac_name}" in the '
                f'{rule.ipt_chain} chain, where the packet does not carry one '
                f'yet; the rule matches on the address alone',
            )

        self.tmp_queue.append(rule)
        return True


class Logging1(PolicyRuleProcessor):
    """Apply global log_all option."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if self.compiler.fw.get_option('log_all'):
            rule.set_option('log', True)
        self.tmp_queue.append(rule)
        return True


class ProcessMultiAddressObjectsInRE(PolicyRuleProcessor):
    """Process runtime MultiAddress objects by splitting into separate rules."""

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

        # A run-time AddressTable belongs here too: it renders as a
        # reference to a named set, which cannot be an element of the
        # anonymous set the other addresses of the element are merged into.
        runtime_objs = [
            o
            for o in elements
            if isinstance(o, MultiAddressRunTime) or is_run_time_address_table(o)
        ]
        if not runtime_objs:
            self.tmp_queue.append(rule)
            return True

        negated = rule.get_neg(self._slot) or bool(
            getattr(rule, f'{self._slot}_single_object_negation', False)
        )
        if len(elements) == 1 or negated:
            # A negated element means "none of these", so its objects have
            # to stay in one rule; the print rule renders them as several
            # matches, which nftables ANDs.
            self.tmp_queue.append(rule)
            return True

        for mart in runtime_objs:
            r = rule.clone()
            setattr(r, self._slot, [mart])
            self.tmp_queue.append(r)

        remaining = [o for o in elements if o not in runtime_objs]
        if remaining:
            setattr(rule, self._slot, remaining)
            self.tmp_queue.append(rule)
        return True


class SplitIfMacAndAddressInRE(PolicyRuleProcessor):
    """Give the MAC-matching objects of an element a rule of their own.

    The objects of a rule element are alternatives, but the matches of one
    nftables rule are ANDed, so alternatives can only share a rule when they
    merge into one set.  A MAC lives in the ethernet header and an IP
    address in the IP header, so they never do: written into the same rule
    they ask for a packet that carries both, and ``ether saddr X`` next to
    ``ether saddr { Y, Z }`` asks for a packet that can never exist at all.

    The element is therefore split into the groups that *can* each become a
    single match - the objects that name a MAC and an address, the objects
    that name only a MAC, and the plain addresses - and every group gets its
    own rule.  A negated element is left alone: "none of these" is a
    conjunction and belongs in one rule.

    The iptables compiler has no equivalent because ``ConvertToAtomic``
    already gives every object its own rule there, and the alternatives
    become the branches of a temporary chain.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    @staticmethod
    def _group(obj) -> int:
        """Return which match an object can be part of."""
        if isinstance(obj, CombinedAddress) and obj.has_phys_address():
            return 0
        if get_mac_only_address(obj):
            return 1
        return 2

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements or len(elements) == 1:
            self.tmp_queue.append(rule)
            return True

        negated = rule.get_neg(self._slot) or bool(
            getattr(rule, f'{self._slot}_single_object_negation', False)
        )
        if negated:
            self.tmp_queue.append(rule)
            return True

        groups: dict[int, list] = {}
        for obj in elements:
            groups.setdefault(self._group(obj), []).append(obj)
        if len(groups) == 1:
            self.tmp_queue.append(rule)
            return True

        for _, objects in sorted(groups.items()):
            split = rule.clone()
            setattr(split, self._slot, objects)
            self.tmp_queue.append(split)
        return True


class SplitIfSeveralSetsInRE(PolicyRuleProcessor):
    """Give every named set of an element a rule of its own.

    An address table, a DNS name and a dynamic interface have no address
    at compile time, so each is matched through a named set the activation
    script fills in.  A set reference cannot be an element of the anonymous
    set the plain addresses of the element are merged into, so it needs a
    match of its own - and the matches of one nftables rule are ANDed,
    which asks for a packet whose address is in two sets at once.  No
    packet is, so a Deny rule of that shape stops nothing and an Accept
    rule lets nothing through.

    The objects of an element are alternatives, so the answer is a rule per
    set plus one for everything that can share an anonymous set.  Two
    objects that render to the *same* set - an interface named in the rule
    and the same interface reached through its host - stay together.

    A negated element is left alone: "none of these" is a conjunction and
    is exactly what several ANDed matches say.

    Runs after ``ExpandMultipleAddresses``, which is where an interface
    reached through its parent host first becomes visible.  The iptables
    compiler needs no equivalent: it wraps such an address in a shell loop
    and ``ConvertToAtomic`` has already given every object its own rule.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements or len(elements) == 1:
            self.tmp_queue.append(rule)
            return True

        negated = rule.get_neg(self._slot) or bool(
            getattr(rule, f'{self._slot}_single_object_negation', False)
        )
        if negated:
            self.tmp_queue.append(rule)
            return True

        ipv6 = bool(getattr(self.compiler, 'ipv6_policy', False))
        groups: dict[str, list] = {}
        for obj in elements:
            groups.setdefault(nft_set_reference_name(obj, ipv6) or '', []).append(obj)
        if len(groups) == 1:
            self.tmp_queue.append(rule)
            return True

        for _, objects in sorted(groups.items()):
            split = rule.clone()
            setattr(split, self._slot, objects)
            self.tmp_queue.append(split)
        return True


class SpecialCasesWithCustomServices(PolicyRuleProcessor):
    """Handle CustomService with ESTABLISHED/RELATED -- make stateless."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if not rule.srv:
            self.tmp_queue.append(rule)
            return True

        platform = self.compiler.my_platform_name()
        to_separate: list = []
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


class VerifyCustomServices(PolicyRuleProcessor):
    """Verify CustomService has code for nftables platform."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)
        platform = self.compiler.my_platform_name()
        for srv in rule.srv:
            if isinstance(srv, CustomService):
                code = custom_service_code(srv, platform)
                if not code:
                    self.compiler.abort(
                        rule,
                        f"Custom service '{srv.name}' is not configured"
                        f" for '{platform}'",
                    )
        return True
