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

"""NATCompiler_ipt: iptables NAT rule compilation.

Corresponds to fwbuilder's iptlib/nat_compiler_ipt.py.
NAT compiler for iptables with 24+ rule processors that transform
NAT rules into iptables -t nat commands.
"""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import uuid
from collections import defaultdict
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._nat_compiler import NATCompiler
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    AddVirtualAddress,
    Begin,
    DropIPv4Rules,
    DropIPv6Rules,
    EmptyGroupsInRE,
    ExpandGroups,
    ExpandMultipleAddressesInNAT,
    NATCheckForDynamicInterfacesOfOtherObjects,
    NATSpecialCaseWithUnnumberedInterface,
    PrintTotalNumberOfRules,
    RecursiveGroupsInRE,
    ReplaceClusterInterfaceInItfRE,
    ResolveMultiAddress,
    SimplePrintProgress,
    VerifyAddresses,
    VerifyAddressRanges,
    VerifyMacAddresses,
    VerifyRules,
    VerifyScriptLiterals,
)
from firewallfabrik.compiler.processors._policy import (
    expand_interface_negation,
)
from firewallfabrik.compiler.processors._service import (
    SeparateSrcAndDstPort,
    SeparateSrcPort,
    SeparateTCPWithFlags,
    VerifyCustomServices,
    VerifyIcmpTypes,
    VerifyIpProtocols,
    VerifyPortRanges,
)
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    Cluster,
    Firewall,
    ICMP6Service,
    ICMPService,
    Interface,
    NATAction,
    NATRuleType,
    Network,
    NetworkIPv6,
    TCPService,
    TCPUDPService,
    UDPService,
    UserService,
)
from firewallfabrik.platforms.iptables._utils import (
    bridge_port_matches_inbound_in_postrouting,
    get_iptables_version,
    single_negation_qualifies,
    version_compare,
)
from firewallfabrik.platforms.linux._netfilter import (
    build_interface_groups,
    count_bridge_interfaces,
    destination_port_half,
    interface_group_object,
    nat_interface_problem,
    strip_mac_objects,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator


STANDARD_NAT_CHAINS = [
    'POSTROUTING',
    'PREROUTING',
    'SNAT',
    'DNAT',
    'MASQUERADE',
    'REDIRECT',
    'NETMAP',
    'LOG',
    'MARK',
    'ACCEPT',
    'REJECT',
    'DROP',
    'RETURN',
    'OUTPUT',
]


class NATCompiler_ipt(NATCompiler):
    """IPT-specific NAT compiler with 24+ rule processors."""

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

        self.bridge_count: int = 0
        self.minus_n_commands: dict[str, bool] | None = minus_n_commands

        # Chain management
        self.chain_usage_counter: dict[str, int] = defaultdict(int)
        self.upstream_chains: dict[str, list[str]] = defaultdict(list)

        # Chain prefix for coexistence mode (e.g. 'fwf' → fwf_PREROUTING)
        self.chain_prefix: str = ''

        # Branch ruleset chain mapping (set by the driver)
        self.branch_ruleset_to_chain_mapping: dict[str, list[str]] | None = None

        # The chain a branch rule set writes into, set by the driver through
        # `register_rule_set_chain()`. Empty for the top rule set.
        self.rule_set_chain: str = ''

        # Print rule processor reference
        self.print_rule_processor: NATRuleProcessor | None = None

        # iptables version
        self.version: str = get_iptables_version(fw)

        # How many temporary chains each rule has been given already.  Per
        # instance, like `PolicyCompiler_ipt.tmp_chain_counters`: the key
        # below is derived from the rule set name and the rule position,
        # which repeat in every firewall of a file, so a counter living
        # longer than one compile hands the same rule a different name
        # every time it is compiled.
        self.tmp_chain_counters: dict[str, int] = {}

        # ipset usage flag
        self.using_ipset: bool = False
        if version_compare(self.version, '1.4.1.1') >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set'))

    @staticmethod
    def get_standard_chains() -> list[str]:
        return STANDARD_NAT_CHAINS

    def my_platform_name(self) -> str:
        return 'iptables'

    def get_new_tmp_chain_name(self, rule: CompRule) -> str:
        """Generate a unique temporary chain name for a rule.

        Uses a stable content-based hash (ruleset name + rule position
        + subrule suffix) so the generated iptables script is
        deterministic across fresh loads of the same `.fwb` / `.fwf`.
        See `PolicyCompiler_ipt.get_new_tmp_chain_name` for the
        rationale.

        fwbuilder keeps the counter in a file-scope map
        (`NATCompiler_ipt.cpp:87`) and can, because it keys it on the
        rule's persistent XML id, which no second rule ever repeats.  The
        key here is not unique that way, so the counter belongs to the
        compile run.
        """
        stable_key = f'{self.rule_set_key()}:{rule.position}:{rule.subrule_suffix}'
        chain_id = hashlib.md5(  # nosec B324
            stable_key.encode(),
            usedforsecurity=False,
        ).hexdigest()[:12]
        n = self.tmp_chain_counters.get(chain_id, 0)
        name = f'C{chain_id}.{n}'
        self.tmp_chain_counters[chain_id] = n + 1
        return name

    def register_rule_set_chain(self, chain_name: str) -> None:
        self.chain_usage_counter[chain_name] = 1
        # Only the first call names this compiler's own rule set; the later
        # ones register the chains a branching rule jumps to.
        if not self.rule_set_chain:
            self.rule_set_chain = chain_name

    def insert_upstream_chain(self, parent: str, child: str) -> None:
        self.upstream_chains[parent].append(child)

    def get_rule_set_name(self) -> str:
        if self.source_ruleset:
            return self.source_ruleset.name
        return 'NAT'

    def get_compiled_script_length(self) -> int:
        return len(self.output.getvalue())

    def prolog(self) -> int:
        for chain in STANDARD_NAT_CHAINS:
            self.chain_usage_counter[chain] = 1

        n = super().prolog()

        # A branch rule set is only reached through the jump of the rule that
        # branches into it, so its rules live in a chain of their own
        # (fwbuilder CompilerDriver_ipt::assignRuleSetChain).  `DecideOnChain`
        # turns that into the per-direction chain the rule really needs.
        if self.rule_set_chain:
            for rule in self.rules:
                rule.ipt_chain = self.rule_set_chain

        # NATPrintRule names the parent bridge next to a wildcard bridge
        # port for the same reason the policy printer does, and needs the
        # same count to decide whether it is worth it.
        self.bridge_count = count_bridge_interfaces(self.fw)

        return n

    def compile(self) -> None:
        banner = f" Compiling ruleset {self.get_rule_set_name()} for 'nat' table"
        if self.ipv6_policy:
            banner += ', IPv6'
        self.info(banner)

        super().compile()

        self.add(Begin())
        self.add(PrintTotalNumberOfRules())

        self.add(ExpandGroupsInItfInb('expand groups in inbound Interface'))
        self.add(
            ReplaceClusterInterfaceInItfRE(
                'replace cluster interfaces inbound', 'itf_inb'
            )
        )
        self.add(
            SingleObjectNegationItfInb('process single object negation in inbound Itf')
        )
        self.add(ItfInbNegation('process negation in inbound Itf'))
        self.add(ExpandGroupsInItfOutb('expand groups in outbound Interface'))
        self.add(
            ReplaceClusterInterfaceInItfRE(
                'replace cluster interfaces outbound', 'itf_outb'
            )
        )
        self.add(
            SingleObjectNegationItfOutb(
                'process single object negation in outbound Itf'
            )
        )
        self.add(ItfOutbNegation('process negation in outbound Itf'))

        self.add(ResolveMultiAddress('resolve compile-time MultiAddress'))

        self.add(RecursiveGroupsInRE('check for recursive groups in OSRC', 'osrc'))
        self.add(RecursiveGroupsInRE('check for recursive groups in ODST', 'odst'))
        self.add(RecursiveGroupsInRE('check for recursive groups in OSRV', 'osrv'))
        self.add(RecursiveGroupsInRE('check for recursive groups in TSRC', 'tsrc'))
        self.add(RecursiveGroupsInRE('check for recursive groups in TDST', 'tdst'))
        self.add(RecursiveGroupsInRE('check for recursive groups in TSRV', 'tsrv'))

        self.add(EmptyGroupsInRE('check for empty groups in OSRC', 'osrc'))
        self.add(EmptyGroupsInRE('check for empty groups in ODST', 'odst'))
        self.add(EmptyGroupsInRE('check for empty groups in OSRV', 'osrv'))
        self.add(EmptyGroupsInRE('check for empty groups in TSRC', 'tsrc'))
        self.add(EmptyGroupsInRE('check for empty groups in TDST', 'tdst'))
        self.add(EmptyGroupsInRE('check for empty groups in TSRV', 'tsrv'))

        self.add(ExpandGroups('Expand groups'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))

        self.add(EliminateDuplicatesInOSRC('eliminate duplicates in OSRC'))
        self.add(EliminateDuplicatesInODST('eliminate duplicates in ODST'))
        self.add(EliminateDuplicatesInOSRV('eliminate duplicates in OSRV'))

        self.add(
            NATProcessMultiAddressObjectsInRE('process MultiAddress in OSrc', 'osrc')
        )
        self.add(
            NATProcessMultiAddressObjectsInRE('process MultiAddress in ODst', 'odst')
        )
        self.add(
            NATProcessMultiAddressObjectsInRE('process MultiAddress in TSrc', 'tsrc')
        )
        self.add(
            NATProcessMultiAddressObjectsInRE('process MultiAddress in TDst', 'tdst')
        )

        self.add(DoOSrvNegation('process negation in OSrv'))

        self.add(ConvertToAtomicForOSrv('convert to atomic rules in OSrv'))

        self.add(ClassifyNATRule('classify NAT rule'))
        self.add(SplitSDNATRule('split SDNAT rules'))
        self.add(ClassifyNATRule('reclassify rules'))
        self.add(ConvertLoadBalancingRules('convert load balancing rules'))
        self.add(VerifyRules('verify rules'))

        self.add(SingleObjectNegationOSrc('negation in OSrc if it holds single object'))
        self.add(SingleObjectNegationODst('negation in ODst if it holds single object'))

        self.add(DoOSrcNegation('process negation in OSrc'))
        self.add(DoODstNegation('process negation in ODst'))

        # Call splitOnODst after processing negation
        self.add(SplitOnODst('split on ODst'))

        self.add(PortTranslationRules('port translation rules'))
        self.add(
            SpecialCaseWithRedirect(
                'special case with redirecting port translation rules'
            )
        )

        if self.fw.get_option('local_nat'):
            if self.fw.get_option('firewall_is_part_of_any_and_networks'):
                self.add(SplitIfOSrcAny('split rule if OSrc is any'))
            self.add(SplitIfOSrcMatchesFw('split rule if OSrc matches FW'))

        self.add(SplitNONATRule('NAT rules that request no translation'))
        self.add(SplitNATBranchRule('Split Branch rules to use all chains'))
        self.add(LocalNATRule('local NAT rule'))
        self.add(DecideOnChain('decide on chain'))
        self.add(DecideOnTarget('decide on target'))

        self.add(
            SplitODstForSNAT(
                'split rule if objects in ODst belong to different subnets'
            )
        )
        self.add(ReplaceFirewallObjectsODst('replace firewall in ODst'))
        self.add(ReplaceFirewallObjectsTSrc('replace firewall in TSrc'))
        self.add(
            SplitOnDynamicInterfaceInODst('split rule if ODst is dynamic interface')
        )
        self.add(
            SplitOnDynamicInterfaceInTSrc('split rule if TSrc is dynamic interface')
        )

        self.add(ExpandMultipleAddressesInNAT('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))

        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        self.add(
            NATSpecialCaseWithUnnumberedInterface(
                'handle unnumbered interfaces in NAT rules'
            )
        )
        self.add(
            NATCheckForDynamicInterfacesOfOtherObjects(
                'check for dynamic interfaces of other objects'
            )
        )
        self.add(VerifyRuleWithMAC('verify MAC address usage in NAT rules'))
        self.add(
            CheckUserServiceInWrongChains('check user service against the NAT chain')
        )
        self.add(NATExpandAddressRanges('expand address ranges in NAT rules'))

        self.add(
            SplitMultiSrcAndDst('split rules where multiple srcs and dsts are present')
        )

        self.add(GroupServicesByProtocol('group services by protocol'))
        # A TCP service may inspect the flags, and one nat rule carries one
        # flag comparison, so a service that names flags needs a rule of its
        # own before the printer merges the rest into a port set.  The
        # policy pipelines have split on it since they were written; the NAT
        # pipelines never did, here or in fwbuilder, and the printer's
        # multi-service branch writes ports alone - so a rule naming a
        # SYN-only service next to any second service translated every TCP
        # packet on those ports instead of the handshake stage it was
        # written for.
        self.add(SeparateTCPWithFlags('split on TCP services with flags'))
        # A Custom Service is a fragment of platform text, so a rule using
        # one on a platform it carries no text for cannot be built.  The
        # processor reads a NAT rule's OSrv as well as a policy rule's Srv,
        # but only the policy pipelines ever ran it, on either platform and
        # in fwbuilder: a NAT rule kept its place in the pipeline and lost
        # the match in the print rule, so the translation went out matching
        # everything else the rule named.
        self.add(VerifyCustomServices('verify custom services'))
        self.add(VerifyPortRanges('verify port ranges'))
        self.add(VerifyIcmpTypes('verify ICMP types'))
        self.add(VerifyIpProtocols('verify IP protocols'))
        self.add(VerifyAddressRanges('verify address ranges'))
        self.add(VerifyScriptLiterals('verify names reaching the script'))
        self.add(VerifyAddresses('verify addresses'))
        self.add(VerifyMacAddresses('verify MAC addresses'))
        self.add(VerifyRules2('check correctness of TSrv'))
        self.add(SeparatePortRanges('separate port ranges'))

        self.add(SeparateSrcPort('separate objects with src ports'))
        self.add(SeparateSrcAndDstPort('separate objects with src and dest ports'))

        self.add(PrepareForMultiport('prepare for multiport'))
        self.add(SplitMultipleICMP('split rule with multiple ICMP services'))

        self.add(ConvertToAtomicForAddresses('convert to atomic rules'))

        self.add(AddVirtualAddress('add virtual addresses'))

        self.add(AssignInterface('assign rules to interfaces'))
        self.add(VerifyRules3('check combination of interface spec and chain'))
        self.add(DynamicInterfaceInODst('split if dynamic interface in ODst'))
        self.add(DynamicInterfaceInTSrc('set target if dynamic interface in TSrc'))
        self.add(AlwaysUseMasquerade('always use masquerading target instead of SNAT'))

        self.add(ConvertToAtomicForItfInb('convert to atomic for inbound interface'))
        self.add(ConvertToAtomicForItfOutb('convert to atomic for outbound interface'))

        self.add(CheckForObjectsWithErrors('check for objects with errors'))
        self.add(CountChainUsage('Count chain usage'))

        # Print rule
        from firewallfabrik.platforms.iptables._nat_print_rule import (
            NATPrintRule,
            NATPrintRuleIptRstEcho,
        )

        if self.fw.get_option('use_iptables_restore'):
            self.print_rule_processor = NATPrintRuleIptRstEcho(
                'generate code for iptables-restore using echo'
            )
        else:
            self.print_rule_processor = NATPrintRule('generate iptables shell script')

        self.print_rule_processor.set_context(self)
        self.print_rule_processor.initialize()
        self.add(self.print_rule_processor)

        self.add(SimplePrintProgress('print progress'))

        self.run_rule_processors()

    def epilog(self) -> None:
        if (
            self.fw.get_option('use_iptables_restore')
            and self.get_compiled_script_length() > 0
            and not self.single_rule_compile_mode
        ):
            self.output.write('#\n')

    def flush_and_set_default_policy(self) -> str:
        if not self.fw.get_option('use_iptables_restore'):
            return ''
        if self.single_rule_compile_mode:
            return ''
        # Quoted, so the shell does not read `[0:0]` as a glob; see
        # PolicyCompiler_ipt.flush_and_set_default_policy.
        return (
            'echo ":PREROUTING ACCEPT [0:0]"\n'
            'echo ":POSTROUTING ACCEPT [0:0]"\n'
            'echo ":OUTPUT ACCEPT [0:0]"\n'
        )

    def print_automatic_rules(self) -> str:
        return ''

    def commit(self) -> str:
        if self.print_rule_processor is not None:
            return getattr(self.print_rule_processor, '_commit', lambda: '')()
        return ''

    def get_used_chains(self) -> list[str]:
        return list(self.chain_usage_counter.keys())


# -- Rule Processors --


class ExpandGroupsInItfInb(NATRuleProcessor):
    """Expand groups in the inbound interface element."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.compiler.expand_groups_in_element(rule, 'itf_inb')
        self.tmp_queue.append(rule)
        return True


class ExpandGroupsInItfOutb(NATRuleProcessor):
    """Expand groups in the outbound interface element."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.compiler.expand_groups_in_element(rule, 'itf_outb')
        self.tmp_queue.append(rule)
        return True


class SingleObjectNegationItfInb(NATRuleProcessor):
    """Handle single-object negation for inbound interface in NAT rules.

    If the inbound interface element has negation and contains exactly
    one object, convert to inline '!' negation.

    Corresponds to C++ NATCompiler::singleObjectNegationItfInb.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('itf_inb') and len(rule.itf_inb) == 1:
            rule.set_neg('itf_inb', False)
            rule.itf_inb_single_object_negation = True
        self.tmp_queue.append(rule)
        return True


class SingleObjectNegationItfOutb(NATRuleProcessor):
    """Handle single-object negation for outbound interface in NAT rules.

    If the outbound interface element has negation and contains exactly
    one object, convert to inline '!' negation.

    Corresponds to C++ NATCompiler::singleObjectNegationItfOutb.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('itf_outb') and len(rule.itf_outb) == 1:
            rule.set_neg('itf_outb', False)
            rule.itf_outb_single_object_negation = True
        self.tmp_queue.append(rule)
        return True


class ItfInbNegation(NATRuleProcessor):
    """Replace negated inbound interface with all other interfaces."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if expand_interface_negation(self.compiler, rule, 'itf_inb'):
            self.tmp_queue.append(rule)
        return True


class ItfOutbNegation(NATRuleProcessor):
    """Replace negated outbound interface with all other interfaces."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if expand_interface_negation(self.compiler, rule, 'itf_outb'):
            self.tmp_queue.append(rule)
        return True


class SingleObjectNegationInRE(NATRuleProcessor):
    """Negate a NAT rule element holding one object with iptables' own ``!``.

    Corresponds to C++ ``NATCompiler::singleObjectNegationOSrc`` and its
    ODst twin, and asks :func:`single_negation_qualifies`, the same
    question the policy pipeline asks.  Asking a looser one here - any
    ``Address`` would do - let an AddressRange through, and
    ``NATExpandAddressRanges`` runs afterwards and writes the range out as
    the networks covering it: the rule then carried one ``!`` per network,
    which is the negation of each network rather than of the range, so a
    packet from inside the range matched the very first of them and the
    rule did the opposite of what it says.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        elements = getattr(rule, self._slot)
        if (
            rule.get_neg(self._slot)
            and len(elements) == 1
            and single_negation_qualifies(self.compiler, elements[0])
        ):
            setattr(rule, f'{self._slot}_single_object_negation', True)
            rule.set_neg(self._slot, False)
        self.tmp_queue.append(rule)
        return True


class SingleObjectNegationOSrc(SingleObjectNegationInRE):
    """Single-object negation for the original source."""

    def __init__(self, name: str) -> None:
        super().__init__(name, 'osrc')


class SingleObjectNegationODst(SingleObjectNegationInRE):
    """Single-object negation for the original destination."""

    def __init__(self, name: str) -> None:
        super().__init__(name, 'odst')


class DropRuleWithEmptyRE(NATRuleProcessor):
    """Drop rules where a required rule element became empty."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # For NAT rules, check osrc/odst/osrv
        # Empty after expansion = should drop (different from "any" = [])
        # We track this with a special flag set by group expansion
        if rule.has_empty_re:
            reason = rule.empty_re_reason or 'one of its elements is empty'
            self.compiler.warning(rule, f'Rule is left out because {reason}')
            return True

        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInOSRC(NATRuleProcessor):
    """Eliminate duplicate objects in OSrc by ID."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        seen = set()
        unique = []
        for obj in rule.osrc:
            oid = id(obj)
            if oid not in seen:
                seen.add(oid)
                unique.append(obj)
        rule.osrc = unique
        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInODST(NATRuleProcessor):
    """Eliminate duplicate objects in ODst by ID."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        seen = set()
        unique = []
        for obj in rule.odst:
            oid = id(obj)
            if oid not in seen:
                seen.add(oid)
                unique.append(obj)
        rule.odst = unique
        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInOSRV(NATRuleProcessor):
    """Eliminate duplicate objects in OSrv by ID."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        seen = set()
        unique = []
        for obj in rule.osrv:
            oid = id(obj)
            if oid not in seen:
                seen.add(oid)
                unique.append(obj)
        rule.osrv = unique
        self.tmp_queue.append(rule)
        return True


class NATProcessMultiAddressObjectsInRE(NATRuleProcessor):
    """Process runtime MultiAddress objects in NAT rules."""

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
        runtime_objs = [o for o in elements if isinstance(o, MultiAddressRunTime)]
        if not runtime_objs:
            self.tmp_queue.append(rule)
            return True
        if len(elements) == 1 and len(runtime_objs) == 1:
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


class ClassifyNATRule(NATRuleProcessor):
    """Classify NAT rule type based on TSrc/TDst/TSrv contents.

    Corresponds to C++ NATCompiler::classifyNATRule.  Considers service
    port translation (TSrv) in addition to address translation (TSrc/TDst).
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.nat_rule_type is not None and rule.nat_rule_type != NATRuleType.Unknown:
            return True

        tsrc = rule.tsrc[0] if rule.tsrc else None
        tdst = rule.tdst[0] if rule.tdst else None
        tsrv = rule.tsrv[0] if rule.tsrv else None
        osrv = rule.osrv[0] if rule.osrv else None

        tsrc_any = tsrc is None
        tdst_any = tdst is None
        tsrv_any = tsrv is None

        # Branch action.  A branch jumps into another rule set and
        # translates nothing itself, so whatever the editor left in the
        # translated elements is not compiled - and saying so beats
        # leaving it there for a later processor to read
        # (NATCompiler::classifyNATRule).
        if rule.action == NATAction.Branch:
            rule.nat_rule_type = NATRuleType.NATBranch
            if rule.tsrc or rule.tdst or rule.tsrv:
                rule.tsrc = []
                rule.tdst = []
                rule.tsrv = []
                self.compiler.warning(
                    rule,
                    'Translated Src, Dst and Srv are ignored in the NAT rule '
                    "with action 'Branch'",
                )
            return True

        # NONAT
        if tsrc_any and tdst_any and tsrv_any:
            rule.nat_rule_type = NATRuleType.NONAT
            return True

        # Determine if TSrv translates src or dst ports
        tsrv_translates_src_port = False
        tsrv_translates_dst_port = False

        if isinstance(osrv, TCPUDPService) and isinstance(tsrv, TCPUDPService):
            tsrv_translates_src_port = (tsrv.src_range_start or 0) != 0 and (
                tsrv.dst_range_start or 0
            ) == 0
            tsrv_translates_dst_port = (tsrv.src_range_start or 0) == 0 and (
                tsrv.dst_range_start or 0
            ) != 0

            # If tsrv defines the same ports as osrv, it's not a translation
            if tsrv_translates_dst_port and (
                (osrv.dst_range_start or 0) == (tsrv.dst_range_start or 0)
                and (osrv.dst_range_end or 0) == (tsrv.dst_range_end or 0)
            ):
                tsrv_translates_dst_port = False

            if tsrv_translates_src_port and (
                (osrv.src_range_start or 0) == (tsrv.src_range_start or 0)
                and (osrv.src_range_end or 0) == (tsrv.src_range_end or 0)
            ):
                tsrv_translates_src_port = False

        # SDNAT: both src and dst translation
        if (
            (not tsrc_any and not tdst_any)
            or (not tsrc_any and tsrv_translates_dst_port)
            or (not tdst_any and tsrv_translates_src_port)
        ):
            rule.nat_rule_type = NATRuleType.SDNAT
            return True

        # SNAT / SNetnat (including src port translation only)
        if (not tsrc_any and tdst_any) or (
            tsrc_any and tdst_any and tsrv_translates_src_port
        ):
            if not tsrc_any and isinstance(tsrc, Network | NetworkIPv6):
                rule.nat_rule_type = NATRuleType.SNetnat
            else:
                rule.nat_rule_type = NATRuleType.SNAT
            return True

        # DNAT / DNetnat / Redirect / LB (including dst port translation only)
        if (tsrc_any and not tdst_any) or (
            tsrc_any and tdst_any and tsrv_translates_dst_port
        ):
            if len(rule.tdst) > 1:
                # Several translated destinations mean load balancing
                # (NATCompiler.cpp:291).  Without the type
                # `ConvertLoadBalancingRules` never ran and
                # `ConvertToAtomicForAddresses` made one DNAT rule per
                # backend - and DNAT terminates, so the first rule took
                # every connection and the other backends got none.
                rule.nat_rule_type = NATRuleType.LB
                return True
            if not tdst_any and isinstance(tdst, Network | NetworkIPv6):
                rule.nat_rule_type = NATRuleType.DNetnat
            elif (
                not tdst_any
                and isinstance(tdst, Firewall)
                and tdst.id == self.compiler.fw.id
            ):
                rule.nat_rule_type = NATRuleType.Redirect
            else:
                rule.nat_rule_type = NATRuleType.DNAT
            return True

        self.compiler.abort('Unsupported NAT rule')
        return True


class PortTranslationRules(NATRuleProcessor):
    """Copy ODst into TDst for port-only translation targeting the firewall.

    Corresponds to C++ NATCompiler_ipt::portTranslationRules.
    When a DNAT rule has TSrc=Any, TDst=Any, TSrv!=Any, and ODst is
    the firewall, copy ODst into TDst so downstream processors can
    recognize it as a redirect.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if (
            rule.nat_rule_type == NATRuleType.DNAT
            and not rule.tsrc
            and not rule.tdst
            and rule.tsrv
            and rule.odst
        ):
            odst = rule.odst[0]
            if isinstance(odst, Firewall) and odst.id == self.compiler.fw.id:
                rule.tdst = [odst]

        self.tmp_queue.append(rule)
        return True


class SpecialCaseWithRedirect(NATRuleProcessor):
    """Convert DNAT to Redirect when TDst is the firewall.

    Corresponds to C++ NATCompiler_ipt::specialCaseWithRedirect.
    If a DNAT rule has TDst matching the firewall, it is a redirect
    (traffic to the firewall itself with port translation).
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type == NATRuleType.DNAT and rule.tdst:
            tdst = rule.tdst[0]
            # A rule of a cluster names the cluster object where a
            # firewall's own rule names the firewall, and both mean this
            # box (`NATCompiler_ipt::specialCaseWithRedirect`).
            cluster = self.compiler.get_cluster()
            if isinstance(tdst, Firewall) and (
                tdst.id == self.compiler.fw.id
                or (cluster is not None and tdst.id == cluster.id)
            ):
                rule.nat_rule_type = NATRuleType.Redirect

        self.tmp_queue.append(rule)
        return True


class SplitNONATRule(NATRuleProcessor):
    """Split NONAT rules into POSTROUTING + PREROUTING/OUTPUT.

    Corresponds to C++ NATCompiler_ipt::splitNONATRule.
    NONAT rules need ACCEPT in both chains to prevent accidental
    translation by other rules.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.ipt_chain and rule.nat_rule_type == NATRuleType.NONAT:
            osrc = rule.osrc[0] if rule.osrc else None
            osrc_is_fw = isinstance(osrc, Firewall) and osrc.id == self.compiler.fw.id

            # First copy: POSTROUTING
            r = rule.clone()
            r.ipt_chain = 'POSTROUTING'
            self.tmp_queue.append(r)

            # Second copy: OUTPUT (if OSrc is fw) or PREROUTING
            if osrc_is_fw:
                rule.ipt_chain = 'OUTPUT'
                rule.osrc = []
            else:
                rule.ipt_chain = 'PREROUTING'
            self.tmp_queue.append(rule)
        else:
            self.tmp_queue.append(rule)

        return True


class ReplaceFirewallObjectsODst(NATRuleProcessor):
    """Replace Firewall object in ODst with its non-loopback interfaces.

    Corresponds to C++ NATCompiler_ipt::ReplaceFirewallObjectsODst.
    Skips Masq and Redirect rule types. For other types, replaces the
    firewall object with Interface objects for address expansion.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.nat_rule_type == NATRuleType.Masq:
            return True

        if not rule.odst:
            return True

        odst = rule.odst[0]
        cluster = self.compiler.get_cluster()
        names_this_box = isinstance(odst, Firewall) and (
            odst.id == self.compiler.fw.id
            or (cluster is not None and odst.id == cluster.id)
        )
        if names_this_box:
            # On a cluster member only the copies of the cluster
            # interfaces count: the traffic is addressed to the address
            # the cluster shares, not to the member's own
            # (`NATCompiler_ipt::ReplaceFirewallObjectsODst`, fwbuilder
            # ticket #1185).
            interfaces = [
                iface
                for iface in self.compiler.fw.interfaces
                if not iface.is_loopback()
                and (
                    cluster is None
                    or self.compiler.is_cluster_interface_of(iface, cluster)
                )
            ]
            if interfaces:
                rule.odst = interfaces

        return True


class ReplaceFirewallObjectsTSrc(NATRuleProcessor):
    """Replace Firewall object in TSrc with the interface facing ODst.

    Corresponds to C++ NATCompiler_ipt::ReplaceFirewallObjectsTSrc.
    For SNAT rules where TSrc is the firewall itself, finds the
    interface whose network contains the ODst address and uses that
    interface.  Falls back to all eligible interfaces when ODst is
    "any" or no matching interface is found.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.nat_rule_type in (NATRuleType.Masq, NATRuleType.Redirect):
            return True

        if not rule.tsrc:
            return True

        tsrc = rule.tsrc[0]
        cluster = self.compiler.get_cluster()
        if not (
            isinstance(tsrc, Firewall)
            and (
                tsrc.id == self.compiler.fw.id
                or (cluster is not None and tsrc.id == cluster.id)
            )
        ):
            return True

        # TSrc is the firewall — replace with the interface facing ODst.
        # On a cluster member the interface facing the destination is
        # looked for on the *cluster*, because that is where the shared
        # addresses are (`NATCompiler_ipt::ReplaceFirewallObjectsTSrc`);
        # the one facing the source stays the member's own.
        odst = rule.odst[0] if rule.odst else None
        osrc = rule.osrc[0] if rule.osrc else None

        odst_owner = cluster if cluster is not None else self.compiler.fw
        odst_iface = (
            self.compiler.find_interface_for(odst, odst_owner) if odst else None
        )
        osrc_iface = (
            self.compiler.find_interface_for(osrc, self.compiler.fw) if osrc else None
        )

        # When ODst has single_object_negation, skip the direct match
        # and fall through to the fallback (excluding odst_iface).
        if odst_iface is not None and not rule.odst_single_object_negation:
            rule.tsrc = [odst_iface]
            return True

        # Fallback: use all non-loopback, non-unnumbered, non-bridge interfaces,
        # excluding the interface facing OSrc (per C++ logic).
        # Also exclude odst_iface when single_object_negation is set.
        # The C++ compares the two interfaces by *name* here and says
        # why: on a cluster member `odst_iface` is a child of the cluster
        # and `osrc_iface` a child of the firewall, so their ids never
        # match even where they stand for the same NIC.
        interfaces = [
            iface
            for iface in self.compiler.fw.interfaces
            if not iface.is_loopback()
            and not iface.is_unnumbered()
            and not iface.is_bridge_port()
            and not (osrc_iface and iface.name == osrc_iface.name)
            and not (
                rule.odst_single_object_negation
                and odst_iface
                and iface.name == odst_iface.name
            )
            and (
                cluster is None or self.compiler.is_cluster_interface_of(iface, cluster)
            )
        ]
        if interfaces:
            rule.tsrc = interfaces
        else:
            self.compiler.abort(
                rule,
                'Could not find suitable interface for the NAT rule. '
                'Perhaps all interfaces are unnumbered?',
            )

        return True


class DecideOnChain(NATRuleProcessor):
    """Assign rules to PREROUTING, POSTROUTING, or OUTPUT chains."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        chain_map = {
            NATRuleType.SNAT: 'POSTROUTING',
            NATRuleType.SNetnat: 'POSTROUTING',
            NATRuleType.Masq: 'POSTROUTING',
            NATRuleType.DNAT: 'PREROUTING',
            NATRuleType.DNetnat: 'PREROUTING',
            NATRuleType.Redirect: 'PREROUTING',
        }

        rt = rule.nat_rule_type
        chain = chain_map.get(rt, '') if rt is not None else ''

        if rule.ipt_chain:
            nat_comp = cast('NATCompiler_ipt', self.compiler)
            if rule.ipt_chain == nat_comp.rule_set_chain and chain:
                # A branch rule set writes into a chain of its own, but the
                # nat table reaches PREROUTING and POSTROUTING through
                # different hooks, so the branch needs one chain per
                # direction (NATCompiler_ipt::decideOnChain).
                new_chain = f'{nat_comp.rule_set_chain}_{chain}'
                nat_comp.register_rule_set_chain(new_chain)
                rule.ipt_chain = new_chain
            return True

        if chain:
            rule.ipt_chain = chain

        return True


class DecideOnTarget(NATRuleProcessor):
    """Assign iptables target based on rule type."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if rule.ipt_target:
            return True

        target_map = {
            NATRuleType.NONAT: 'ACCEPT',
            NATRuleType.SNAT: 'SNAT',
            NATRuleType.SNetnat: 'NETMAP',
            NATRuleType.DNAT: 'DNAT',
            NATRuleType.DNetnat: 'NETMAP',
            NATRuleType.Masq: 'MASQUERADE',
            NATRuleType.Redirect: 'REDIRECT',
            NATRuleType.Return: 'RETURN',
        }

        rt = rule.nat_rule_type
        if rt is not None:
            target = target_map.get(rt, '')
            if target:
                rule.ipt_target = target

        return True


class GroupServicesByProtocol(NATRuleProcessor):
    """Split rules with mixed-protocol services into separate rules.

    Corresponds to C++ Compiler::groupServicesByProtocol.
    Groups services by protocol number and creates one rule per group.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrv) <= 1:
            self.tmp_queue.append(rule)
            return True

        # Group services by protocol number
        groups: dict[int, list] = {}
        for srv in rule.osrv:
            proto = srv.get_protocol_number()
            groups.setdefault(proto, []).append(srv)

        if len(groups) <= 1:
            # All same protocol, no split needed
            self.tmp_queue.append(rule)
            return True

        # Create one rule per protocol group
        for srv_list in groups.values():
            r = rule.clone()
            r.osrv = srv_list
            self.tmp_queue.append(r)

        return True


class SeparatePortRanges(NATRuleProcessor):
    """Separate TCP/UDP services with port ranges into individual rules.

    Services where src or dst port range start != end (i.e. actual port
    ranges like 749:750) or "any TCP/UDP" services (all ports zero) get
    pulled out into their own rules because they can't be combined with
    single-port services in a ``-m multiport`` match.

    Uses the same condition logic as the policy compiler variant.
    """

    @staticmethod
    def _is_port_range(srv) -> bool:
        if not isinstance(srv, TCPService | UDPService):
            return False

        srs = srv.src_range_start or 0
        sre = srv.src_range_end or 0
        drs = srv.dst_range_start or 0
        dre = srv.dst_range_end or 0

        if srs != 0 and sre == 0:
            sre = srs
        if drs != 0 and dre == 0:
            dre = drs

        if srs == 0 and sre == 0 and drs == 0 and dre == 0:
            sre = 65535
            dre = 65535

        return srs != sre or drs != dre

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrv) <= 1:
            self.tmp_queue.append(rule)
            return True

        separated = []
        for srv in rule.osrv:
            if self._is_port_range(srv):
                r = rule.clone()
                r.osrv = [srv]
                self.tmp_queue.append(r)
                separated.append(srv)

        remaining = [s for s in rule.osrv if s not in separated]
        if remaining:
            rule.osrv = remaining
            self.tmp_queue.append(rule)

        return True


class PrepareForMultiport(NATRuleProcessor):
    """Set ipt_multiport flag for rules with multiple same-protocol services.

    Corresponds to C++ NATCompiler_ipt::prepareForMultiport.
    Also splits into chunks when the multiport entry count exceeds 15
    (the iptables multiport module limit).

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

        if len(rule.osrv) <= 1:
            self.tmp_queue.append(rule)
            return True

        # Only TCP and UDP ports go into one multiport match.  An ICMP
        # type, an IP protocol number, a custom service, a packet mark and
        # a connection owner each need their own match, and the print rule
        # renders one service per rule, so a list of them has to be split
        # or everything but the first entry is lost.  Same split as the
        # policy compiler's PrepareForMultiport.
        first_srv = rule.osrv[0]
        if not isinstance(first_srv, TCPService | UDPService):
            for srv in rule.osrv:
                r = rule.clone()
                r.osrv = [srv]
                self.tmp_queue.append(r)
            return True

        rule.ipt_multiport = True

        total_entries = sum(self._multiport_entry_count(s) for s in rule.osrv)
        if total_entries > 15:
            # Split into chunks respecting the 15-entry limit
            chunk: list = []
            chunk_entries = 0
            for srv in rule.osrv:
                entries = self._multiport_entry_count(srv)
                if chunk and chunk_entries + entries > 15:
                    r = rule.clone()
                    r.osrv = chunk
                    r.ipt_multiport = True
                    self.tmp_queue.append(r)
                    chunk = []
                    chunk_entries = 0
                chunk.append(srv)
                chunk_entries += entries
            if chunk:
                r = rule.clone()
                r.osrv = chunk
                r.ipt_multiport = True
                self.tmp_queue.append(r)
        else:
            self.tmp_queue.append(rule)

        return True


class ConvertToAtomicForAddresses(NATRuleProcessor):
    """Split rules with multiple addresses into individual atomic rules.

    Corresponds to C++ NATCompiler::ConvertToAtomicForAddresses.
    Creates one rule per combination of OSrc x ODst x TSrc x TDst.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        osrc_list = rule.osrc or [None]
        odst_list = rule.odst or [None]
        tsrc_list = rule.tsrc or [None]
        tdst_list = rule.tdst or [None]

        for osrc in osrc_list:
            for odst in odst_list:
                for tsrc in tsrc_list:
                    for tdst in tdst_list:
                        r = rule.clone()
                        r.osrc = [osrc] if osrc is not None else []
                        r.odst = [odst] if odst is not None else []
                        r.tsrc = [tsrc] if tsrc is not None else []
                        r.tdst = [tdst] if tdst is not None else []
                        self.tmp_queue.append(r)

        return True


class AssignInterface(NATRuleProcessor):
    """Assign outbound interface for SNAT/Masquerade rules.

    Corresponds to C++ NATCompiler_ipt::AssignInterface.
    For SNAT rules, determines the outbound interface from the TSrc
    address's parent interface.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Only assign interface for SNAT/Masq rules
        if rule.nat_rule_type not in (NATRuleType.SNAT, NATRuleType.Masq):
            self.tmp_queue.append(rule)
            return True

        # If interface already assigned, pass through
        if rule.itf_inb or rule.itf_outb:
            self.tmp_queue.append(rule)
            return True

        # Get the TSrc address and find its parent interface
        # "Original" leaves the element empty, and such a rule still has
        # to name the interfaces it can leave by: the C++ reads the Any
        # object here, fails the Interface cast and falls through to the
        # interface groups below.
        tsrc = rule.tsrc[0] if rule.tsrc else None

        iface = None
        if isinstance(tsrc, Interface):
            iface = tsrc
        elif isinstance(tsrc, Address) and tsrc.interface is not None:
            iface = tsrc.interface

        if iface is not None:
            owner = iface.device
            if iface.device_id == self.compiler.fw.id:
                rule.itf_outb = [iface]
                self.tmp_queue.append(rule)
                return True
            if isinstance(owner, Cluster):
                # The rule translates to a cluster interface, so it leaves
                # by the interface this member has in the failover group -
                # and TSrc stays the cluster interface, because the address
                # it translates to is the one the cluster shares
                # (NATCompiler_ipt::AssignInterface says so in the same
                # words).  A cluster interface with no failover group is
                # the copy of a member interface and is used as it stands.
                member_iface = iface
                if iface.is_failover_interface():
                    member_iface = iface.get_failover_group().get_interface_for_member(
                        self.compiler.fw
                    )
                if member_iface is not None:
                    rule.itf_outb = [member_iface]
                    self.tmp_queue.append(rule)
                    return True

        # TSrc is not tied to an interface of this firewall, so the rule
        # has to name every interface the translated traffic could leave
        # by - one rule per interface *group*, the way fwbuilder's
        # `regular_interfaces` map does it, so eth0..eth3 become one
        # `-o eth+` instead of four rules.
        groups = build_interface_groups(
            self.compiler.fw, bool(getattr(self.compiler, 'ipv6', False))
        )
        n = 0
        for group_name, members in sorted(groups.items()):
            if group_name == '*' or not members:
                continue
            r = rule.clone()
            r.itf_outb = [interface_group_object(self.compiler.fw, group_name)]
            self.tmp_queue.append(r)
            n += 1

        if n == 0:
            self.tmp_queue.append(rule)

        return True


class SplitIfOSrcAny(NATRuleProcessor):
    """Split DNAT rule if OSrc is 'any' and local_nat + firewall_is_part_of_any are on.

    Corresponds to C++ NATCompiler_ipt::splitIfOSrcAny.
    For DNAT rules where OSrc is "any" (empty) or has single_object_negation,
    and the inbound interface is "any", creates a copy with OSrc set to the
    firewall object.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Always push the original rule first
        self.tmp_queue.append(rule)

        # Do not split if user nailed inbound interface
        if rule.itf_inb:
            return True

        # Skip rules added to handle negation
        if rule.get_option('rule_added_for_osrc_neg', False):
            return True
        if rule.get_option('rule_added_for_odst_neg', False):
            return True
        if rule.get_option('rule_added_for_osrv_neg', False):
            return True

        if rule.nat_rule_type == NATRuleType.DNAT and (
            rule.is_osrc_any() or rule.osrc_single_object_negation
        ):
            r = rule.clone()
            r.osrc = [self.compiler.fw]
            self.tmp_queue.append(r)

        return True


class SplitIfOSrcMatchesFw(NATRuleProcessor):
    """Split rule if OSrc contains the firewall among other objects.

    Corresponds to C++ NATCompiler_ipt::splitIfOSrcMatchesFw.
    When OSrc has multiple objects and some match the firewall,
    extract those into separate rules.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrc) <= 1:
            self.tmp_queue.append(rule)
            return True

        nat_comp = cast('NATCompiler_ipt', self.compiler)
        fw_likes: list = []
        not_fw_likes: list = []
        for obj in rule.osrc:
            if nat_comp.complex_match(obj, nat_comp.fw):
                fw_likes.append(obj)
            else:
                not_fw_likes.append(obj)

        if fw_likes and not_fw_likes:
            for obj in fw_likes:
                r = rule.clone()
                r.osrc = [obj]
                self.tmp_queue.append(r)
            rule.osrc = not_fw_likes

        self.tmp_queue.append(rule)
        return True


class LocalNATRule(NATRuleProcessor):
    """Assign OUTPUT chain for DNAT/DNetnat/Redirect rules where OSrc matches FW.

    Corresponds to C++ NATCompiler_ipt::localNATRule.
    For DNAT/DNetnat/Redirect rules: if OSrc matches the firewall, set chain
    to OUTPUT. If OSrc IS the firewall object itself, clear OSrc to "any".
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nat_comp = cast('NATCompiler_ipt', self.compiler)

        if rule.nat_rule_type in (
            NATRuleType.DNAT,
            NATRuleType.DNetnat,
            NATRuleType.Redirect,
        ):
            osrc = rule.osrc[0] if rule.osrc else None
            if osrc is not None and nat_comp.complex_match(osrc, nat_comp.fw):
                rule.ipt_chain = 'OUTPUT'
                if isinstance(osrc, Firewall) and osrc.id == nat_comp.fw.id:
                    rule.osrc = []

        self.tmp_queue.append(rule)
        return True


class VerifyRuleWithMAC(NATRuleProcessor):
    """Take the MAC out of a NAT rule in a chain that cannot match one.

    The mac match registers for PREROUTING, INPUT and FORWARD only
    (``net/netfilter/xt_mac.c``, ``.hooks``), so ``xt_check_match``
    (``net/netfilter/x_tables.c``) refuses the rule with -EINVAL anywhere
    else and iptables stops the activation script with "Invalid argument".
    A NAT rule reaches POSTROUTING through every SNAT and Masquerade rule
    and OUTPUT through local NAT.

    Ports ``NATCompiler_ipt::verifyRuleWithMAC``: a bare physAddress is
    removed, and a combined address - which is what a host with "MAC
    address matching" expands to, and therefore the usual shape here -
    keeps its IP half and loses only the MAC.  Only a combined address
    with no address at all goes with it.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.osrc:
            self.tmp_queue.append(rule)
            return True

        chain = rule.ipt_chain or ''
        if chain in ('PREROUTING', 'FORWARD', 'INPUT'):
            self.tmp_queue.append(rule)
            return True

        kept, mac_name = strip_mac_objects(rule.osrc)
        if not mac_name:
            self.tmp_queue.append(rule)
            return True

        rule.osrc = kept

        if not rule.osrc:
            self.compiler.abort(
                rule,
                f'SNAT rule can not match MAC address, and after removing '
                f"object '{mac_name}' from OSrc it becomes 'Any'",
            )
            return True

        self.compiler.warning(
            rule,
            f"SNAT rule can not match MAC address. Object '{mac_name}' "
            f'removed from the rule',
        )
        self.tmp_queue.append(rule)
        return True


class CheckUserServiceInWrongChains(NATRuleProcessor):
    """Drop a NAT rule that matches the connection owner in prerouting.

    The kernel registers the owner match for the local-out and postrouting
    hooks only (``net/netfilter/xt_owner.c``: ``.hooks = (1 <<
    NF_INET_LOCAL_OUT) | (1 << NF_INET_POST_ROUTING)``), because a packet
    arriving from the wire has no socket to ask.  ``xt_check_match``
    (``net/netfilter/x_tables.c``) refuses the rule with -EINVAL, and the
    command iptables then reports as "Invalid argument" stops the
    activation script.  The policy compiler has always guarded this; the
    NAT one reaches prerouting through every DNAT and Redirect rule.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        srv = rule.osrv[0] if rule.osrv else None
        if isinstance(srv, UserService) and rule.ipt_chain == 'PREROUTING':
            self.compiler.warning(
                rule,
                "Iptables matches module 'owner' only in the OUTPUT and "
                'POSTROUTING chains, where the packet still has the socket '
                'that produced it',
            )
            return True  # drop rule

        self.tmp_queue.append(rule)
        return True


class NATExpandAddressRanges(NATRuleProcessor):
    """Expand AddressRange objects in OSrc and ODst to networks.

    Corresponds to C++ NATCompiler_ipt::ExpandAddressRanges.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if hasattr(self.compiler, 'expand_address_ranges'):
            self.compiler.expand_address_ranges(rule, 'osrc')
            self.compiler.expand_address_ranges(rule, 'odst')
        self.tmp_queue.append(rule)
        return True


class CheckForObjectsWithErrors(NATRuleProcessor):
    """Check for objects marked with compilation errors in NAT rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        for slot in ('osrc', 'odst', 'osrv', 'tsrc', 'tdst', 'tsrv'):
            for obj in getattr(rule, slot):
                data = getattr(obj, 'data', None) or {}
                if data.get('rule_error', False):
                    error_msg = data.get('error_msg', 'Object has errors')
                    name = getattr(obj, 'name', str(obj))
                    # An object that failed to resolve renders to nothing,
                    # and an element that renders to nothing is "any", so a
                    # translation rule kept here translates traffic it never
                    # named.
                    self.compiler.abort(
                        rule,
                        f"Object '{name}' has errors: {error_msg}. "
                        f'The rule is left out',
                    )
                    return True
        self.tmp_queue.append(rule)
        return True


class CountChainUsage(NATRuleProcessor):
    """Count how often each chain is jumped to.

    Ports C++ ``NATCompiler_ipt::countChainUsage``: a chain is used when
    a rule names it as its target, so the count is keyed on
    ``ipt_target``, not on the chain the rule sits in.  The built-in NAT
    chains and the chains of the rule sets are seeded to 1 beforehand
    (``prolog`` and ``register_rule_set_chain``).
    """

    def process_next(self) -> bool:
        if not self.slurp():
            return False

        nat_comp = cast('NATCompiler_ipt', self.compiler)
        for rule in self.tmp_queue:
            target = rule.ipt_target
            if target:
                nat_comp.chain_usage_counter[target] = (
                    nat_comp.chain_usage_counter.get(target, 0) + 1
                )

        return True


class DoOSrcNegation(NATRuleProcessor):
    """Handle multi-object negation in OSrc via temp chain with RETURN rules.

    Corresponds to C++ NATCompiler_ipt::doOSrcNegation.
    Creates a temporary chain: jump rule keeps everything except osrc,
    return rules match osrc objects, action rule fires if no match.

    Pattern:
      CHAIN     !A    B    C    TYPE     TARGET
      -----     any   B    C    (same)   TMP_CHAIN
      TMP_CHAIN  A   any  any   RETURN   RETURN
      TMP_CHAIN any  any   C    (same)   (original)
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('osrc'):
            self.tmp_queue.append(rule)
            return True

        rule.set_neg('osrc', False)

        new_chain = self.compiler.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except osrc -> jump to temp chain
        r_jump = rule.clone()
        r_jump.osrc = []
        r_jump.ipt_target = new_chain
        self.tmp_queue.append(r_jump)

        # Return rule: keep only osrc objects, clear everything else
        r_return = rule.clone()
        r_return.odst = []
        r_return.osrv = []
        r_return.tsrc = []
        r_return.tdst = []
        r_return.tsrv = []
        r_return.set_neg('odst', False)
        r_return.set_neg('osrv', False)
        r_return.nat_rule_type = NATRuleType.Return
        r_return.ipt_target = 'RETURN'
        r_return.ipt_chain = new_chain
        r_return.nat_iface_in = 'nil'
        r_return.nat_iface_out = 'nil'
        r_return.set_option('rule_added_for_osrc_neg', True)
        self.tmp_queue.append(r_return)

        # Action rule: clear osrc, odst; keep osrv and translated objects
        r_action = rule.clone()
        r_action.osrc = []
        r_action.odst = []
        r_action.set_neg('odst', False)
        r_action.set_neg('osrv', False)
        r_action.ipt_chain = new_chain
        r_action.nat_iface_in = 'nil'
        r_action.nat_iface_out = 'nil'
        r_action.set_option('rule_added_for_osrc_neg', True)
        self.tmp_queue.append(r_action)

        return True


class DoODstNegation(NATRuleProcessor):
    """Handle multi-object negation in ODst via temp chain with RETURN rules.

    Corresponds to C++ NATCompiler_ipt::doODstNegation.

    Pattern:
      CHAIN      A    !B   C    TYPE     TARGET
      -----      A   any   C    (same)   TMP_CHAIN
      TMP_CHAIN any    B  any   RETURN   RETURN
      TMP_CHAIN any  any   C    (same)   (original)
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('odst'):
            self.tmp_queue.append(rule)
            return True

        rule.set_neg('odst', False)

        new_chain = self.compiler.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except odst -> jump to temp chain
        r_jump = rule.clone()
        r_jump.odst = []
        r_jump.ipt_target = new_chain
        r_jump.set_option('rule_added_for_odst_neg', True)
        self.tmp_queue.append(r_jump)

        # Return rule: keep only odst objects, clear everything else
        r_return = rule.clone()
        r_return.osrc = []
        r_return.osrv = []
        r_return.tsrc = []
        r_return.tdst = []
        r_return.tsrv = []
        r_return.set_neg('osrc', False)
        r_return.set_neg('osrv', False)
        r_return.nat_rule_type = NATRuleType.Return
        r_return.ipt_target = 'RETURN'
        r_return.ipt_chain = new_chain
        r_return.nat_iface_in = 'nil'
        r_return.nat_iface_out = 'nil'
        self.tmp_queue.append(r_return)

        # Action rule: clear osrc, odst; keep osrv
        r_action = rule.clone()
        r_action.osrc = []
        r_action.odst = []
        r_action.set_neg('osrc', False)
        r_action.set_neg('osrv', False)
        r_action.ipt_chain = new_chain
        r_action.nat_iface_in = 'nil'
        r_action.nat_iface_out = 'nil'
        r_action.set_option('rule_added_for_odst_neg', True)
        self.tmp_queue.append(r_action)

        return True


class DoOSrvNegation(NATRuleProcessor):
    """Handle multi-object negation in OSrv via temp chain with RETURN rules.

    Corresponds to C++ NATCompiler_ipt::doOSrvNegation.

    Pattern:
      CHAIN      A    B   !C    TYPE     TARGET
      -----      A    B   any   (same)   TMP_CHAIN
      TMP_CHAIN any  any   C    RETURN   RETURN
      TMP_CHAIN any  any  any   (same)   (original)
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.get_neg('osrv'):
            self.tmp_queue.append(rule)
            return True

        rule.set_neg('osrv', False)

        new_chain = self.compiler.get_new_tmp_chain_name(rule)

        # Jump rule: keep everything except osrv -> jump to temp chain
        r_jump = rule.clone()
        r_jump.osrv = []
        r_jump.ipt_target = new_chain
        r_jump.set_option('rule_added_for_osrv_neg', True)
        self.tmp_queue.append(r_jump)

        # Return rule: keep only osrv objects, clear everything else
        r_return = rule.clone()
        r_return.osrc = []
        r_return.odst = []
        r_return.tsrc = []
        r_return.tdst = []
        r_return.set_neg('osrc', False)
        r_return.set_neg('odst', False)
        r_return.nat_rule_type = NATRuleType.Return
        r_return.ipt_target = 'RETURN'
        r_return.ipt_chain = new_chain
        r_return.nat_iface_in = 'nil'
        r_return.nat_iface_out = 'nil'
        r_return.set_option('rule_added_for_osrv_neg', True)
        self.tmp_queue.append(r_return)

        # Action rule: clear everything except translated objects
        r_action = rule.clone()
        r_action.osrc = []
        r_action.odst = []
        r_action.osrv = []
        r_action.set_neg('osrc', False)
        r_action.set_neg('odst', False)
        r_action.ipt_chain = new_chain
        r_action.nat_iface_in = 'nil'
        r_action.nat_iface_out = 'nil'
        self.tmp_queue.append(r_action)

        return True


class SplitOnODst(NATRuleProcessor):
    """Split DNAT rules with multiple ODst objects into separate rules.

    Corresponds to C++ NATCompiler_ipt::splitOnODst.
    Called after negation processing to ensure each DNAT rule has
    at most one object in ODst.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type == NATRuleType.DNAT and len(rule.odst) > 1:
            for obj in rule.odst:
                r = rule.clone()
                r.odst = [obj]
                self.tmp_queue.append(r)
        else:
            self.tmp_queue.append(rule)

        return True


class SplitSDNATRule(NATRuleProcessor):
    """Split SDNAT rules into separate DNAT + SNAT rules.

    Corresponds to C++ NATCompiler_ipt::splitSDNATRule.
    The first rule translates destination (clears TSrc), the second
    rule translates source (uses TDst values in ODst, clears TDst).
    Both get type Unknown for reclassification.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type != NATRuleType.SDNAT:
            self.tmp_queue.append(rule)
            return True

        # Determine service translation directions
        tsrv_translates_src_port = False
        tsrv_translates_dst_port = False

        osrv_obj = rule.osrv[0] if rule.osrv else None
        tsrv_obj = rule.tsrv[0] if rule.tsrv else None

        if isinstance(osrv_obj, TCPUDPService) and isinstance(tsrv_obj, TCPUDPService):
            tsrv_translates_src_port = (tsrv_obj.src_range_start or 0) != 0 and (
                tsrv_obj.dst_range_start or 0
            ) == 0
            tsrv_translates_dst_port = (tsrv_obj.src_range_start or 0) == 0 and (
                tsrv_obj.dst_range_start or 0
            ) != 0

            if tsrv_translates_dst_port and (
                (osrv_obj.dst_range_start or 0) == (tsrv_obj.dst_range_start or 0)
                and (osrv_obj.dst_range_end or 0) == (tsrv_obj.dst_range_end or 0)
            ):
                tsrv_translates_dst_port = False

            if tsrv_translates_src_port and (
                (osrv_obj.src_range_start or 0) == (tsrv_obj.src_range_start or 0)
                and (osrv_obj.src_range_end or 0) == (tsrv_obj.src_range_end or 0)
            ):
                tsrv_translates_src_port = False

        # First rule: translates destination, type Unknown for reclassification
        r_dnat = rule.clone()
        r_dnat.nat_rule_type = NATRuleType.Unknown
        r_dnat.tsrc = []
        if tsrv_translates_src_port:
            r_dnat.tsrv = []
        self.tmp_queue.append(r_dnat)

        # Second rule: translates source, uses TDst in ODst
        r_snat = rule.clone()
        r_snat.nat_rule_type = NATRuleType.Unknown

        # Clear ODst negation in second rule (handled by first)
        r_snat.set_neg('odst', False)

        # ODst = original TDst (translated destination becomes match for SNAT)
        r_snat.odst = list(rule.tdst)

        # If TSrv translated dst port, match it in OSrv of second rule.
        # Only the destination half of it: the first rule is a destination
        # translation and cannot have written a source port, so matching on
        # one would leave the source untranslated.
        if (
            tsrv_obj
            and not rule.is_tsrv_any()
            and isinstance(tsrv_obj, TCPUDPService)
            and (tsrv_obj.dst_range_start or 0) != 0
        ):
            r_snat.osrv = [destination_port_half(tsrv_obj)]

        r_snat.tdst = []
        if tsrv_translates_dst_port:
            r_snat.tsrv = []
        self.tmp_queue.append(r_snat)

        return True


class SplitNATBranchRule(NATRuleProcessor):
    """Split NATBranch rules into separate copies for each chain.

    Corresponds to C++ NATCompiler_ipt::splitNATBranchRule.
    Branch rules need to go into both PREROUTING and POSTROUTING
    chains since the branch may contain both DNAT and SNAT rules.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type != NATRuleType.NATBranch:
            self.tmp_queue.append(rule)
            return True

        nat_comp = cast('NATCompiler_ipt', self.compiler)
        branch_name = rule.get_option('branch_name', '')

        if not branch_name:
            # The C++ sets `ipt_chain` to PREROUTING and `ipt_target` to
            # "UNDEFINED" behind its abort() and says why in a comment:
            # "in case we are in the test mode and abort() does not really
            # abort.  Both the chain and the target are bogus"
            # (NATCompiler_ipt.cpp:1886).  In normal operation abort()
            # throws and no script comes out at all, which is why the gold
            # for firewall2-4 has neither `-N UNDEFINED` nor the jump.
            # fwf's abort() only reports, so copying those two lines put a
            # jump into an empty chain named UNDEFINED into the nat table:
            # the rule translates nothing, and the activation says it
            # succeeded.  The nftables compiler reports the same rule and
            # leaves it out.
            self.compiler.abort(rule, 'NAT branching rule misses branch rule set.')
            return True

        # Check if we have branch chain mapping info
        if nat_comp.branch_ruleset_to_chain_mapping is not None:
            chains = nat_comp.branch_ruleset_to_chain_mapping.get(branch_name)
            if chains is not None:
                for branch_chain in chains:
                    if branch_chain.startswith(branch_name + '_'):
                        my_chain = branch_chain[len(branch_name) + 1 :]
                        # A branching rule that is itself part of a branch
                        # rule set belongs in that rule set's chain, not in
                        # the built-in one.  The C++ writes the bare chain
                        # here (NATCompiler_ipt.cpp:1838) and so installs
                        # the jump on all traffic; the fallback below has
                        # the prefix, so the two halves disagree.
                        if nat_comp.rule_set_chain:
                            my_chain = f'{nat_comp.rule_set_chain}_{my_chain}'
                            nat_comp.register_rule_set_chain(my_chain)
                        r = rule.clone()
                        r.ipt_chain = my_chain
                        r.ipt_target = branch_chain
                        self.tmp_queue.append(r)
                return True

        # Fallback: split into both PREROUTING and POSTROUTING
        self.compiler.warning(
            rule,
            'NAT branching rule does not have information'
            ' about targets used in the branch ruleset'
            ' to choose proper chain in the nat table.'
            ' Will split the rule and place it in both'
            ' PREROUTING and POSTROUTING',
        )

        rs_name = nat_comp.get_rule_set_name()
        prefix = f'{rs_name}_' if rs_name != 'NAT' else ''

        for prepost in ('PRE', 'POST'):
            r = rule.clone()
            new_chain = f'{prefix}{prepost}ROUTING'
            tgt_chain = f'{branch_name}_{prepost}ROUTING'
            nat_comp.register_rule_set_chain(new_chain)
            nat_comp.register_rule_set_chain(tgt_chain)
            r.ipt_chain = new_chain
            r.ipt_target = tgt_chain
            self.tmp_queue.append(r)

        return True


class ConvertLoadBalancingRules(NATRuleProcessor):
    """Fold the backends of a load-balancing NAT rule into one range.

    Ports ``NATCompiler_ipt::ConvertLoadBalancingRules``.  DNAT spreads
    connections over ``--to-destination first-last`` by hashing the source
    (``nf_nat_core.c``, ``find_best_ips_proto``), so the backends have to
    reach the target as a single address range.  Left as separate objects
    they become one DNAT rule each, and since DNAT terminates the first
    rule takes every connection.

    The addresses have to be contiguous for a range to mean the same
    thing, which is what the C++ checks with its temporary AddressRange's
    ``dimension() != 2``; a gap is reported rather than quietly widened
    to cover an address nobody named.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type != NATRuleType.LB:
            self.tmp_queue.append(rule)
            return True

        # The backends are usually Host objects, and only their addresses
        # can be sorted and checked for gaps.  fwbuilder gets this for free
        # because its Host derives from Address; here the expansion the
        # pipeline runs later has to happen first.  It is idempotent, so
        # `ExpandMultipleAddressesInNAT` still does the right thing after.
        self.compiler.expand_addr(rule, 'tdst')

        addresses = []
        for obj in rule.tdst:
            addr_str = getattr(obj, 'get_address', lambda: '')() or ''
            try:
                addresses.append(ipaddress.ip_address(addr_str))
            except ValueError:
                self.compiler.abort(
                    rule,
                    f'Translated Destination of a load balancing NAT rule '
                    f'holds "{getattr(obj, "name", obj)}", which is not a '
                    f'single address',
                )
                return True

        addresses.sort()
        for previous, current in itertools.pairwise(addresses):
            if int(current) - int(previous) != 1:
                self.compiler.abort(
                    rule,
                    'Non-contiguous address range in '
                    'Translated Destination in load balancing NAT rule',
                )
                return True

        first, last = addresses[0], addresses[-1]
        stand_in = AddressRange(
            id=uuid.uuid4(),
            name=f'%{first}-{last}%',
        )
        stand_in.start_address = {'address': str(first)}
        stand_in.end_address = {'address': str(last)}
        rule.tdst = [stand_in]
        rule.nat_rule_type = NATRuleType.DNAT
        self.tmp_queue.append(rule)
        return True


class VerifyRules2(NATRuleProcessor):
    """Verify OSrv/TSrv consistency after groupServicesByProtocol.

    Corresponds to C++ NATCompiler_ipt::VerifyRules2.
    Checks that TSrv is not set when OSrv is 'Any', and that
    TSrv protocol matches OSrv protocol.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type != NATRuleType.Return:
            osrv_any = not rule.osrv
            tsrv_any = not rule.tsrv

            if osrv_any and not tsrv_any:
                self.compiler.abort(
                    rule,
                    'Can not use service object in Translated Service '
                    "if Original Service is 'Any'.",
                )
                return True

            if not tsrv_any:
                s1 = rule.osrv[0] if rule.osrv else None
                s2 = rule.tsrv[0] if rule.tsrv else None
                if s1 is not None and s2 is not None:
                    p1 = getattr(s1, 'get_protocol_name', lambda: '')()
                    p2 = getattr(s2, 'get_protocol_name', lambda: '')()
                    if p1 and p2 and p1 != p2:
                        self.compiler.abort(
                            rule,
                            'Translated Service should be either '
                            "'Original' or should contain object of the "
                            'same type as Original Service.',
                        )
                        return True

        self.tmp_queue.append(rule)
        return True


class VerifyRules3(NATRuleProcessor):
    """Verify interface specification is compatible with the chosen chain.

    Corresponds to C++ NATCompiler_ipt::VerifyRules3, which asks the rule
    type instead of the chain and so only covers a plain SNAT and DNAT.  A
    masquerading, a netmap and a redirect rule land in the very same chains
    and a NONAT rule is split into a copy for each of them, and iptables
    refuses ``-i`` in POSTROUTING and ``-o`` in PREROUTING for all of them
    alike.  Asking the chain the rule ended up in covers every type.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # A rule moved into a helper chain matches its interface in the
        # rule that jumps there, not in the chain itself.
        problem = nat_interface_problem(
            rule.ipt_chain or '',
            has_itf_inb=bool(rule.itf_inb) and rule.nat_iface_in != 'nil',
            has_itf_outb=bool(rule.itf_outb) and rule.nat_iface_out != 'nil',
            iif_in_postrouting=bridge_port_matches_inbound_in_postrouting(
                self.compiler, rule.itf_inb[0] if rule.itf_inb else None
            ),
        )
        if problem:
            self.compiler.abort(rule, f'Rule {problem}; the rule is left out')
            return True

        self.tmp_queue.append(rule)
        return True


class SplitODstForSNAT(NATRuleProcessor):
    """Split SNAT rules where ODst objects belong to different subnets.

    Corresponds to C++ NATCompiler::splitODstForSNAT.
    Groups ODst objects by the firewall interface they belong to
    and creates separate rules for each group.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type != NATRuleType.SNAT:
            self.tmp_queue.append(rule)
            return True

        if not rule.odst or len(rule.odst) <= 1:
            self.tmp_queue.append(rule)
            return True

        # Group by interface
        groups: dict[str, list] = {}
        for obj in rule.odst:
            iface = self.compiler.find_interface_for(obj, self.compiler.fw)
            iid = str(iface.id) if iface is not None else ''
            groups.setdefault(iid, []).append(obj)

        if len(groups) <= 1:
            self.tmp_queue.append(rule)
            return True

        for obj_list in groups.values():
            r = rule.clone()
            r.odst = obj_list
            self.tmp_queue.append(r)

        return True


class SplitOnDynamicInterfaceInODst(NATRuleProcessor):
    """Split rule if ODst contains dynamic interfaces among other objects.

    Corresponds to C++ NATCompiler_ipt::splitOnDynamicInterfaceInODst
    (via splitRuleIfRuleElementIsDynamicInterface).
    Dynamic interfaces are pulled out into separate rules because
    their addresses are resolved at runtime.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.odst) <= 1:
            self.tmp_queue.append(rule)
            return True

        dynamic = []
        regular = []
        for obj in rule.odst:
            if isinstance(obj, Interface) and not obj.is_regular():
                dynamic.append(obj)
            else:
                regular.append(obj)

        if not dynamic:
            self.tmp_queue.append(rule)
            return True

        # Create separate rules for each dynamic interface
        for iface in dynamic:
            r = rule.clone()
            r.odst = [iface]
            self.tmp_queue.append(r)

        # Keep regular objects in the original rule
        rule.odst = regular
        self.tmp_queue.append(rule)

        return True


class SplitOnDynamicInterfaceInTSrc(NATRuleProcessor):
    """Split rule if TSrc contains dynamic interfaces among other objects.

    Corresponds to C++ NATCompiler_ipt::splitOnDynamicInterfaceInTSrc
    (via splitRuleIfRuleElementIsDynamicInterface).
    Dynamic interfaces are pulled out into separate rules because
    their addresses are resolved at runtime.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.tsrc) <= 1:
            self.tmp_queue.append(rule)
            return True

        dynamic = []
        regular = []
        for obj in rule.tsrc:
            if isinstance(obj, Interface) and not obj.is_regular():
                dynamic.append(obj)
            else:
                regular.append(obj)

        if not dynamic:
            self.tmp_queue.append(rule)
            return True

        # Create separate rules for each dynamic interface
        for iface in dynamic:
            r = rule.clone()
            r.tsrc = [iface]
            self.tmp_queue.append(r)

        # Keep regular objects in the original rule
        rule.tsrc = regular
        self.tmp_queue.append(rule)

        return True


class DynamicInterfaceInODst(NATRuleProcessor):
    """Name the member's own interface where the rule names the cluster's.

    Ports ``NATCompiler_ipt::dynamicInterfaceInODst``
    (NATCompiler_ipt.cpp:1269).  A dynamic cluster interface has no
    address at compile time and none at run time either - it exists on no
    machine - so the generated script would look up a device that is not
    there and translate to nothing.  The interface the member firewall
    actually has is what the failover group names.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if not rule.odst:
            return True

        odst = rule.odst[0]
        if (
            isinstance(odst, Interface)
            and odst.is_dynamic()
            and odst.is_failover_interface()
        ):
            rule.odst = [self.compiler.correct_for_cluster(odst), *rule.odst[1:]]

        return True


class DynamicInterfaceInTSrc(NATRuleProcessor):
    """Convert SNAT to Masquerade if TSrc is a dynamic interface.

    Corresponds to C++ NATCompiler_ipt::dynamicInterfaceInTSrc.
    If TSrc is a non-regular (dynamic) interface and the rule option
    ``ipt_use_snat_instead_of_masq`` is not set, convert the SNAT
    rule to Masquerade.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        if not rule.tsrc:
            return True

        tsrc = rule.tsrc[0]

        if (
            rule.nat_rule_type == NATRuleType.SNAT
            and isinstance(tsrc, Interface)
            and not tsrc.is_regular()
        ):
            # A cluster interface stands for the member's own one here
            # too, and for the same reason: the script reads the address
            # off the running device.
            if tsrc.is_failover_interface():
                tsrc = self.compiler.correct_for_cluster(tsrc)
                rule.tsrc = [tsrc, *rule.tsrc[1:]]
            use_snat = rule.get_option('ipt_use_snat_instead_of_masq', False)
            if not use_snat:
                rule.nat_rule_type = NATRuleType.Masq
                if not rule.ipt_target or rule.ipt_target == 'SNAT':
                    rule.ipt_target = 'MASQUERADE'

        return True


class AlwaysUseMasquerade(NATRuleProcessor):
    """Convert SNAT to Masquerade if the rule option requests it.

    Corresponds to C++ NATCompiler_ipt::alwaysUseMasquerading.
    If the rule option ``ipt_use_masq`` is set and the rule is SNAT,
    convert to Masquerade target.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        use_masq = rule.get_option('ipt_use_masq', False)
        if use_masq and rule.nat_rule_type == NATRuleType.SNAT:
            rule.nat_rule_type = NATRuleType.Masq
            if not rule.ipt_target or rule.ipt_target == 'SNAT':
                rule.ipt_target = 'MASQUERADE'

        return True


class SplitMultiSrcAndDst(NATRuleProcessor):
    """Optimize rules with multiple OSrc AND multiple ODst.

    Corresponds to C++ NATCompiler_ipt::splitMultiSrcAndDst.
    Creates a temp chain: a jump rule matches the smaller dimension
    (src or dst), and the action rule in the temp chain matches the
    other dimension.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nosrv = len(rule.osrv)
        nosrc = len(rule.osrc)
        nodst = len(rule.odst)

        # Only split if osrv is any, both osrc and odst have objects,
        # and we have multiple objects to split.
        if (
            (nosrv > 1 or rule.osrv)
            or (nosrc < 1 or not rule.osrc)
            or (nodst < 1 or not rule.odst)
            or (nosrc == 1 and nodst == 1)
        ):
            self.tmp_queue.append(rule)
            return True

        if rule.nat_rule_type not in (
            NATRuleType.NONAT,
            NATRuleType.SNAT,
            NATRuleType.DNAT,
        ):
            self.tmp_queue.append(rule)
            return True

        new_chain = self.compiler.get_new_tmp_chain_name(rule)

        # Create jump rule pointing to temp chain
        r_jump = rule.clone()

        # Move the original rule to the temp chain
        rule.ipt_chain = new_chain
        rule.nat_iface_in = 'nil'
        rule.nat_iface_out = 'nil'

        # Decide which dimension to keep in the jump rule
        if nosrc < nodst:
            # Jump rule keeps osrc, clears odst
            r_jump.odst = []
            # Action rule keeps odst, clears osrc
            rule.osrc = []
        else:
            # Jump rule keeps odst, clears osrc
            r_jump.osrc = []
            # Action rule keeps osrc, clears odst
            rule.odst = []

        r_jump.ipt_target = new_chain

        self.tmp_queue.append(r_jump)
        self.tmp_queue.append(rule)

        return True


class SplitMultipleICMP(NATRuleProcessor):
    """Split rules with multiple ICMP services into individual rules.

    Corresponds to C++ NATCompiler_ipt::splitMultipleICMP.
    ICMP services cannot be combined in multiport matching, so
    each ICMP service gets its own rule.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrv) <= 1:
            self.tmp_queue.append(rule)
            return True

        first_srv = rule.osrv[0]
        if not isinstance(first_srv, ICMPService | ICMP6Service):
            self.tmp_queue.append(rule)
            return True

        for srv in rule.osrv:
            r = rule.clone()
            r.osrv = [srv]
            self.tmp_queue.append(r)

        return True


class ConvertToAtomicForOSrv(NATRuleProcessor):
    """Split rules with multiple OSrv when TSrv is not 'any'.

    Corresponds to C++ NATCompiler_ipt::convertToAtomicportForOSrv.
    When TSrv specifies a translation and OSrv has multiple services,
    each service must be in its own rule to pair with TSrv correctly.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrv) > 1 and rule.tsrv:
            for srv in rule.osrv:
                r = rule.clone()
                r.osrv = [srv]
                self.tmp_queue.append(r)
        else:
            self.tmp_queue.append(rule)

        return True


class ConvertToAtomicForItfInb(NATRuleProcessor):
    """Split rules with multiple inbound interfaces into separate rules.

    Corresponds to C++ NATCompiler::ConvertToAtomicForItfInb.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.itf_inb) <= 1:
            self.tmp_queue.append(rule)
            return True

        for itf_obj in rule.itf_inb:
            r = rule.clone()
            r.itf_inb = [itf_obj]
            self.tmp_queue.append(r)

        return True


class ConvertToAtomicForItfOutb(NATRuleProcessor):
    """Split rules with multiple outbound interfaces into separate rules.

    Corresponds to C++ NATCompiler::ConvertToAtomicForItfOutb.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.itf_outb) <= 1:
            self.tmp_queue.append(rule)
            return True

        for itf_obj in rule.itf_outb:
            r = rule.clone()
            r.itf_outb = [itf_obj]
            self.tmp_queue.append(r)

        return True
