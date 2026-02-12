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

from collections import defaultdict
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._nat_compiler import NATCompiler
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    DropIPv4Rules,
    DropIPv6Rules,
    EmptyGroupsInRE,
    ExpandGroups,
    SimplePrintProgress,
)
from firewallfabrik.core.objects import (
    Address,
    Firewall,
    Host,
    Interface,
    NATAction,
    NATRuleType,
    Network,
    NetworkIPv6,
    TCPService,
    TCPUDPService,
    UDPService,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator


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


# Module-level temp chain counter
_tmp_chain_no: dict[str, int] = {}

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

        self.have_dynamic_interfaces: bool = False
        self.minus_n_commands: dict[str, bool] | None = minus_n_commands

        # Chain management
        self.chain_usage_counter: dict[str, int] = defaultdict(int)

        # Print rule processor reference
        self.print_rule_processor: NATRuleProcessor | None = None

        # iptables version
        self.version: str = fw.version or ''

        # ipset usage flag
        self.using_ipset: bool = False
        if _version_compare(self.version, '1.4.1.1') >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set', False))

    @staticmethod
    def get_standard_chains() -> list[str]:
        return STANDARD_NAT_CHAINS

    def my_platform_name(self) -> str:
        return 'iptables'

    @staticmethod
    def get_new_tmp_chain_name(rule: CompRule) -> str:
        """Generate a unique temporary chain name for a rule."""
        global _tmp_chain_no
        chain_id = str(rule.id).replace('-', '')[:12]
        n = _tmp_chain_no.get(chain_id, 0)
        name = f'C{chain_id}.{n}'
        _tmp_chain_no[chain_id] = n + 1
        return name

    def register_rule_set_chain(self, chain_name: str) -> None:
        self.chain_usage_counter[chain_name] = 1

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

        if n > 0:
            for iface in self.fw.interfaces:
                if iface.is_dynamic():
                    self.have_dynamic_interfaces = True

        return n

    def compile(self) -> None:
        banner = f" Compiling ruleset {self.get_rule_set_name()} for 'nat' table"
        if self.ipv6_policy:
            banner += ', IPv6'
        self.info(banner)

        super().compile()

        self.add(Begin())

        self.add(
            SingleObjectNegationItfInb('process single object negation in inbound Itf')
        )
        self.add(
            SingleObjectNegationItfOutb(
                'process single object negation in outbound Itf'
            )
        )

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

        self.add(ClassifyNATRule('classify NAT rule'))
        self.add(VerifyRules('verify rules'))

        self.add(SingleObjectNegationOSrc('negation in OSrc if it holds single object'))
        self.add(SingleObjectNegationODst('negation in ODst if it holds single object'))

        self.add(PortTranslationRules('port translation rules'))
        self.add(
            SpecialCaseWithRedirect(
                'special case with redirecting port translation rules'
            )
        )

        if self.fw.get_option('local_nat', False):
            if self.fw.get_option('firewall_is_part_of_any_and_networks', False):
                self.add(SplitIfOSrcAny('split rule if OSrc is any'))
            self.add(SplitIfOSrcMatchesFw('split rule if OSrc matches FW'))

        self.add(SplitNONATRule('NAT rules that request no translation'))
        self.add(LocalNATRule('local NAT rule'))
        self.add(DecideOnChain('decide on chain'))
        self.add(DecideOnTarget('decide on target'))

        self.add(ReplaceFirewallObjectsODst('replace firewall in ODst'))
        self.add(ReplaceFirewallObjectsTSrc('replace firewall in TSrc'))
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))

        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        self.add(GroupServicesByProtocol('group services by protocol'))
        self.add(SeparatePortRanges('separate port ranges'))
        self.add(PrepareForMultiport('prepare for multiport'))
        self.add(ConvertToAtomicForAddresses('convert to atomic rules'))
        self.add(AssignInterface('assign rules to interfaces'))

        self.add(CountChainUsage('Count chain usage'))

        # Print rule
        from firewallfabrik.platforms.iptables._nat_print_rule import (
            NATPrintRule,
            NATPrintRuleIptRstEcho,
        )

        if self.fw.get_option('use_iptables_restore', False):
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
            self.fw.get_option('use_iptables_restore', False)
            and self.get_compiled_script_length() > 0
            and not self.single_rule_compile_mode
        ):
            self.output.write('#\n')

    def flush_and_set_default_policy(self) -> str:
        if not self.fw.get_option('use_iptables_restore', False):
            return ''
        if self.single_rule_compile_mode:
            return ''
        return (
            'echo :PREROUTING ACCEPT [0:0]\n'
            'echo :POSTROUTING ACCEPT [0:0]\n'
            'echo :OUTPUT ACCEPT [0:0]\n'
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


class _PassthroughNAT(NATRuleProcessor):
    """Base for processors that pass rules through (stub)."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
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


class SingleObjectNegationOSrc(NATRuleProcessor):
    """Handle single-object negation for OSrc in NAT rules.

    If OSrc has negation and contains exactly one address object with
    a single IP that doesn't match the firewall, convert to inline
    '!' negation.

    Corresponds to C++ NATCompiler::singleObjectNegationOSrc.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('osrc') and len(rule.osrc) == 1:
            obj = rule.osrc[0]
            if isinstance(obj, Address) and not self.compiler.complex_match(
                obj, self.compiler.fw
            ):
                rule.osrc_single_object_negation = True
                rule.set_neg('osrc', False)
        self.tmp_queue.append(rule)
        return True


class SingleObjectNegationODst(NATRuleProcessor):
    """Handle single-object negation for ODst in NAT rules.

    If ODst has negation and contains exactly one address object with
    a single IP that doesn't match the firewall, convert to inline
    '!' negation.

    Corresponds to C++ NATCompiler::singleObjectNegationODst.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('odst') and len(rule.odst) == 1:
            obj = rule.odst[0]
            if isinstance(obj, Address) and not self.compiler.complex_match(
                obj, self.compiler.fw
            ):
                rule.odst_single_object_negation = True
                rule.set_neg('odst', False)
        self.tmp_queue.append(rule)
        return True


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

        # Branch action
        if rule.action == NATAction.Branch:
            rule.nat_rule_type = NATRuleType.NATBranch
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


class VerifyRules(NATRuleProcessor):
    """Verify correctness of NAT rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_neg('tsrc'):
            self.compiler.abort('Can not use negation in translated source')
            return True

        if rule.get_neg('tdst'):
            self.compiler.abort('Can not use negation in translated destination')
            return True

        if rule.get_neg('tsrv'):
            self.compiler.abort('Can not use negation in translated service')
            return True

        self.tmp_queue.append(rule)
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
            if isinstance(tdst, Firewall) and tdst.id == self.compiler.fw.id:
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
        if isinstance(odst, Firewall) and odst.id == self.compiler.fw.id:
            interfaces = [
                iface
                for iface in self.compiler.fw.interfaces
                if not iface.is_loopback()
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

    @staticmethod
    def _find_interface_for(addr_obj, fw) -> Interface | None:
        """Find the firewall interface on the same network as *addr_obj*."""
        import ipaddress

        target_addr_str = None
        if isinstance(addr_obj, Address):
            target_addr_str = addr_obj.get_address()
        elif isinstance(addr_obj, Interface) and addr_obj.addresses:
            target_addr_str = addr_obj.addresses[0].get_address()

        if not target_addr_str:
            return None

        try:
            target_ip = ipaddress.ip_address(target_addr_str)
        except (ValueError, TypeError):
            return None

        for iface in fw.interfaces:
            if not iface.is_regular():
                continue
            for addr in iface.addresses:
                addr_str = addr.get_address()
                mask_str = addr.get_netmask()
                if not addr_str or not mask_str:
                    continue
                try:
                    network = ipaddress.ip_network(
                        f'{addr_str}/{mask_str}', strict=False
                    )
                    if target_ip in network:
                        return iface
                except (ValueError, TypeError):
                    continue

        return None

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
        if not (isinstance(tsrc, Firewall) and tsrc.id == self.compiler.fw.id):
            return True

        # TSrc is the firewall — replace with the interface facing ODst
        odst = rule.odst[0] if rule.odst else None
        osrc = rule.osrc[0] if rule.osrc else None

        odst_iface = self._find_interface_for(odst, self.compiler.fw) if odst else None
        osrc_iface = self._find_interface_for(osrc, self.compiler.fw) if osrc else None

        # When ODst has single_object_negation, skip the direct match
        # and fall through to the fallback (excluding odst_iface).
        if odst_iface is not None and not rule.odst_single_object_negation:
            rule.tsrc = [odst_iface]
            return True

        # Fallback: use all non-loopback, non-unnumbered, non-bridge interfaces,
        # excluding the interface facing OSrc (per C++ logic).
        # Also exclude odst_iface when single_object_negation is set.
        interfaces = [
            iface
            for iface in self.compiler.fw.interfaces
            if not iface.is_loopback()
            and not iface.is_unnumbered()
            and not iface.is_bridge_port()
            and not (osrc_iface and iface.id == osrc_iface.id)
            and not (
                rule.odst_single_object_negation
                and odst_iface
                and iface.id == odst_iface.id
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

        if rule.ipt_chain:
            return True

        rt = rule.nat_rule_type
        if rt is not None:
            chain = chain_map.get(rt, '')
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


class ExpandMultipleAddresses(NATRuleProcessor):
    """Expand hosts/firewalls/interfaces into their addresses.

    Corresponds to C++ NATCompiler::ExpandMultipleAddresses.
    Replaces Host/Firewall/Interface objects in element lists with
    their Address objects, then sorts by address.  The expansion
    varies by rule type: 'expand_fully' means Host/Firewall expand
    through interfaces to addresses; otherwise the element is kept
    as-is.
    """

    @staticmethod
    def _expand_slot(objects: list) -> list:
        """Expand a single element list, replacing composite objects.

        Host/Firewall objects are expanded through their interfaces to
        addresses.  Interface objects are expanded to their addresses
        (unless dynamic).  Loopback interfaces are skipped when
        expanding from a parent Host/Firewall.
        """
        result = []
        for obj in objects:
            if isinstance(obj, Interface):
                if obj.is_dynamic():
                    result.append(obj)
                elif obj.is_loopback():
                    continue
                else:
                    for addr in obj.addresses:
                        result.append(addr)
            elif isinstance(obj, Host):
                for iface in getattr(obj, 'interfaces', []):
                    if iface.is_loopback():
                        continue
                    if iface.is_dynamic():
                        result.append(iface)
                    else:
                        for addr in iface.addresses:
                            result.append(addr)
            else:
                result.append(obj)

        # Sort by address for deterministic output
        def _sort_key(o):
            addr = getattr(o, 'get_address', lambda: None)()
            if addr is not None:
                import ipaddress as _ipa

                try:
                    return _ipa.ip_address(addr).packed
                except (ValueError, TypeError):
                    pass
            return b'\xff' * 16

        result.sort(key=_sort_key)
        return result

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        rt = rule.nat_rule_type
        if rt in (NATRuleType.NONAT, NATRuleType.Return):
            rule.osrc = self._expand_slot(rule.osrc)
            rule.odst = self._expand_slot(rule.odst)
        elif rt in (NATRuleType.SNAT, NATRuleType.SDNAT) or rt == NATRuleType.DNAT:
            rule.osrc = self._expand_slot(rule.osrc)
            rule.odst = self._expand_slot(rule.odst)
            rule.tsrc = self._expand_slot(rule.tsrc)
            rule.tdst = self._expand_slot(rule.tdst)
        elif rt == NATRuleType.Redirect:
            rule.osrc = self._expand_slot(rule.osrc)
            rule.odst = self._expand_slot(rule.odst)
            rule.tsrc = self._expand_slot(rule.tsrc)

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
    Also splits into chunks of 15 if needed (iptables multiport limit).
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrv) <= 1:
            self.tmp_queue.append(rule)
            return True

        # Only set multiport for TCP/UDP services
        first_srv = rule.osrv[0]
        if not isinstance(first_srv, TCPService | UDPService):
            self.tmp_queue.append(rule)
            return True

        rule.ipt_multiport = True

        if len(rule.osrv) > 15:
            # Split into chunks of 15
            for i in range(0, len(rule.osrv), 15):
                chunk = rule.osrv[i : i + 15]
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
        tsrc = rule.tsrc[0] if rule.tsrc else None
        if tsrc is None:
            self.tmp_queue.append(rule)
            return True

        iface = None
        if isinstance(tsrc, Interface):
            iface = tsrc
        elif isinstance(tsrc, Address) and tsrc.interface is not None:
            iface = tsrc.interface

        if iface is not None and iface.device_id == self.compiler.fw.id:
            rule.itf_outb = [iface]
            self.tmp_queue.append(rule)
            return True

        # TSrc not tied to a firewall interface — assign to each
        # regular (non-loopback) interface
        n = 0
        for iface in self.compiler.fw.interfaces:
            if iface.is_loopback():
                continue
            r = rule.clone()
            r.itf_outb = [iface]
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


class CountChainUsage(NATRuleProcessor):
    """Count chain usage for all rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        chain = rule.ipt_chain
        if chain:
            nat_comp = cast('NATCompiler_ipt', self.compiler)
            nat_comp.chain_usage_counter[chain] = (
                nat_comp.chain_usage_counter.get(chain, 0) + 1
            )
        self.tmp_queue.append(rule)
        return True
