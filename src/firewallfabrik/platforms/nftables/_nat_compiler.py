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

"""NATCompiler_nft: nftables NAT rule compilation.

Compiles NAT rules into nftables NAT chain rules.
Unlike iptables, nftables NAT is simpler:
- Uses `snat to`, `dnat to`, `masquerade` inline
- No separate SNAT/DNAT/MASQUERADE targets
- No -t nat table flag needed (tables are user-defined)
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._nat_compiler import NATCompiler
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    DropIPv4Rules,
    DropIPv6Rules,
    EmptyGroupsInRE,
    ExpandGroups,
    ResolveMultiAddress,
    SimplePrintProgress,
)
from firewallfabrik.core.objects import (
    Address,
    Firewall,
    Interface,
    NATAction,
    NATRuleType,
    Network,
    NetworkIPv6,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator


class NATCompiler_nft(NATCompiler):
    """nftables NAT compiler."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
        oscnf: OSConfigurator | None = None,
    ) -> None:
        super().__init__(session, fw, ipv6_policy)
        self.oscnf = oscnf
        self.have_dynamic_interfaces: bool = False

        # Per-chain rule collection for nftables output assembly
        self.chain_rules: dict[str, list[str]] = {
            'prerouting': [],
            'postrouting': [],
            'output': [],
        }

    def my_platform_name(self) -> str:
        return 'nftables'

    def get_rule_set_name(self) -> str:
        if self.source_ruleset:
            return self.source_ruleset.name
        return 'NAT'

    def prolog(self) -> int:
        n = super().prolog()

        if n > 0:
            for iface in self.fw.interfaces:
                if iface.is_dynamic():
                    self.have_dynamic_interfaces = True

        return n

    def compile(self) -> None:
        banner = f' Compiling NAT ruleset {self.get_rule_set_name()} for nftables'
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

        self.add(ResolveMultiAddress('resolve compile-time MultiAddress'))

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

        if self.fw.opt_local_nat:
            if self.fw.opt_firewall_is_part_of_any_and_networks:
                self.add(SplitIfOSrcAny('split rule if OSrc is any'))
            self.add(SplitIfOSrcMatchesFw('split rule if OSrc matches FW'))

        self.add(LocalNATRule('local NAT rule'))
        self.add(DecideOnChain('decide on chain'))

        self.add(ReplaceFirewallObjectsTSrc('replace firewall in TSrc'))
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))

        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        self.add(GroupServicesByProtocol('group services by protocol'))
        self.add(ConvertToAtomicForAddresses('convert to atomic rules'))
        self.add(AssignInterface('assign rules to interfaces'))

        # Print rule
        from firewallfabrik.platforms.nftables._nat_print_rule import NATPrintRule_nft

        pr = NATPrintRule_nft('generate nftables NAT rules')
        pr.set_context(self)
        pr.initialize()
        self.add(pr)

        self.add(SimplePrintProgress('print progress'))

        self.run_rule_processors()

    def epilog(self) -> None:
        pass


# -- Rule Processors --


class SingleObjectNegationItfInb(NATRuleProcessor):
    """Handle single-object negation for inbound interface in NAT rules.

    If the inbound interface element has negation and contains exactly
    one object, convert to inline '!=' negation.
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
    one object, convert to inline '!=' negation.
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


class _PassthroughNAT(NATRuleProcessor):
    """Base for processors that pass rules through."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)
        return True


class DropRuleWithEmptyRE(NATRuleProcessor):
    """Drop rules where a required rule element became empty."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

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
    """Classify NAT rule type based on TSrc/TDst/TSrv contents."""

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

        tsrc_any = tsrc is None
        tdst_any = tdst is None
        tsrv_any = tsrv is None

        if rule.action == NATAction.Branch:
            rule.nat_rule_type = NATRuleType.NATBranch
            return True

        if tsrc_any and tdst_any and tsrv_any:
            rule.nat_rule_type = NATRuleType.NONAT
            return True

        if not tsrc_any and tdst_any:
            if isinstance(tsrc, Network | NetworkIPv6):
                rule.nat_rule_type = NATRuleType.SNetnat
            else:
                rule.nat_rule_type = NATRuleType.SNAT
            return True

        if tsrc_any and not tdst_any:
            if isinstance(tdst, Network | NetworkIPv6):
                rule.nat_rule_type = NATRuleType.DNetnat
            elif isinstance(tdst, Firewall) and tdst.id == self.compiler.fw.id:
                rule.nat_rule_type = NATRuleType.Redirect
            else:
                rule.nat_rule_type = NATRuleType.DNAT
            return True

        if not tsrc_any and not tdst_any:
            rule.nat_rule_type = NATRuleType.SDNAT
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

        nat_comp = cast('NATCompiler_nft', self.compiler)
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
    """Assign output chain for DNAT/DNetnat/Redirect rules where OSrc matches FW.

    Corresponds to C++ NATCompiler_ipt::localNATRule.
    For DNAT/DNetnat/Redirect rules: if OSrc matches the firewall, set chain
    to output. If OSrc IS the firewall object itself, clear OSrc to "any".
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nat_comp = cast('NATCompiler_nft', self.compiler)

        if rule.nat_rule_type in (
            NATRuleType.DNAT,
            NATRuleType.DNetnat,
            NATRuleType.Redirect,
        ):
            osrc = rule.osrc[0] if rule.osrc else None
            if osrc is not None and nat_comp.complex_match(osrc, nat_comp.fw):
                rule.ipt_chain = 'output'
                if isinstance(osrc, Firewall) and osrc.id == nat_comp.fw.id:
                    rule.osrc = []

        self.tmp_queue.append(rule)
        return True


class DecideOnChain(NATRuleProcessor):
    """Assign rules to prerouting, postrouting, or output chains."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        chain_map = {
            NATRuleType.SNAT: 'postrouting',
            NATRuleType.SNetnat: 'postrouting',
            NATRuleType.Masq: 'postrouting',
            NATRuleType.DNAT: 'prerouting',
            NATRuleType.DNetnat: 'prerouting',
            NATRuleType.Redirect: 'prerouting',
        }

        if rule.ipt_chain:
            return True

        rt = rule.nat_rule_type
        chain = chain_map.get(rt, '') if rt is not None else ''
        if chain:
            rule.ipt_chain = chain
        else:
            no_chain_types = {NATRuleType.NONAT, NATRuleType.Return, NATRuleType.SDNAT}
            if rule.nat_rule_type not in no_chain_types:
                self.compiler.error(
                    rule,
                    f'No chain assignment for NAT rule type: {rule.nat_rule_type}',
                )

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


class ExpandMultipleAddresses(_PassthroughNAT):
    """Expand hosts/firewalls with multiple addresses."""

    pass


class GroupServicesByProtocol(NATRuleProcessor):
    """Split rules with mixed-protocol services."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.osrv) <= 1:
            self.tmp_queue.append(rule)
            return True

        groups: dict[int, list] = {}
        for srv in rule.osrv:
            proto = srv.get_protocol_number()
            groups.setdefault(proto, []).append(srv)

        if len(groups) <= 1:
            self.tmp_queue.append(rule)
            return True

        for srv_list in groups.values():
            r = rule.clone()
            r.osrv = srv_list
            self.tmp_queue.append(r)

        return True


class ConvertToAtomicForAddresses(NATRuleProcessor):
    """Split rules with multiple addresses into individual atomic rules."""

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
    """Assign outbound interface for SNAT/Masquerade rules."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.nat_rule_type not in (NATRuleType.SNAT, NATRuleType.Masq):
            self.tmp_queue.append(rule)
            return True

        if rule.itf_inb or rule.itf_outb:
            self.tmp_queue.append(rule)
            return True

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
