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

from typing import TYPE_CHECKING

from firewallfabrik.compiler._nat_compiler import NATCompiler
from firewallfabrik.compiler._rule_processor import NATRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    DropIPv4Rules,
    DropIPv6Rules,
    ExpandGroups,
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

        self.add(DecideOnChain('decide on chain'))

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


class DecideOnChain(NATRuleProcessor):
    """Assign rules to prerouting or postrouting chains."""

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
