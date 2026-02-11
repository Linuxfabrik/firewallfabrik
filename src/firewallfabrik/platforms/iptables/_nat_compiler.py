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
    TCPService,
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
        self.add(DecideOnTarget('decide on target'))

        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))

        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        self.add(GroupServicesByProtocol('group services by protocol'))
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

        # Branch action
        if rule.action == NATAction.Branch:
            rule.nat_rule_type = NATRuleType.NATBranch
            return True

        # NONAT
        if tsrc_any and tdst_any and tsrv_any:
            rule.nat_rule_type = NATRuleType.NONAT
            return True

        # SNAT / SNetnat
        if not tsrc_any and tdst_any:
            if isinstance(tsrc, Network | NetworkIPv6):
                rule.nat_rule_type = NATRuleType.SNetnat
            else:
                rule.nat_rule_type = NATRuleType.SNAT
            return True

        # DNAT / DNetnat / Redirect
        if tsrc_any and not tdst_any:
            if isinstance(tdst, Network | NetworkIPv6):
                rule.nat_rule_type = NATRuleType.DNetnat
            elif isinstance(tdst, Firewall) and tdst.id == self.compiler.fw.id:
                rule.nat_rule_type = NATRuleType.Redirect
            else:
                rule.nat_rule_type = NATRuleType.DNAT
            return True

        # SDNAT: both src and dst translation
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
    """Expand hosts/firewalls with multiple addresses."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)
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
