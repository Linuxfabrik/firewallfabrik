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

from typing import TYPE_CHECKING, cast

from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
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
    Direction,
    Firewall,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    PolicyAction,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

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
        self.have_dynamic_interfaces: bool = False

        # Per-chain rule collection for nftables output assembly.
        # Unlike iptables (where -A CHAIN is part of each command),
        # nftables rules are placed inside chain blocks, so we need
        # to track which chain each rule belongs to.
        self.chain_rules: dict[str, list[str]] = {
            'input': [],
            'forward': [],
            'output': [],
        }

    def my_platform_name(self) -> str:
        return 'nftables'

    def prolog(self) -> int:
        """Initialize compiler."""
        n = super().prolog()

        if n > 0:
            for iface in self.fw.interfaces:
                if iface.is_dynamic():
                    self.have_dynamic_interfaces = True

        return n

    def compile(self) -> None:
        """Main compilation: sets up the rule processor pipeline.

        Much simpler than iptables — no mangle splitting, multiport
        optimization, or temp chain management needed.
        """
        banner = f' Compiling policy ruleset {self.get_rule_set_name()} for nftables'
        if self.ipv6_policy:
            banner += ', IPv6'
        self.info(banner)

        super().compile()

        # -- Processor pipeline --
        self.add(Begin('Begin compilation'))

        # Store original action
        self.add(StoreAction('store action'))

        # Interface and direction
        self.add(InterfaceAndDirection('interface+dir'))
        self.add(
            SplitIfIfaceAndDirectionBoth('split interface rule with direction both')
        )

        self.add(ResolveMultiAddress('resolve compile-time MultiAddress'))

        # Check for empty groups before expansion
        self.add(EmptyGroupsInRE('check for empty groups in SRC', 'src'))
        self.add(EmptyGroupsInRE('check for empty groups in DST', 'dst'))
        self.add(EmptyGroupsInRE('check for empty groups in SRV', 'srv'))
        self.add(EmptyGroupsInRE('check for empty groups in ITF', 'itf'))

        # Expand groups and clean up
        self.add(ExpandGroups('expand all groups'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))
        self.add(EliminateDuplicatesInSRC('eliminate duplicates in SRC'))
        self.add(EliminateDuplicatesInDST('eliminate duplicates in DST'))
        self.add(EliminateDuplicatesInSRV('eliminate duplicates in SRV'))

        # Reject settings
        self.add(FillActionOnReject('fill action_on_reject'))

        # Logging — inline in nftables, no temp chain needed
        self.add(Logging_nft('process logging'))

        # Negation processors
        self.add(SplitIfSrcNegAndFw('split if src negated and fw'))
        self.add(SplitIfDstNegAndFw('split if dst negated and fw'))
        self.add(NftNegation('process negation'))

        # Chain assignment
        self.add(SplitIfSrcAny('split rule if src is any'))
        self.add(SplitIfDstAny('split rule if dst is any'))
        self.add(SplitIfSrcMatchesFw('split if src matches FW'))
        self.add(SplitIfDstMatchesFw('split if dst matches FW'))
        self.add(DecideOnChainIfDstFW('decide chain if dst is fw'))
        self.add(SplitIfSrcFWNetwork('split rule if src has a net fw has interface on'))
        self.add(DecideOnChainIfSrcFW('decide chain if src is fw'))
        self.add(SplitIfDstFWNetwork('split rule if dst has a net fw has interface on'))
        self.add(SpecialCaseWithFW2('replace fw with its interfaces if src==dst==fw'))
        self.add(DecideOnChainIfLoopback('any-any rule on loopback'))
        self.add(FinalizeChain('assign chain'))
        self.add(DecideOnTarget('set target'))

        # Clean up firewall object in src/dst
        self.add(RemoveFW('remove fw'))
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty elements'))

        # Address family filtering
        if self.ipv6_policy:
            self.add(DropIPv4Rules('drop ipv4 rules'))
        else:
            self.add(DropIPv6Rules('drop ipv6 rules'))
        self.add(DropRuleWithEmptyRE('drop rules after AF filter'))

        # Convert to atomic
        self.add(ConvertToAtomicForInterfaces('convert to atomic by interfaces'))
        self.add(GroupServicesByProtocol('split on services'))

        self.add(Optimize3('optimization 3'))

        if self.fw.opt_check_shading and not self.single_rule_compile_mode:
            self.add(DetectShadowing('detect rule shadowing'))

        # Print rule
        self.add(self.create_print_rule_processor())
        self.add(SimplePrintProgress())

        self.run_rule_processors()

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


# ═══════════════════════════════════════════════════════════════════
# Rule Processors
# ═══════════════════════════════════════════════════════════════════


class _Passthrough(PolicyRuleProcessor):
    """Base for processors that pass rules through."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
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
            global_reject = self.compiler.fw.opt_action_on_reject
            if global_reject:
                rule.set_option('action_on_reject', global_reject)

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
            if rule.get_option('tagging', False):
                self.compiler.error(
                    rule, 'Tagging not yet supported by nftables compiler'
                )
            if rule.get_option('classification', False):
                self.compiler.error(
                    rule, 'Classification not yet supported by nftables compiler'
                )
            if rule.get_option('routing', False):
                self.compiler.error(
                    rule, 'Policy routing not yet supported by nftables compiler'
                )
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
        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.opt_firewall_is_part_of_any_and_networks
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('no_output_chain', False):
            self.tmp_queue.append(rule)
            return True

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # C++ also splits when single_object_negation is set, but only if
        # the single negated object does NOT match the firewall itself.
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        src_neg_split = (
            rule.src_single_object_negation
            and len(rule.src) == 1
            and not nft_comp.complex_match(rule.src[0], nft_comp.fw)
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
        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.opt_firewall_is_part_of_any_and_networks
        if not afpa:
            self.tmp_queue.append(rule)
            return True

        if rule.get_option('no_input_chain', False):
            self.tmp_queue.append(rule)
            return True

        if rule.ipt_chain:
            self.tmp_queue.append(rule)
            return True

        # C++ also splits when single_object_negation is set, but only if
        # the single negated object does NOT match the firewall itself.
        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        dst_neg_split = (
            rule.dst_single_object_negation
            and len(rule.dst) == 1
            and not nft_comp.complex_match(rule.dst[0], nft_comp.fw)
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


class SplitIfSrcMatchesFw(PolicyRuleProcessor):
    """Split rule if src contains the firewall object."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if len(rule.src) <= 1:
            self.tmp_queue.append(rule)
            return True

        to_extract = []
        for obj in rule.src:
            if nft_comp.complex_match(obj, nft_comp.fw):
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

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if len(rule.dst) <= 1:
            self.tmp_queue.append(rule)
            return True

        to_extract = []
        for obj in rule.dst:
            if nft_comp.complex_match(obj, nft_comp.fw):
                to_extract.append(obj)

        if to_extract and len(rule.dst) > len(to_extract):
            for obj in to_extract:
                r = rule.clone()
                r.dst = [obj]
                self.tmp_queue.append(r)
                rule.dst.remove(obj)

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

        dst = rule.dst[0] if rule.dst else None
        if dst is not None:
            direction = rule.direction
            matches_fw = nft_comp.complex_match(dst, nft_comp.fw)

            if direction == Direction.Inbound:
                if matches_fw:
                    rule.ipt_chain = 'input'
            elif direction == Direction.Both and matches_fw:
                rule.ipt_chain = 'input'
                rule.direction = Direction.Inbound

        self.tmp_queue.append(rule)
        return True


class SplitIfSrcFWNetwork(PolicyRuleProcessor):
    """Split rule if src contains a network the FW has an interface on."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if rule.ipt_chain or rule.is_src_any():
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

        src = rule.src[0] if rule.src else None
        if src is not None:
            direction = rule.direction
            matches_fw = nft_comp.complex_match(src, nft_comp.fw)

            if direction == Direction.Outbound:
                if matches_fw:
                    rule.ipt_chain = 'output'
            elif direction == Direction.Both and matches_fw:
                rule.ipt_chain = 'output'
                rule.direction = Direction.Outbound

        self.tmp_queue.append(rule)
        return True


class SplitIfDstFWNetwork(PolicyRuleProcessor):
    """Split rule if dst contains a network the FW has an interface on."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if rule.ipt_chain or rule.is_dst_any():
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
    """Replace fw with its interface addresses when src==dst==fw."""

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
            and isinstance(src_obj, Firewall)
            and src_obj.id == nft_comp.fw.id
            and isinstance(dst_obj, Firewall)
            and dst_obj.id == nft_comp.fw.id
        ):
            all_addrs = []
            for iface in nft_comp.fw.interfaces:
                if iface.is_unnumbered():
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

        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None
        direction = rule.direction
        nft_comp = cast('PolicyCompiler_nft', self.compiler)

        if direction == Direction.Inbound:
            if dst is not None and nft_comp.complex_match(dst, nft_comp.fw):
                rule.ipt_chain = 'input'
        elif direction == Direction.Outbound:
            if src is not None and nft_comp.complex_match(src, nft_comp.fw):
                rule.ipt_chain = 'output'
        else:
            if dst is not None and nft_comp.complex_match(dst, nft_comp.fw):
                rule.ipt_chain = 'input'
            elif src is not None and nft_comp.complex_match(src, nft_comp.fw):
                rule.ipt_chain = 'output'

        self.tmp_queue.append(rule)
        return True


class DecideOnTarget(PolicyRuleProcessor):
    """Set the nftables verdict based on rule action."""

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
            PolicyAction.Continue: '.CONTINUE',
            PolicyAction.Custom: '.CUSTOM',
        }
        action = rule.action
        target = target_map.get(action) if isinstance(action, PolicyAction) else None
        if target is not None:
            rule.ipt_target = target
        else:
            action_name = action.name if action else str(action)
            not_yet = {
                PolicyAction.Accounting,
                PolicyAction.Branch,
                PolicyAction.Modify,
                PolicyAction.Pipe,
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
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        nft_comp = cast('PolicyCompiler_nft', self.compiler)
        chain = rule.ipt_chain
        fw_id = nft_comp.fw.id

        if chain == 'input' and not rule.dst_single_object_negation:
            rule.dst = [obj for obj in rule.dst if obj.id != fw_id]
        elif chain == 'output' and not rule.src_single_object_negation:
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


class Optimize3(PolicyRuleProcessor):
    """Remove duplicate rules that produce identical nftables commands.

    Unlike iptables (where the chain name is part of the command string),
    nftables rules don't include the chain. We include the chain in the
    dedup key so identical rules in different chains are kept.
    """

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

        chain = rule.ipt_chain or ''
        rule_str = f'{chain}:{pr.policy_rule_to_string(rule)}'
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

        if len(groups) <= 1:
            self.tmp_queue.append(rule)
        elif self._can_merge_tcp_udp(groups):
            rule.merged_tcp_udp = True
            self.tmp_queue.append(rule)
        else:
            for _proto, srvs in sorted(groups.items()):
                r = rule.clone()
                r.srv = srvs
                self.tmp_queue.append(r)

        return True

    @staticmethod
    def _can_merge_tcp_udp(groups: dict[int, list]) -> bool:
        """Check if groups consist only of TCP+UDP with identical ports."""
        if set(groups.keys()) != {6, 17}:
            return False

        tcp_srvs = groups[6]
        udp_srvs = groups[17]

        tcp_dst = {(s.dst_range_start or 0, s.dst_range_end or 0) for s in tcp_srvs}
        udp_dst = {(s.dst_range_start or 0, s.dst_range_end or 0) for s in udp_srvs}
        tcp_src = {(s.src_range_start or 0, s.src_range_end or 0) for s in tcp_srvs}
        udp_src = {(s.src_range_start or 0, s.src_range_end or 0) for s in udp_srvs}

        return tcp_dst == udp_dst and tcp_src == udp_src
