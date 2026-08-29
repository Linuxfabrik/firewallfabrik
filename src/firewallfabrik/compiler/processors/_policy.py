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

"""Generic policy rule processors shared across platforms.

Corresponds to the processor classes from fwbuilder's policy_compiler.py,
rewritten for CompRule dataclasses.
"""

from __future__ import annotations

import ipaddress as _ipa
import uuid

from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core._options import option_int, option_is_true
from firewallfabrik.core.objects import (
    AddressRange,
    Direction,
    Firewall,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    PhysAddress,
    PolicyAction,
)
from firewallfabrik.platforms.linux._netfilter import interface_direction_problem


class InterfacePolicyRules(PolicyRuleProcessor):
    """Split rules with multiple interfaces into separate rules,
    one per interface."""

    def __init__(self, name: str = 'Interface policy rules') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.is_itf_any():
            self.tmp_queue.append(rule)
            return True

        if len(rule.itf) == 1:
            self.tmp_queue.append(rule)
            return True

        # Multiple interfaces — split into one rule per interface
        for itf_obj in rule.itf:
            r = rule.clone()
            r.itf = [itf_obj]
            self.tmp_queue.append(r)

        return True


class SrcNegation(PolicyRuleProcessor):
    """Process negation in source rule element.

    If negation is not allowed, report error. Otherwise pass through
    (platform-specific compilers handle negation).
    """

    def __init__(self, allow_negation: bool = False, name: str = 'SrcNegation') -> None:
        super().__init__(name)
        self._allow_negation = allow_negation

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_neg('src') and not self._allow_negation:
            self.compiler.abort(
                rule, 'Negation in source is not supported by this platform'
            )
        self.tmp_queue.append(rule)
        return True


class DstNegation(PolicyRuleProcessor):
    """Process negation in destination rule element."""

    def __init__(self, allow_negation: bool = False, name: str = 'DstNegation') -> None:
        super().__init__(name)
        self._allow_negation = allow_negation

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_neg('dst') and not self._allow_negation:
            self.compiler.abort(
                rule, 'Negation in destination is not supported by this platform'
            )
        self.tmp_queue.append(rule)
        return True


class SrvNegation(PolicyRuleProcessor):
    """Process negation in service rule element."""

    def __init__(self, allow_negation: bool = False, name: str = 'SrvNegation') -> None:
        super().__init__(name)
        self._allow_negation = allow_negation

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_neg('srv') and not self._allow_negation:
            self.compiler.abort(
                rule, 'Negation in service is not supported by this platform'
            )
        self.tmp_queue.append(rule)
        return True


def expand_interface_negation(compiler, rule, slot: str) -> bool:
    """Turn "not these interfaces" into "all the other ones".

    "All the other ones" is not the whole interface list.  fwbuilder
    builds it in `Compiler::fullInterfaceNegationInRE`
    (libfwbuilder/fwcompiler/Compiler.cpp:1053) from the interfaces the
    firewall actually protects, and leaves four kinds out:

    * the loopback interface,
    * an interface the administrator marked *unprotected*, which says
      that no rules are to be generated for it (fwbuilder bug #2710034),
    * a bridge port, unless the firewall bridges - on a routing firewall
      the packet is seen on the bridge, so a rule naming the port never
      matches,
    * a cluster interface, which belongs to the cluster and not to this
      member.

    Writing those out means "not eth1" produces rules that cannot match,
    and the traffic the rule was written to cover passes.

    Returns whether the rule should stay in the pipeline.  It should not
    when the negated set covers every interface the firewall has: the
    element then holds nothing, and an empty element means "any" here, so
    the rule would apply on exactly the interfaces it was written to skip.
    fwbuilder cannot land in that state - its empty element is not "any",
    and both `PolicyCompiler::InterfacePolicyRules` and
    `NATCompiler::ConvertToAtomicForItf*` iterate zero times and drop the
    rule (Compiler.cpp:1036, RuleElement.cpp:141).
    """
    if not rule.get_neg(slot):
        return True

    bridging_fw = bool(compiler.fw.get_option('bridging_fw'))
    negated_ids = {obj.id for obj in getattr(rule, slot) if isinstance(obj, Interface)}
    remaining = [
        iface
        for iface in compiler.fw.interfaces
        if iface.id not in negated_ids
        and not iface.is_loopback()
        and not iface.is_unprotected()
        and not (iface.is_bridge_port() and not bridging_fw)
        and not iface.get_option('cluster_interface', False)
    ]
    rule.set_neg(slot, False)
    setattr(rule, slot, remaining)

    if not remaining:
        compiler.warning(
            rule,
            'The rule excludes every interface the firewall has, so there is '
            'none left for it to match on; the rule is left out',
        )
        return False
    return True


class SingleObjectNegationItf(PolicyRuleProcessor):
    """Carry a single negated interface through as an inline negation.

    Ports ``Compiler::singleObjectNegation`` for the Itf element, which
    takes the interface elements without asking anything else of them
    (Compiler.cpp).  Both back ends can say "not this one" in a rule:
    ``! -i eth0`` and ``iifname != "eth0"``.  Several of them cannot be
    said that way and go to `ItfNegation` instead.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        if rule.get_neg('itf') and len(rule.itf) == 1:
            rule.itf_single_object_negation = True
            rule.set_neg('itf', False)
        self.tmp_queue.append(rule)
        return True


class ItfNegation(PolicyRuleProcessor):
    """Process negation in interface rule element.

    Replaces a negated interface set with all other interfaces
    on the firewall (excluding loopback).
    """

    def __init__(self, name: str = 'ItfNegation') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if expand_interface_negation(self.compiler, rule, 'itf'):
            self.tmp_queue.append(rule)
        return True


class TimeNegation(PolicyRuleProcessor):
    """Process negation in time/interval rule element."""

    def __init__(
        self, allow_negation: bool = False, name: str = 'TimeNegation'
    ) -> None:
        super().__init__(name)
        self._allow_negation = allow_negation

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_neg('when') and not self._allow_negation:
            self.compiler.abort(
                rule, 'Negation in time is not supported by this platform'
            )
        self.tmp_queue.append(rule)
        return True


class ExpandMultipleAddresses(PolicyRuleProcessor):
    """Expand hosts/firewalls with multiple interfaces into
    individual interface address references in Src and Dst."""

    def __init__(self, name: str = 'Expand multiple addresses') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.compiler.expand_addr(rule, 'src')
        self.compiler.expand_addr(rule, 'dst')
        self.tmp_queue.append(rule)
        return True


class ExpandMultipleAddressesIfNotFWInSrc(PolicyRuleProcessor):
    """Expand the source into addresses unless it is the firewall itself.

    The firewall object is what the chain decisions downstream reason
    about, so it stays whole; everything else is replaced by the
    addresses behind it, because a Host or an Interface object answers a
    different question than the address it carries.  Whether a
    destination is a broadcast, whether a source is on a network the
    firewall has an interface on, whether the rule belongs in the input
    chain - all of that is asked of a single address.

    Ports ``PolicyCompiler_ipt::expandMultipleAddressesIfNotFWinSrc``
    (PolicyCompiler_ipt.cpp:3013), which fwbuilder runs before
    ``finalizeChain`` for exactly that reason.
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
    """Expand the destination into addresses unless it is the firewall.

    See :class:`ExpandMultipleAddressesIfNotFWInSrc`; this is the
    destination half (``PolicyCompiler_ipt.cpp:3024``).
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


class DropRuleWithImpossibleInterface(PolicyRuleProcessor):
    """Drop a rule whose chain cannot see the interface it matches on.

    A packet has no outgoing device before the routing decision and a
    locally generated one has no incoming device at all, so ``-o`` is
    impossible in PREROUTING and INPUT and ``-i`` in OUTPUT (see
    ``platforms/linux/_netfilter.py``).  iptables refuses such a rule
    outright and nftables accepts one that never matches, so neither can
    do what the rule asks for.

    The postrouting chain is not one of those cases any more and the
    compiler is asked about it, because the answer differs per back end:
    nftables matches the incoming device there and iptables only does so
    for a bridge port.

    Runs before ``CountChainUsage`` rather than in the print rule: the
    dropped rule may be the only jump to a temporary chain, and counting
    it would leave that chain created and filled but unreachable.
    """

    def __init__(self, name: str = 'drop rules with an impossible interface') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.iface_label == 'nil' or rule.direction not in (
            Direction.Inbound,
            Direction.Outbound,
        ):
            self.tmp_queue.append(rule)
            return True

        inbound = rule.direction == Direction.Inbound
        problem = interface_direction_problem(
            rule.ipt_chain,
            inbound,
            iif_in_postrouting=self.compiler.can_match_inbound_in_postrouting(rule),
        )
        if not problem:
            self.tmp_queue.append(rule)
            return True

        side = 'incoming' if inbound else 'outgoing'
        self.compiler.error(
            rule,
            f'Rule matches on the {side} interface but {problem}; the rule is left out',
        )
        return True


class MACFiltering(PolicyRuleProcessor):
    """Remove MAC addresses from rules when not supported.

    Issues warnings and aborts if removing MACs makes elements empty.
    """

    def __init__(self, name: str = 'MAC filtering') -> None:
        super().__init__(name)
        self._last_rule_lbl = ''

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)

        lbl = rule.label

        for slot in ('src', 'dst'):
            elements = getattr(rule, slot)
            if not elements:
                continue

            mac_objs = [obj for obj in elements if isinstance(obj, PhysAddress)]
            if mac_objs:
                new_elements = [
                    obj for obj in elements if not isinstance(obj, PhysAddress)
                ]
                setattr(rule, slot, new_elements)

                if self._last_rule_lbl != lbl:
                    self.compiler.warning(
                        rule,
                        'MAC address matching is not supported. '
                        'MAC addresses removed from rule',
                    )
                    self._last_rule_lbl = lbl

                if not new_elements:
                    self.compiler.abort(
                        rule,
                        "Rule element becomes 'Any' after MAC "
                        'addresses have been removed',
                    )

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
        rule = self.get_next()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements:
            self.tmp_queue.append(rule)
            return True

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
                        'netmask': '128',
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


class AddressRangesInRE(PolicyRuleProcessor):
    """Replace an AddressRange with the networks that cover it.

    The ``iprange`` match arrived in iptables 1.2.11, so an older binary
    has no way to compare an address against a range.  fwbuilder answers
    that by writing the range out as the smallest set of CIDR blocks that
    covers it and letting the rule match on those instead
    (``PolicyCompiler_ipt::compile`` picks ``addressRanges`` over
    ``specialCaseAddressRangeInRE`` below 1.2.11).  The blocks become one
    rule each further down the pipeline, which is what the reference
    output shows: `-d 192.168.1.10/31`, `-d 192.168.1.12/30`, ...

    Corresponds to C++ ``PolicyCompiler::addressRanges``.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements:
            self.tmp_queue.append(rule)
            return True

        new_elements: list = []
        for obj in elements:
            networks = self._to_networks(obj, rule)
            if networks is None:
                new_elements.append(obj)
            else:
                new_elements.extend(networks)
        setattr(rule, self._slot, new_elements)

        self.tmp_queue.append(rule)
        return True

    def _to_networks(self, obj, rule) -> list | None:
        """Return the networks covering *obj*, or None if it is not a range."""
        if not isinstance(obj, AddressRange):
            return None
        start, end = obj.get_start_address(), obj.get_end_address()
        if not start or not end:
            return None
        try:
            blocks = list(
                _ipa.summarize_address_range(
                    _ipa.ip_address(start), _ipa.ip_address(end)
                )
            )
        except (ValueError, TypeError):
            self.compiler.error(
                rule,
                f'Address range "{obj.name}" does not name two addresses of '
                'the same family',
            )
            return None

        networks = []
        for index, block in enumerate(blocks):
            is_v4 = block.version == 4
            cls = Network if is_v4 else NetworkIPv6
            net = cls(id=uuid.uuid4(), name=f'{obj.name}_{index}')
            net.inet_addr_mask = {
                'address': str(block.network_address),
                'netmask': str(block.netmask) if is_v4 else str(block.prefixlen),
            }
            networks.append(net)
        return networks


class AddressRangesInSrc(AddressRangesInRE):
    """Replace an AddressRange in Src with the networks covering it."""

    def __init__(self, name: str) -> None:
        super().__init__(name, 'src')


class AddressRangesInDst(AddressRangesInRE):
    """Replace an AddressRange in Dst with the networks covering it."""

    def __init__(self, name: str) -> None:
        super().__init__(name, 'dst')


#: The rule option behind the "Assume firewall is part of any" checkbox.
FW_PART_OF_ANY = 'firewall_is_part_of_any_and_networks'


def normalize_fw_part_of_any(rules, fw) -> None:
    """Give every rule a 0 or a 1 for "assume firewall is part of any".

    Ports the loop in ``PolicyCompiler_ipt::prolog`` (PolicyCompiler_ipt.cpp:444)
    and its comment.  A `.fwb` carries five spellings of this rule option
    side by side - the corpus has ``''``, ``'0'``, ``'1'``, ``'False'``,
    ``'True'`` and ``'true'`` - because in Firewall Builder 3.0 it was a
    checkbox and became a tri-state afterwards:

    * empty means "use the firewall's setting",
    * ``True`` is the old checkbox ticked and means on,
    * ``False`` is the old checkbox cleared and means *the firewall's
      setting* as well, because back then a rule could not turn the option
      off on its own,
    * anything else is already the tri-state value and is read as a number,
      which is why ``'true'`` - not ``'True'`` - comes out as 0.

    Every reader afterwards asks whether the value is 1.  Read as a Python
    truth value instead, ``'0'`` is a non-empty string and therefore on:
    a rule that says "do not assume it" got the extra INPUT and OUTPUT
    copies naming the firewall that the option exists to suppress.
    """
    global_afpa = 1 if fw is not None and fw.get_option(FW_PART_OF_ANY) else 0
    for rule in rules:
        stored = (rule.options or {}).get(FW_PART_OF_ANY, '')
        text = str(stored).strip() if not isinstance(stored, bool) else str(stored)
        if text == '' or text == 'False':
            rule.set_option(FW_PART_OF_ANY, global_afpa)
        elif text == 'True':
            rule.set_option(FW_PART_OF_ANY, 1)
        else:
            rule.set_option(FW_PART_OF_ANY, option_int(stored))


def assumes_fw_is_part_of_any(rule) -> bool:
    """Does *rule* assume the firewall is part of "any" and of the networks?

    One reader for the value :func:`normalize_fw_part_of_any` leaves
    behind, because every C++ site asks the same question the same way
    (``ruleopt->getInt(...) == 1``).
    """
    return option_int((rule.options or {}).get(FW_PART_OF_ANY, 0)) == 1


def dst_is_a_cluster_this_firewall_is_in(dst, fw) -> bool:
    """Is *dst* a cluster object whose members include *fw*?

    `PolicyCompiler_ipt::decideOnChainIfDstFW` asks that next to
    `complexMatch`, and says why in a comment: the destination may be a
    cluster object, and not necessarily the cluster being compiled.
    Traffic addressed to a cluster this firewall belongs to is addressed
    to this firewall, so the rule belongs in the input chain - and it is
    answered from the cluster's own membership rather than from
    `parent_cluster_id`, so it holds when the member is compiled on its
    own.

    Only the destination is asked.  `decideOnChainIfSrcFW` has no such
    branch: traffic *from* a cluster is traffic from whichever member sent
    it, which is not necessarily this one.
    """
    from firewallfabrik.core.objects import Cluster

    if not isinstance(dst, Cluster) or fw is None:
        return False
    return any(member.id == fw.id for member in dst.get_members_list())


def is_mangle_only_rule_set(rule_set) -> bool:
    """Return whether *rule_set* carries mangle rules only."""
    if rule_set is None:
        return False
    options = rule_set.options or {}
    return option_is_true(options.get('mangle_only_rule_set', False))


def _rule_option(rule, key) -> bool:
    return option_is_true((rule.options or {}).get(key, False))


def rule_set_has_mangle_rules(rule_set) -> bool:
    """Whether *rule_set* holds a rule that tags or classifies.

    That is what makes a branch into it a branch into the mangle table
    (``CompilerDriver_ipt::findBranchesInMangleTable``).
    """
    return any(
        _rule_option(rule, 'tagging') or _rule_option(rule, 'classification')
        for rule in rule_set.rules
    )


def rule_set_classifies(rule_set) -> bool:
    """Whether *rule_set* holds a rule that assigns a traffic class.

    The iptables CLASSIFY target registers for LOCAL_OUT, FORWARD and
    POST_ROUTING alone (``net/netfilter/xt_CLASSIFY.c``, ``.hooks``), so a
    jump into such a rule set from prerouting is a command iptables
    refuses - which stops the activation script.  nftables has no such
    restriction on ``meta priority set`` (``nft_meta_set_validate`` checks
    the hook for ``meta pkttype set`` only).
    """
    return any(_rule_option(rule, 'classification') for rule in rule_set.rules)


def branch_target_has_mangle_rules(rule, compiler) -> bool:
    """Whether *rule* branches into a rule set with rules for the mangle table.

    The administrator can say so with the rule's own "branch in mangle
    table" option, and `CompilerDriver_ipt::findBranchesInMangleTable` sets
    that option for them whenever the target rule set holds a rule that
    tags or classifies - which is the common case, because a mangle rule
    set is normally reached by an ordinary branch.  The driver collects the
    names, because each rule set is compiled by a compiler of its own.
    """
    if rule.action != PolicyAction.Branch:
        return False
    if rule.get_option('ipt_branch_in_mangle', False):
        return True
    return rule.get_option('branch_name', '') in getattr(
        compiler, 'mangle_branch_chains', ()
    )


def branches_into_mangle_only(rule, compiler) -> bool:
    """Whether *rule* branches into a rule set that has no filter half.

    Such a rule has nothing left to do in the filter table
    (``PolicyCompiler_ipt::dropMangleTableRules``).
    """
    if not branch_target_has_mangle_rules(rule, compiler):
        return False
    return rule.get_option('branch_name', '') in getattr(
        compiler, 'mangle_only_branch_chains', ()
    )


class KeepMangleTableRules(PolicyRuleProcessor):
    """Keep only the rules the mangle run installs.

    A rule branching into a mangle rule set is turned into one jump per
    built-in chain the branch may need.  The rules in the branch are the
    administrator's, so the compiler does not know which hook their targets
    require - CLASSIFY, for one, is refused in prerouting - and
    ``MangleTableCompiler_ipt::keepMangleTableRules`` therefore jumps from
    prerouting, postrouting and forward alike.  Forward is on the list
    because only a forwarded packet can match an incoming and an outgoing
    interface at once (fwbuilder ticket #1415).

    Subclasses name the chains the way their back end spells them, and say
    which of them a rule set that assigns a traffic class may not be
    reached from.
    """

    PREROUTING = 'PREROUTING'
    POSTROUTING = 'POSTROUTING'
    FORWARD = 'FORWARD'
    #: Chains from which a branch that classifies must not be entered.
    CLASSIFY_FORBIDDEN_CHAINS: tuple[str, ...] = ()

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if is_mangle_only_rule_set(self.compiler.source_ruleset):
            self.tmp_queue.append(rule)
            return True

        if branch_target_has_mangle_rules(rule, self.compiler):
            inbound = rule.direction in (
                Direction.Undefined,
                Direction.Both,
                Direction.Inbound,
            )
            outbound = rule.direction in (
                Direction.Undefined,
                Direction.Both,
                Direction.Outbound,
            )
            chains = []
            if inbound:
                chains.append(self.PREROUTING)
            if outbound:
                chains.append(self.POSTROUTING)
            chains.append(self.FORWARD)

            branch_name = rule.get_option('branch_name', '')
            if branch_name in getattr(self.compiler, 'classifying_branch_chains', ()):
                refused = [c for c in chains if c in self.CLASSIFY_FORBIDDEN_CHAINS]
                if refused:
                    chains = [c for c in chains if c not in refused]
                    self.compiler.warning(
                        rule,
                        f'Rule set "{branch_name}" assigns a traffic class, '
                        f'which the {"/".join(refused).lower()} chain cannot '
                        f'carry, so the branch is not taken there',
                    )

            for chain in chains:
                copy = rule.clone()
                copy.ipt_chain = chain
                self.tmp_queue.append(copy)
            return True

        if (
            rule.get_option('tagging', False)
            or rule.get_option('routing', False)
            or rule.get_option('classification', False)
            or rule.get_option('put_in_mangle_table', False)
        ):
            self.tmp_queue.append(rule)

        return True


class SpecialCaseWithFWInDstAndOutbound(PolicyRuleProcessor):
    """Drop an outbound forwarding rule whose destination is the firewall.

    A packet that is not from the firewall and is addressed to it goes
    into the input chain and is never forwarded, so it cannot cross an
    interface outbound and a rule written that way would never see it.
    Ports ``PolicyCompiler_ipt::specialCaseWithFWInDstAndOutbound``
    (PolicyCompiler_ipt.cpp:2761), which has four guards before it drops
    anything, and each of them keeps a rule the administrator wrote:

    * the interface has to be one of *this* firewall's;
    * a bridging firewall forwards a broadcast and a multicast frame, so a
      rule naming one as its destination is legitimate there;
    * a negated source may well be the firewall, so the packet may be one
      the firewall generated;
    * and with "assume firewall is part of any and networks" off, a
      network object is not the firewall unless its mask covers a single
      address - which is what makes "outbound to ff00::/8" a rule to keep.

    Shared, because a rule this drops is dropped without a word: the
    nftables copy had the first, second and fourth guard missing while its
    docstring described them, and one rule of the reference corpus
    disappeared from the nftables ruleset and stayed in the iptables one.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        itf = rule.itf[0] if rule.itf else None
        src = rule.src[0] if rule.src else None
        dst = rule.dst[0] if rule.dst else None

        if not (
            rule.direction == Direction.Outbound
            and isinstance(itf, Interface)
            and itf.device_id == self.compiler.fw.id
            # iptables spells the chain OUTPUT and nftables output.
            and (rule.ipt_chain or '').lower() != 'output'
        ):
            self.tmp_queue.append(rule)
            return True

        if (
            dst is not None
            and hasattr(dst, 'is_broadcast')
            and (dst.is_broadcast() or dst.is_multicast())
            and self.compiler.fw.get_option('bridging_fw')
        ):
            self.tmp_queue.append(rule)
            return True

        if rule.get_neg('src') or rule.src_single_object_negation:
            self.tmp_queue.append(rule)
            return True

        rule_afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)

        src_matches = (
            self.compiler.complex_match(src, self.compiler.fw)
            if src is not None
            else False
        )
        dst_matches = (
            self.compiler.complex_match(dst, self.compiler.fw)
            if dst is not None
            else False
        )

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
            return True  # drop

        self.tmp_queue.append(rule)
        return True
