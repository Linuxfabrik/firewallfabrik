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
from firewallfabrik.core.objects import (
    AddressRange,
    Direction,
    Interface,
    IPv4,
    IPv6,
    Network,
    NetworkIPv6,
    PhysAddress,
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
