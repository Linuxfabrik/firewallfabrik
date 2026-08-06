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

        if not rule.get_neg('itf'):
            self.tmp_queue.append(rule)
            return True

        # Get the negated interface IDs
        negated_ids = {obj.id for obj in rule.itf if isinstance(obj, Interface)}

        # Replace with all other non-loopback interfaces
        all_ifaces = self.compiler.fw.interfaces
        rule.set_neg('itf', False)
        rule.itf = [
            iface
            for iface in all_ifaces
            if iface.id not in negated_ids and not iface.is_loopback()
        ]

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

    A packet has no incoming device once the routing decision is made and
    no outgoing one before it, so ``-i`` is impossible in POSTROUTING and
    OUTPUT and ``-o`` in PREROUTING and INPUT (see
    ``platforms/linux/_netfilter.py``).  iptables refuses such a rule
    outright and nftables accepts one that never matches, so neither can
    do what the rule asks for.

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
        problem = interface_direction_problem(rule.ipt_chain, inbound)
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
