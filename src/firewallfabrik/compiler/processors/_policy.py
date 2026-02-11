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

from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core.objects import (
    Interface,
    PhysAddress,
)


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


class CheckForObjectsWithErrors(PolicyRuleProcessor):
    """Check for objects that were marked with errors.

    In the CompRule model, objects don't carry error flags directly,
    so this is largely a passthrough. Platform-specific processors
    may set error conditions.
    """

    def __init__(self, name: str = 'Check for objects with errors') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        self.tmp_queue.append(rule)
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
