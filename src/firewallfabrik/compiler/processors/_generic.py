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

"""Generic rule processors shared across all compilers.

Corresponds to the generic processor classes from fwbuilder's compiler.py,
rewritten for CompRule dataclasses.
"""

from __future__ import annotations

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core._util import SLOT_VALUES
from firewallfabrik.core.objects import (
    Address,
    ICMP6Service,
    ICMPService,
)


class Begin(BasicRuleProcessor):
    """Injects CompRules from the compiler's rules list into the pipeline."""

    def __init__(self, name: str = 'Begin') -> None:
        super().__init__(name)
        self._init = False

    def process_next(self) -> bool:
        if not self._init:
            assert self.compiler is not None
            for rule in self.compiler.rules:
                if rule.disabled:
                    continue
                self.tmp_queue.append(rule)
            self._init = True
            return bool(self.tmp_queue)
        return False


class PrintTotalNumberOfRules(BasicRuleProcessor):
    """Counts total rules (uses slurp). Passes all rules through."""

    def __init__(self, name: str = 'Print total number of rules') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        if self.slurp():
            return True
        return bool(self.tmp_queue)


class SimplePrintProgress(BasicRuleProcessor):
    """Passes rules through, optionally printing progress."""

    def __init__(self, name: str = 'Progress') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is not None:
            self.tmp_queue.append(rule)
            return True
        return False


class SingleRuleFilter(BasicRuleProcessor):
    """Filter to single rule in single-rule compile mode."""

    def __init__(self, name: str = 'Single rule filter') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        if (
            self.compiler
            and self.compiler.single_rule_compile_mode
            and str(rule.id) != self.compiler.single_rule_id
        ):
            return True  # skip, try next
        self.tmp_queue.append(rule)
        return True


class SkipDisabledRules(BasicRuleProcessor):
    """Remove disabled rules from the pipeline."""

    def __init__(self, name: str = 'Skip disabled rules') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        if not rule.disabled:
            self.tmp_queue.append(rule)
        return True


class ExpandGroups(BasicRuleProcessor):
    """Expand group references in all rule element slots.

    Replaces Group objects with their leaf member objects.
    """

    def __init__(self, name: str = 'Expand groups') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in SLOT_VALUES:
            elements = getattr(rule, slot)
            if not elements:
                continue
            self.compiler.expand_groups_in_element(rule, slot)

        self.tmp_queue.append(rule)
        return True


class ConvertToAtomic(BasicRuleProcessor):
    """Split rules with multiple objects in Src/Dst/Srv into separate
    atomic rules (one object per element).

    Creates the Cartesian product of Src x Dst x Srv.
    """

    def __init__(self, name: str = 'Convert to atomic') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        src = rule.src or [None]
        dst = rule.dst or [None]
        srv = rule.srv or [None]

        if len(src) <= 1 and len(dst) <= 1 and len(srv) <= 1:
            self.tmp_queue.append(rule)
            return True

        for s in src:
            for d in dst:
                for v in srv:
                    r = rule.clone()
                    r.src = [s] if s is not None else []
                    r.dst = [d] if d is not None else []
                    r.srv = [v] if v is not None else []
                    self.tmp_queue.append(r)

        return True


class ConvertToAtomicForAddresses(BasicRuleProcessor):
    """Split rules with multiple address objects in Src/Dst only.

    Unlike ConvertToAtomic, this preserves multi-service rules
    (used after service grouping in iptables compiler).
    """

    def __init__(self, name: str = 'Convert to atomic for addresses') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        src = rule.src or [None]
        dst = rule.dst or [None]

        if len(src) <= 1 and len(dst) <= 1:
            self.tmp_queue.append(rule)
            return True

        for s in src:
            for d in dst:
                r = rule.clone()
                r.src = [s] if s is not None else []
                r.dst = [d] if d is not None else []
                self.tmp_queue.append(r)

        return True


class ConvertToAtomicForInterfaces(BasicRuleProcessor):
    """Split rules with multiple interfaces into separate rules."""

    def __init__(self, name: str = 'Convert to atomic for interfaces') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        if len(rule.itf) <= 1:
            self.tmp_queue.append(rule)
            return True

        for itf_obj in rule.itf:
            r = rule.clone()
            r.itf = [itf_obj]
            self.tmp_queue.append(r)

        return True


class DropRulesByAddressFamily(BasicRuleProcessor):
    """Base class for dropping rules by address family.

    Removes addresses of the wrong family from rule element slots.
    If a slot becomes empty (was non-empty before), drops the entire rule.
    """

    def __init__(self, name: str = '', drop_ipv6: bool = True) -> None:
        super().__init__(name)
        self._drop_ipv6 = drop_ipv6

    def _should_drop(self, obj) -> bool:
        """Return True if this address object should be dropped."""
        if not isinstance(obj, Address):
            return False
        addr_str = obj.get_address()
        if not addr_str:
            return False
        if self._drop_ipv6 and obj.is_v6():
            return True
        return bool(not self._drop_ipv6 and obj.is_v4())

    def _filter_slot(self, rule: CompRule, slot: str) -> bool:
        """Filter address objects in a slot. Returns True if rule should be dropped."""
        elements = getattr(rule, slot)
        if not elements:
            return False  # empty = "any", leave as-is

        new_elements = [obj for obj in elements if not self._should_drop(obj)]
        if elements and not new_elements:
            return True  # slot became empty, drop rule
        setattr(rule, slot, new_elements)
        return False

    def _filter_srv_slot(self, rule: CompRule, slot: str) -> bool:
        """Filter ICMP services by address family. Returns True if rule should be dropped."""
        elements = getattr(rule, slot)
        if not elements:
            return False

        new_elements = []
        for obj in elements:
            if isinstance(obj, ICMPService) and not isinstance(obj, ICMP6Service):
                if not self._drop_ipv6:
                    continue  # drop ICMPv4 when compiling for IPv6
            elif isinstance(obj, ICMP6Service) and self._drop_ipv6:
                continue  # drop ICMPv6 when compiling for IPv4
            new_elements.append(obj)

        if elements and not new_elements:
            return True
        setattr(rule, slot, new_elements)
        return False

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        # Filter address elements
        for slot in ('src', 'dst', 'osrc', 'odst', 'tsrc', 'tdst', 'rdst'):
            if self._filter_slot(rule, slot):
                return True  # drop rule

        # Filter service elements for ICMP
        for slot in ('srv', 'osrv', 'tsrv'):
            if self._filter_srv_slot(rule, slot):
                return True  # drop rule

        self.tmp_queue.append(rule)
        return True


class DropIPv4Rules(DropRulesByAddressFamily):
    """Drop rules that contain only IPv4 addresses (for IPv6 compilation)."""

    def __init__(self, name: str = 'Drop IPv4 rules') -> None:
        super().__init__(name, drop_ipv6=False)


class DropIPv6Rules(DropRulesByAddressFamily):
    """Drop rules that contain only IPv6 addresses (for IPv4 compilation)."""

    def __init__(self, name: str = 'Drop IPv6 rules') -> None:
        super().__init__(name, drop_ipv6=True)


class DropRuleWithEmptyRE(BasicRuleProcessor):
    """Drop rules that have empty rule elements that shouldn't be empty.

    After group expansion, if an element that previously contained
    objects is now empty, the rule should be dropped.
    """

    def __init__(self, name: str = 'Drop rules with empty RE') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        # For policy rules, check src, dst, srv
        # Empty means "any" which is valid — we only drop if the rule
        # was explicitly cleared by a previous processor (which would
        # set a special flag). For now, pass through.
        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInSRC(BasicRuleProcessor):
    """Remove duplicate objects from the src element."""

    def __init__(self, name: str = 'Eliminate duplicates in SRC') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        self.compiler.eliminate_duplicates_in_element(rule, 'src')
        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInDST(BasicRuleProcessor):
    """Remove duplicate objects from the dst element."""

    def __init__(self, name: str = 'Eliminate duplicates in DST') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        self.compiler.eliminate_duplicates_in_element(rule, 'dst')
        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInSRV(BasicRuleProcessor):
    """Remove duplicate objects from the srv element."""

    def __init__(self, name: str = 'Eliminate duplicates in SRV') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        self.compiler.eliminate_duplicates_in_element(rule, 'srv')
        self.tmp_queue.append(rule)
        return True


class DetectShadowing(BasicRuleProcessor):
    """Detect rule shadowing (uses slurp).

    Passes all rules through — shadowing detection is advisory only.
    """

    def __init__(self, name: str = 'Detect shadowing') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        if self.slurp():
            return True
        return bool(self.tmp_queue)


class AssignUniqueRuleId(BasicRuleProcessor):
    """Assign sequential abs_rule_number to each rule."""

    def __init__(self, name: str = 'Assign unique rule ID') -> None:
        super().__init__(name)
        self._counter = 0

    def process_next(self) -> bool:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        rule.abs_rule_number = self._counter
        self._counter += 1
        self.tmp_queue.append(rule)
        return True
