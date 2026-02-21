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

import ipaddress as _ipa

from firewallfabrik.compiler._comp_rule import CompRule, expand_group
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core._util import SLOT_VALUES
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    Direction,
    Group,
    ICMP6Service,
    ICMPService,
    IPService,
    MultiAddress,
    Network,
    NetworkIPv6,
    PolicyAction,
    Service,
    TCPService,
    TCPUDPService,
)


def _is_runtime(obj: MultiAddress) -> bool:
    """Return True if the MultiAddress is marked for run-time resolution."""
    return bool((obj.data or {}).get('run_time', False))


class Begin(BasicRuleProcessor):
    """Injects CompRules from the compiler's rules list into the pipeline."""

    def __init__(self, name: str = 'Begin') -> None:
        super().__init__(name)
        self._init = False

    def process_next(self) -> bool:
        if not self._init:
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

        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        if (
            self.compiler.single_rule_compile_mode
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

        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        if not rule.disabled:
            self.tmp_queue.append(rule)
        return True


class ResolveMultiAddress(BasicRuleProcessor):
    """Resolve compile-time MultiAddress objects in all rule element slots.

    Corresponds to C++ ``Preprocessor::convertObject()`` which calls
    ``MultiAddress::loadFromSource()`` before compilation.  In C++ this
    runs as a separate ``Preprocessor`` pass over the entire object tree;
    here we do it per-rule in the processor pipeline, but *before*
    ``EmptyGroupsInRE`` so that the empty-group check can see whether
    resolution produced any addresses.

    - **Compile-time** MultiAddress (DNSName, AddressTable): resolved
      and replaced with the resulting Address objects in the slot.
    - **Runtime** MultiAddress: kept as-is.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in SLOT_VALUES:
            elements = getattr(rule, slot)
            if not elements:
                continue
            new_elements = []
            changed = False
            for obj in elements:
                if isinstance(obj, MultiAddress) and not _is_runtime(obj):
                    new_elements.extend(
                        self.compiler._resolve_multi_address(obj),
                    )
                    changed = True
                else:
                    new_elements.append(obj)
            if changed:
                setattr(rule, slot, new_elements)

        self.tmp_queue.append(rule)
        return True


class EmptyGroupsInRE(BasicRuleProcessor):
    """Check for empty groups in a specific rule element slot.

    Corresponds to C++ ``Compiler::emptyGroupsInRE``.  Runs **after**
    ``ResolveMultiAddress`` and **before** ``ExpandGroups``.  For each
    Group in the slot that has zero effective members (recursively
    counting through nested groups):

    - If ``ignore_empty_groups`` is **true**: remove the empty group from
      the element and warn.  If the element becomes "any" (empty) after
      all removals, drop the rule.
    - If ``ignore_empty_groups`` is **false** (default): abort compilation.

    Runtime MultiAddress objects are skipped (their content is unknown at
    compile time).

    Each platform compiler adds one instance per slot it cares about
    (C++: src, dst, srv, itf for policy; osrc, odst, osrv, tsrc, tdst,
    tsrv for NAT).
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    @staticmethod
    def _count_children(session, obj) -> int:
        """Count effective leaf members of a group recursively.

        Matches C++ ``Compiler::emptyGroupsInRE::countChildren``.
        Runtime MultiAddress objects count as 1 (their content is
        unknown at compile time).
        """
        if not isinstance(obj, Group):
            return 1
        if isinstance(obj, MultiAddress) and _is_runtime(obj):
            return 1
        members = expand_group(session, obj)
        return len(members)

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements:
            # Element is "any" — nothing to check
            self.tmp_queue.append(rule)
            return True

        # Find empty groups in this slot.  Skip runtime MultiAddress
        # objects — their content is unknown at compile time.  Matches
        # C++ Compiler::emptyGroupsInRE::processNext().
        empty_groups: list = []
        for obj in elements:
            if isinstance(obj, MultiAddress) and _is_runtime(obj):
                continue
            if (
                isinstance(obj, Group)
                and self._count_children(self.compiler.session, obj) == 0
            ):
                empty_groups.append(obj)

        if not empty_groups:
            self.tmp_queue.append(rule)
            return True

        if self.compiler.fw.opt_ignore_empty_groups:
            # Remove empty groups and warn
            for obj in empty_groups:
                name = getattr(obj, 'name', str(obj))
                self.compiler.warning(
                    rule,
                    f"Empty group or address table object '{name}'",
                )
            remaining = [o for o in elements if o not in empty_groups]
            setattr(rule, self._slot, remaining)
            if not remaining:
                # Element became "any" after removal — drop the rule
                self.compiler.warning(
                    rule,
                    f'After removal of all empty groups rule element'
                    f" {self._slot} becomes 'any'; dropping rule"
                    f' {rule.label} because option'
                    f" 'Ignore rules with empty groups' is in effect",
                )
                return True  # drop rule
        else:
            names = ', '.join(getattr(o, 'name', str(o)) for o in empty_groups)
            self.compiler.abort(
                rule,
                f"Empty group or address table object '{names}'"
                f' is used in the rule but option'
                f" 'Ignore rules with empty groups' is off",
            )
            return True  # abort was set

        self.tmp_queue.append(rule)
        return True


class ExpandGroups(BasicRuleProcessor):
    """Expand group references in all rule element slots.

    Replaces Group objects with their leaf member objects.
    """

    def __init__(self, name: str = 'Expand groups') -> None:
        super().__init__(name)

    def process_next(self) -> bool:

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
    """Drop rules where a required rule element became empty (size==0).

    Corresponds to C++ ``Compiler::dropRuleWithEmptyRE``.
    After group expansion and address processing, checks if src or dst
    (for policy rules) became literally empty.  An empty element is
    different from "any" — "any" is the initial default, while an empty
    element results from all objects being removed by earlier processors.
    """

    def __init__(self, name: str = 'Drop rules with empty RE') -> None:
        super().__init__(name)

    def process_next(self) -> bool:

        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        # Check if any required element became empty after processing.
        # In our CompRule model, [] means "any" initially, but if a slot
        # was non-empty and became empty due to filtering (address family,
        # etc.), it should be dropped.  The has_empty_re flag is set by
        # processors that remove objects from elements.
        if getattr(rule, 'has_empty_re', False):
            return True  # drop

        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInSRC(BasicRuleProcessor):
    """Remove duplicate objects from the src element."""

    def __init__(self, name: str = 'Eliminate duplicates in SRC') -> None:
        super().__init__(name)

    def process_next(self) -> bool:

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

        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        self.compiler.eliminate_duplicates_in_element(rule, 'srv')
        self.tmp_queue.append(rule)
        return True


class DetectShadowing(BasicRuleProcessor):
    """Detect rule shadowing — abort if an earlier rule completely covers a later one.

    Corresponds to C++ PolicyCompiler::DetectShadowing.
    Accumulates rules and for each new rule checks whether any previously
    seen rule is more general (shadows it).  Aborts compilation on the
    first match.

    Rules with negation, Branch/Continue/Return/Accounting actions,
    fallback, or hidden flags are excluded from the check.
    """

    def __init__(self, name: str = 'Detect shadowing') -> None:
        super().__init__(name)
        self._rules_seen: list[CompRule] = []

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        # Skip rules that shouldn't participate in shadowing checks
        if rule.fallback or rule.hidden:
            return True
        if rule.get_neg('src') or rule.get_neg('dst') or rule.get_neg('srv'):
            return True
        if rule.action in (
            PolicyAction.Branch,
            PolicyAction.Continue,
            PolicyAction.Return,
            PolicyAction.Accounting,
        ):
            return True

        for prev in self._rules_seen:
            if prev.abs_rule_number == rule.abs_rule_number:
                continue
            if self._rule_shadows(prev, rule):
                self.compiler.abort(
                    prev,
                    f"Rule '{prev.label}' shadows rule '{rule.label}' below it",
                )
                break

        self._rules_seen.append(rule)
        return True

    def _rule_shadows(self, r1: CompRule, r2: CompRule) -> bool:
        """Return True if r1 is more general than r2 (r1 shadows r2)."""
        # Skip r1 candidates with special properties
        if r1.get_neg('src') or r1.get_neg('dst') or r1.get_neg('srv'):
            return False
        if r1.action in (
            PolicyAction.Branch,
            PolicyAction.Continue,
            PolicyAction.Return,
            PolicyAction.Accounting,
        ):
            return False
        # Routing rules may or may not be terminal — skip
        if r1.get_option('routing', False) or r2.get_option('routing', False):
            return False
        # r2 with Continue action is non-terminating, can't be shadowed
        if r2.action == PolicyAction.Continue:
            return False

        # Chain check: rules in different chains can't shadow each other
        if r1.ipt_chain and r2.ipt_chain and r1.ipt_chain != r2.ipt_chain:
            return False

        # Interface check (matches C++ checkInterfacesForShadowing):
        # r1=above, r2=below. If above is "any" interface → can shadow.
        # If above is specific and below is "any" → can't shadow.
        # If both specific → must match.
        r1_itf = r1.itf[0] if r1.itf else None  # above rule
        r2_itf = r2.itf[0] if r2.itf else None  # below rule
        if r1_itf is None:
            pass  # r1 is "any" interface → can shadow anything
        elif r2_itf is None:
            return False  # r1 specific, r2 "any" → can't shadow
        else:
            r1_id = getattr(r1_itf, 'id', None)
            r2_id = getattr(r2_itf, 'id', None)
            if r1_id is not None and r2_id is not None and r1_id != r2_id:
                return False

        # Direction check: normalize Both to match the other rule's direction
        # (matches C++ PolicyCompiler::checkForShadowing)
        d1 = r1.direction or Direction.Both
        d2 = r2.direction or Direction.Both
        if d1 == Direction.Both:
            d1 = d2
        if d2 == Direction.Both:
            d2 = d1
        if d1 != d2:
            return False

        # All three rule elements must satisfy containment
        return (
            self._element_shadows(r1.src, r2.src)
            and self._element_shadows(r1.dst, r2.dst)
            and self._srv_element_shadows(r1.srv, r2.srv)
        )

    @staticmethod
    def _element_shadows(e1: list, e2: list) -> bool:
        """Return True if address element e1 is a superset of e2.

        e1 shadows e2 when every object in e2 is "contained by" at
        least one object in e1.  An empty element (= "any") contains
        everything.
        """
        if not e1:  # e1 is "any" → contains everything
            return True
        if not e2:  # e2 is "any" → only contained by "any"
            return False
        return all(any(_addr_contains(a1, a2) for a1 in e1) for a2 in e2)

    @staticmethod
    def _srv_element_shadows(e1: list, e2: list) -> bool:
        """Return True if service element e1 is a superset of e2."""
        if not e1 and not e2:  # both "any" → no shadowing (C++ semantics)
            return False
        if not e1:  # e1 is "any" → contains everything
            return True
        if not e2:  # e2 is "any" → only contained by "any"
            return False
        return all(any(_srv_contains(s1, s2) for s1 in e1) for s2 in e2)


def _addr_contains(a1, a2) -> bool:
    """Return True if address a1 contains (is a superset of) a2.

    Uses the ipaddress module for network/host containment checks.
    """
    if a1 is a2 or a1.id == a2.id:
        return True

    # "any" address contains everything
    if isinstance(a1, Address) and a1.is_any():
        return True
    if isinstance(a2, Address) and a2.is_any():
        return False

    try:
        r1 = _addr_range(a1)
        r2 = _addr_range(a2)
    except (ValueError, TypeError):
        return False

    if r1 is None or r2 is None:
        return False

    return r1[0] <= r2[0] and r2[1] <= r1[1]


def _addr_range(obj) -> tuple | None:
    """Return (first_addr, last_addr) for an address object."""
    if isinstance(obj, AddressRange):
        start = obj.get_start_address()
        end = obj.get_end_address()
        if start and end:
            return (_ipa.ip_address(start), _ipa.ip_address(end))
        return None

    if isinstance(obj, (Network, NetworkIPv6)):
        addr_s = obj.get_address()
        mask_s = obj.get_netmask()
        if addr_s and mask_s:
            try:
                net = _ipa.ip_network(f'{addr_s}/{mask_s}', strict=False)
                return (net.network_address, net.broadcast_address)
            except ValueError:
                return None
        return None

    # Single host / IPv4 / IPv6 / Interface address
    if isinstance(obj, Address):
        addr_s = obj.get_address()
        if addr_s:
            addr = _ipa.ip_address(addr_s)
            return (addr, addr)
    return None


def _srv_data_val(srv, key: str) -> str:
    """Get a service data-dict value as a string for comparison.

    Matches C++ ``FWObject::getStr()`` semantics: missing/None → empty string.
    """
    if not srv.data:
        return ''
    val = srv.data.get(key)
    if val is None or val == '':
        return ''
    return str(val)


_IP_FLAGS = ('fragm', 'short_fragm', 'lsrr', 'ssrr', 'rr', 'ts')


def _srv_contains(s1, s2) -> bool:
    """Return True if service s1 contains (is a superset of) s2."""
    if s1 is s2 or s1.id == s2.id:
        return True

    s1_any = isinstance(s1, Service) and s1.is_any()
    s2_any = isinstance(s2, Service) and s2.is_any()
    # C++: both "any" → false (no shadowing between identical "any" services)
    if s1_any and s2_any:
        return False
    # "any" service contains specific
    if s1_any:
        return True
    # specific cannot contain "any"
    if s2_any:
        return False

    # IPService: check IP flags + TOS/DSCP before protocol comparison
    # (C++ Compiler_ops.cpp:373-400)
    if isinstance(s1, IPService) and isinstance(s2, IPService):
        # All six IP option flags must match
        for flag in _IP_FLAGS:
            if _srv_data_val(s1, flag) != _srv_data_val(s2, flag):
                return False
        # TOS and DSCP codes must match
        if _srv_data_val(s1, 'tos_code') != _srv_data_val(s2, 'tos_code'):
            return False
        if _srv_data_val(s1, 'dscp_code') != _srv_data_val(s2, 'dscp_code'):
            return False
        p1 = s1.get_protocol_number()
        p2 = s2.get_protocol_number()
        if p1 == p2:
            return True
        # proto 0 (any IP) in s1 shadows specific proto in s2
        return p1 == 0

    # TCP/UDP port range containment
    if isinstance(s1, TCPUDPService) and isinstance(s2, TCPUDPService):
        if s1.get_protocol_number() != s2.get_protocol_number():
            return False
        # TCP flag check: flags and masks must match (C++ Compiler_ops.cpp:406-415)
        if isinstance(s1, TCPService) and isinstance(s2, TCPService):
            if (s1.tcp_flags or {}) != (s2.tcp_flags or {}):
                return False
            if (s1.tcp_flags_masks or {}) != (s2.tcp_flags_masks or {}):
                return False
        srs1 = s1.src_range_start or 0
        sre1 = s1.src_range_end or 0
        drs1 = s1.dst_range_start or 0
        dre1 = s1.dst_range_end or 0
        srs2 = s2.src_range_start or 0
        sre2 = s2.src_range_end or 0
        drs2 = s2.dst_range_start or 0
        dre2 = s2.dst_range_end or 0
        # Normalize: 0 means "any" → full range (C++ uses 65536)
        if srs1 == 0 and sre1 == 0:
            srs1, sre1 = 0, 65536
        if drs1 == 0 and dre1 == 0:
            drs1, dre1 = 0, 65536
        if srs2 == 0 and sre2 == 0:
            srs2, sre2 = 0, 65536
        if drs2 == 0 and dre2 == 0:
            drs2, dre2 = 0, 65536
        return srs1 <= srs2 and sre2 <= sre1 and drs1 <= drs2 and dre2 <= dre1

    # ICMP: type -1 (any) in s1 shadows specific type in s2
    # C++: returns (o1.type != -1 && o2.type == -1) where o1=below, o2=above
    # Python: s1=above, s2=below, so: (s2.type != -1 && s1.type == -1)
    if isinstance(s1, ICMPService) and isinstance(s2, ICMPService):
        if type(s1) is not type(s2):  # ICMPv4 vs ICMPv6
            return False
        codes1 = s1.codes or {}
        codes2 = s2.codes or {}
        t1 = codes1.get('type', -1)
        t2 = codes2.get('type', -1)
        return t2 != -1 and t1 == -1

    # Cross-type: IPService with proto=0 and all IP flags cleared
    # can shadow any other service type (C++ Compiler_ops.cpp:453-474)
    if isinstance(s1, IPService) and not isinstance(s2, IPService):
        if s1.get_protocol_number() != 0:
            return False
        data = s1.data or {}
        for flag in _IP_FLAGS:
            val = data.get(flag)
            if val is not None and str(val) == 'True':
                return False
        return True

    return False


class AssignUniqueRuleId(BasicRuleProcessor):
    """Assign sequential abs_rule_number to each rule."""

    def __init__(self, name: str = 'Assign unique rule ID') -> None:
        super().__init__(name)
        self._counter = 0

    def process_next(self) -> bool:

        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False
        rule.abs_rule_number = self._counter
        self._counter += 1
        self.tmp_queue.append(rule)
        return True
