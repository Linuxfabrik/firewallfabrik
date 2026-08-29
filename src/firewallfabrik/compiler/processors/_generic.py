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
import re
import sys

import sqlalchemy

from firewallfabrik.compiler._combined_address import (
    CombinedAddress,
    host_matches_by_mac,
)
from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._interval_helpers import interval_problem
from firewallfabrik.compiler._rule_processor import (
    BasicRuleProcessor,
    NATRuleProcessor,
    PolicyRuleProcessor,
)
from firewallfabrik.core._options import option_is_true
from firewallfabrik.core._util import SLOT_VALUES
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    CustomService,
    Direction,
    DNSName,
    Group,
    Host,
    ICMP6Service,
    ICMPService,
    Interface,
    IPService,
    IPv4,
    IPv6,
    MultiAddress,
    NATRuleType,
    Network,
    NetworkIPv6,
    PhysAddress,
    PolicyAction,
    Service,
    TCPService,
    TCPUDPService,
    get_address_table_source,
    group_membership,
    is_run_time_address_table,
    netmask_prefix_length,
    normalize_mac_address,
)


def _is_runtime(obj: MultiAddress) -> bool:
    """Return True if the MultiAddress is marked for run-time resolution."""
    return bool((obj.data or {}).get('run_time', False))


def _get_group_members(session, group: Group) -> list:
    """Return the direct members of a group (without recursive expansion).

    Uses the ``group_membership`` association table to look up member IDs,
    then resolves them to model objects.  Needed by
    :class:`RecursiveGroupsInRE` to walk the group tree.
    """
    member_ids = (
        session.execute(
            sqlalchemy.select(group_membership.c.member_id).where(
                group_membership.c.group_id == group.id,
            ),
        )
        .scalars()
        .all()
    )
    if not member_ids:
        return []

    from firewallfabrik.compiler._comp_rule import _resolve_objects

    obj_map = _resolve_objects(session, set(member_ids))
    return [obj_map[mid] for mid in member_ids if mid in obj_map]


class Begin(BasicRuleProcessor):
    """Injects CompRules from the compiler's rules list into the pipeline.

    With *clone* the pipeline gets copies instead of the rules themselves.
    fwbuilder always works on copies (`Begin` puts them in
    ``compiler->dbcopy``); here the main pass deliberately works on the
    originals, so a second pipeline over the same rules - the shadowing
    detection - has to ask for copies. Without them any processor that
    modifies a rule in place, such as group or address expansion, changes
    what the main pass then compiles.
    """

    def __init__(self, name: str = 'Begin', clone: bool = False) -> None:
        super().__init__(name)
        self._init = False
        self._clone = clone

    def process_next(self) -> bool:
        if not self._init:
            for rule in self.compiler.rules:
                if rule.disabled:
                    continue
                self.tmp_queue.append(rule.clone() if self._clone else rule)
            self._init = True
            return bool(self.tmp_queue)
        return False


class PrintTotalNumberOfRules(BasicRuleProcessor):
    """Say how many rules the pass starts with, then pass them all through.

    Ports ``Compiler::printTotalNumberOfRules`` (Compiler.cpp:764), which
    every pass of the C++ compiler carries right behind ``Begin``.  The
    line only appears in verbose mode, where it is what makes a fwf trace
    line up with a fwb_ipt one when the two are diffed
    (docs/developer-guide/Debugging.md).
    """

    def __init__(self, name: str = 'Print total number of rules') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        if self.slurp():
            if getattr(self.compiler, 'verbose', False):
                self.compiler.info(f' processing {len(self.tmp_queue)} rules')
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

    An object that resolves to *nothing* - an address table whose file is
    empty or unreadable, a DNS name with no record for the family being
    compiled - stays in the element.  Replacing it with nothing would leave
    the element empty, and an empty element is "any" everywhere downstream:
    a rule written for the addresses in that file would match every address
    there is.  ``EmptyGroupsInRE`` runs next and answers for it the way
    fwbuilder does, naming the object.
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
                    resolved = self.compiler._resolve_multi_address(obj)
                    if not resolved:
                        new_elements.append(obj)
                        continue
                    new_elements.extend(resolved)
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

    @classmethod
    def _count_children(cls, compiler, obj, _seen: set | None = None) -> int:
        """Count effective leaf members of a group recursively.

        Matches C++ ``Compiler::emptyGroupsInRE::countChildren``, including
        its recursion: a group counts what its members count, never itself,
        because a group of empty groups is empty too.

        A run-time MultiAddress counts as 1 - what is in it is not known
        until the script runs.  A compile-time one counts what it resolved
        to: an address table is a group whose members live in a file rather
        than in the data file, so asking the database how many children it
        has answers zero for every one of them.
        """
        if not isinstance(obj, Group):
            return 1
        if isinstance(obj, MultiAddress):
            if _is_runtime(obj):
                return 1
            return len(compiler._resolve_multi_address(obj))
        if _seen is None:
            _seen = set()
        if obj.id in _seen:
            return 0
        _seen.add(obj.id)
        return sum(
            cls._count_children(compiler, member, _seen)
            for member in _get_group_members(compiler.session, obj)
        )

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
            if isinstance(obj, Group) and self._count_children(self.compiler, obj) == 0:
                empty_groups.append(obj)

        if not empty_groups:
            self.tmp_queue.append(rule)
            return True

        if self.compiler.fw.get_option('ignore_empty_groups'):
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


class RecursiveGroupsInRE(BasicRuleProcessor):
    """Check for recursive (self-referencing) groups in a rule element slot.

    Corresponds to C++ ``Compiler::recursiveGroupsInRE``.  Runs **before**
    ``EmptyGroupsInRE`` and ``ExpandGroups``.  For each Group in the slot,
    recursively checks whether any nested group references itself or an
    ancestor, aborting compilation if it does.

    Each platform compiler adds one instance per slot it cares about
    (e.g. src, dst, srv for policy; osrc, odst, osrv for NAT).
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def _is_recursive_group(self, grid, obj) -> None:
        """Recursively check whether *obj* contains a reference back to *grid*.

        Matches C++ ``Compiler::recursiveGroupsInRE::isRecursiveGroup``.
        """
        if not isinstance(obj, Group):
            return

        members = _get_group_members(self.compiler.session, obj)
        for member in members:
            if not isinstance(member, Group):
                continue
            if member.id == grid or obj.id == member.id:
                name = getattr(member, 'name', str(member))
                self.compiler.abort(
                    None,
                    f"Group '{name}' references itself recursively",
                )
                return
            self._is_recursive_group(grid, member)
            self._is_recursive_group(member.id, member)

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        elements = getattr(rule, self._slot)
        if not elements:
            self.tmp_queue.append(rule)
            return True

        for obj in elements:
            if isinstance(obj, Group):
                self._is_recursive_group(obj.id, obj)

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
    """Split rules with multiple interfaces into separate rules.

    A negated interface element is kept whole: "on none of these
    interfaces" would turn into "not on this one" per rule, which every
    other interface of the set satisfies.
    """

    def __init__(self, name: str = 'Convert to atomic for interfaces') -> None:
        super().__init__(name)

    def process_next(self) -> bool:

        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        if len(rule.itf) <= 1 or rule.itf_single_object_negation:
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

    @staticmethod
    def _contained_addresses(obj):
        """Return the Address objects an Interface / Host carries."""
        if isinstance(obj, Interface):
            return list(obj.addresses or [])
        if isinstance(obj, Host):
            addrs = []
            for iface in obj.interfaces or []:
                addrs.extend(iface.addresses or [])
            return addrs
        return []

    def _should_drop(self, obj) -> bool:
        """Return True if this address object should be dropped.

        Family detection goes through ``is_v4()`` / ``is_v6()`` rather than
        ``get_address()``: an AddressRange keeps its endpoints in
        ``start_address`` / ``end_address`` and has an empty
        ``get_address()``, so gating on that would let a wrong-family range
        slip through the filter (and render an IPv4 range in an ip6 rule).
        Objects with no determinable family (e.g. MAC/PhysAddress) report
        neither v4 nor v6 and are always kept.

        Interface and Host objects are not Address instances but carry
        addresses; a single-stack interface used in the wrong family (e.g. an
        IPv6-only tunnel in the IPv4 pass, or an IPv4 host in the IPv6 pass)
        must be dropped, otherwise the print rule renders its only address in
        the wrong family and the ruleset fails to load. A dual-stack object
        is kept (the print rule then selects the matching address); an object
        with no addresses at all (dynamic / unnumbered) is also kept, since
        its family is only known at run time.
        """
        if isinstance(obj, Address):
            if self._drop_ipv6 and obj.is_v6():
                return True
            return bool(not self._drop_ipv6 and obj.is_v4())

        if isinstance(obj, (Interface, Host)):
            # Consider only real IP addresses. A MAC/PhysAddress reports
            # neither family; a MAC-only host is link-layer and family
            # neutral, so it must survive both passes rather than being
            # dropped as "wrong family".
            ip_addrs = [
                a for a in self._contained_addresses(obj) if a.is_v4() or a.is_v6()
            ]
            if not ip_addrs:
                return False
            want_v6 = not self._drop_ipv6
            keep = any(a.is_v6() if want_v6 else a.is_v4() for a in ip_addrs)
            return not keep

        return False

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
        """Filter ICMP / CustomService objects by address family.

        Matches fwbuilder ``Compiler::DropByServiceFamily``
        (libfwbuilder/fwcompiler/Compiler.cpp around line 1626), which
        uses ``Service::isV4Only()`` / ``isV6Only()``.  For
        ``CustomService`` those are driven by the ``address_family``
        XML attribute, stored as ``custom_address_family`` in fwf.

        Returns True if the rule should be dropped.
        """
        import socket

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
            elif isinstance(obj, CustomService):
                caf = getattr(obj, 'custom_address_family', None)
                if caf == socket.AF_INET and not self._drop_ipv6:
                    continue  # v4-only CustomService in IPv6 compile
                if caf == socket.AF_INET6 and self._drop_ipv6:
                    continue  # v6-only CustomService in IPv4 compile
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

    def __init__(
        self, name: str = 'Drop rules with empty RE', quiet: bool = False
    ) -> None:
        super().__init__(name)
        #: The shadowing pass runs on copies and installs nothing, so a
        #: rule it drops is one the main pass drops too and reports there.
        #: Repeating it would say twice, in two wordings, that one rule is
        #: gone.
        self._quiet = quiet

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
            # An element the address-family filter emptied is the ordinary
            # fate of a single-stack rule in the other family's pass, and
            # the rule is still compiled for the family it names.  fwbuilder
            # drops it without a word (`DropIPv4Rules` and `DropIPv6Rules`
            # carry an empty warning string), and saying something here
            # buries the reports that matter under one line per rule on
            # every dual-stack firewall.  Where the other family is not
            # compiled at all the rule really is gone, and then it is said.
            quiet = self._quiet or (
                getattr(rule, 'empty_re_family_only', False)
                and getattr(self.compiler, 'other_family_is_compiled', False)
            )
            if not quiet:
                # Saying so matters: the rule is in the policy, the GUI shows
                # it, and it is missing from this ruleset for a reason the
                # administrator cannot see anywhere else.
                reason = (
                    getattr(rule, 'empty_re_reason', '')
                    or 'one of its elements is empty'
                )
                self.compiler.warning(rule, f'Rule is left out because {reason}')
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
        # Each logical rule may expand into several compiled variants
        # (e.g. one per interface / address family).  Without deduplication
        # the same "Rule X shadows Rule Y below it" message is emitted
        # once per expanded variant pair, which is noise.  Track reported
        # (prev.position, rule.position) pairs and warn at most once.
        self._reported_shadows: set[tuple] = set()

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        # Skip rules that shouldn't participate in shadowing checks
        if rule.fallback or rule.hidden:
            return True
        # Negated elements never participate in shadowing.  Cover both the
        # raw negation flag and the single_object_negation flag: a platform
        # may already have moved the negation into single_object_negation
        # (e.g. nftables' native '!=') before shadowing runs, and a negated
        # element must not be treated as a plain match (see issue #136).
        if (
            rule.get_neg('src')
            or rule.get_neg('dst')
            or rule.get_neg('srv')
            or rule.src_single_object_negation
            or rule.dst_single_object_negation
            or rule.srv_single_object_negation
        ):
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
                # Atomic expansion of "any" destinations (e.g.
                # SplitIfDstAnyForShadowing splitting an outbound
                # "any" rule into a firewall-targeting INPUT copy)
                # can produce two atomic variants from different
                # logical rules that carry identical match elements.
                # Matching fwbuilder's ``!(*r == *rule)`` guard in
                # PolicyCompiler::DetectShadowing::processNext, skip
                # the warning when the two atomics are equivalent:
                # they encode the same effective match, not a real
                # shadow relationship.
                if self._rules_equivalent(prev, rule):
                    continue
                # Keyed by label, not position: a branch rule set numbers
                # its rules from 0 like every other one, so a position pair
                # alone reports the first rule set and silently swallows the
                # same finding in all the others.
                key = (prev.label, rule.label)
                if key not in self._reported_shadows:
                    self._reported_shadows.add(key)
                    self.compiler.warning(
                        f"Rule '{prev.label}' shadows rule '{rule.label}' below it"
                        + self._overlap(rule),
                    )
                break

        self._rules_seen.append(rule)
        return True

    @staticmethod
    def _overlap(rule: CompRule) -> str:
        """Name the one combination that is covered, if it is not the rule.

        The check runs on atomic rules - `ConvertToAtomic` splits every
        rule into one per (source, destination, service), in fwbuilder as
        much as here - so one atom of a rule being covered is enough to
        report it.  A rule naming five services of which one is covered is
        therefore reported like a rule that is dead, and an administrator
        who reads it that way deletes four working services with it.
        Saying which combination it was costs one clause and turns the
        sentence into something that can be acted on.
        """
        parts = []
        for slot, label in (('dst', 'destination'), ('srv', 'service')):
            objects = getattr(rule, slot) or []
            if len(objects) != 1:
                continue
            name = getattr(objects[0], 'name', '')
            if name:
                parts.append(f"{label} '{name}'")
        if not parts:
            return ''
        return ', for ' + ' and '.join(parts)

    @staticmethod
    def _rules_equivalent(r1: CompRule, r2: CompRule) -> bool:
        """Return True if two atomic rules carry identical match content."""
        d1 = r1.direction or Direction.Both
        d2 = r2.direction or Direction.Both
        if d1 != d2:
            return False
        if r1.action != r2.action:
            return False
        if (r1.ipt_chain or '') != (r2.ipt_chain or ''):
            return False
        for slot in ('src', 'dst', 'srv', 'itf'):
            e1 = getattr(r1, slot) or []
            e2 = getattr(r2, slot) or []
            if len(e1) != len(e2):
                return False
            ids1 = sorted(getattr(o, 'id', id(o)) for o in e1)
            ids2 = sorted(getattr(o, 'id', id(o)) for o in e2)
            if ids1 != ids2:
                return False
        return True

    def _rule_shadows(self, r1: CompRule, r2: CompRule) -> bool:
        """Return True if r1 is more general than r2 (r1 shadows r2)."""
        # Skip r1 candidates with special properties.  As in process_next,
        # cover single_object_negation too so a negated shadower cannot be
        # mistaken for a plain match (see issue #136).
        if (
            r1.get_neg('src')
            or r1.get_neg('dst')
            or r1.get_neg('srv')
            or r1.src_single_object_negation
            or r1.dst_single_object_negation
            or r1.srv_single_object_negation
        ):
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

        # A rule that only fires at a limited rate cannot cover one that
        # fires without a limit, or with a looser one.
        if not self._limits_allow_shadowing(r1, r2):
            return False

        # All three rule elements must satisfy containment
        return (
            self._element_shadows(r1.src, r2.src)
            and self._element_shadows(r1.dst, r2.dst)
            and self._srv_element_shadows(r1.srv, r2.srv)
        )

    @staticmethod
    def _limits_allow_shadowing(above: CompRule, below: CompRule) -> bool:
        """Return whether the rate limits let *above* shadow *below*.

        Ports ``PolicyCompiler_ipt::checkForShadowingPlatformSpecific``. A
        rule with a limit only acts on the packets that stay under it, so it
        covers a rule below only when its own limit is at least as generous
        and counts the same way. The comparison lives here rather than in
        the iptables compiler because the rule options are
        platform-independent and nftables renders them as ``limit rate``.
        """

        def rate(rule: CompRule, key: str) -> int:
            try:
                value = int(rule.get_option(key, 0) or 0)
            except (TypeError, ValueError):
                return 0
            # -1 is how the GUI stores "no limit", which is the loosest
            # setting there is.
            return sys.maxsize if value == -1 else value

        for value_key, companions in (
            ('limit_value', ('limit_value_not', 'limit_suffix')),
            ('connlimit_value', ('connlimit_value_not', 'connlimit_suffix')),
            (
                'hashlimit_value',
                ('hashlimit_suffix', 'hashlimit_mode', 'hashlimit_name'),
            ),
        ):
            above_rate = rate(above, value_key)
            below_rate = rate(below, value_key)
            if above_rate <= 0 and below_rate <= 0:
                continue
            if below_rate > above_rate:
                return False
            for key in companions:
                if str(above.get_option(key, '') or '') != str(
                    below.get_option(key, '') or ''
                ):
                    return False
        return True

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
        """Return True if service element e1 is a superset of e2.

        Two elements that are both "any" cover each other.  fwbuilder looks
        as if it said otherwise - `Compiler_ops.cpp:364` reads
        ``if (o1.isAny() && o2.isAny()) RETURN(false)`` - but the identity
        test three lines above it wins: both rules point at the *same* "any"
        service object, so ``o1.getId()==o2.getId()`` returns true first.
        That line only ever fires for two different objects that each report
        `isAny()`.  `_srv_contains` already models this correctly; only the
        shortcut for the empty list did not, which is why an
        "accept everything" above a "deny everything" - the most obvious
        shadowing there is - went unreported.
        """
        if not e1 and not e2:  # both "any" → the same object on both sides
            return True
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

    # "any" address contains everything (AddressRange has no is_any)
    if isinstance(a1, Address) and not isinstance(a1, AddressRange) and a1.is_any():
        return True
    if isinstance(a2, Address) and not isinstance(a2, AddressRange) and a2.is_any():
        return False

    try:
        r1 = _addr_range(a1)
        r2 = _addr_range(a2)
    except (ValueError, TypeError):
        return False

    if r1 is None or r2 is None:
        return False

    # Addresses of different families never contain one another. Comparing an
    # IPv4Address with an IPv6Address raises TypeError ("not of the same
    # version"), which would otherwise abort the whole shadowing pass.
    if r1[0].version != r2[0].version:
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
        if _srv_data_val(s1, 'tos') != _srv_data_val(s2, 'tos'):
            return False
        if _srv_data_val(s1, 'dscp') != _srv_data_val(s2, 'dscp'):
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
        return all(not option_is_true(data.get(flag)) for flag in _IP_FLAGS)

    return False


class ConvertAnyToNotFWForShadowing(PolicyRuleProcessor):
    """Create Return rules for fw when src/dst is 'any' and fw-is-part-of-any is off.

    For the shadowing detection pass: when 'firewall_is_part_of_any_and_networks'
    is off, 'any' does NOT include the firewall. To model this for shadowing,
    create a Return rule with fw in the relevant element.

    Corresponds to C++ PolicyCompiler::convertAnyToNotFWForShadowing. Shared by
    every platform's shadowing pass, so it lives here rather than in a specific
    backend.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        afpa = rule.get_option('firewall_is_part_of_any_and_networks', False)
        if not afpa:
            afpa = self.compiler.fw.get_option('firewall_is_part_of_any_and_networks')

        if not afpa:
            fw = self.compiler.fw

            if rule.is_src_any():
                r = rule.clone()
                r.action = PolicyAction.Return
                r.src = [fw]
                self.tmp_queue.append(r)

            if rule.is_dst_any():
                r = rule.clone()
                r.action = PolicyAction.Return
                r.dst = [fw]
                self.tmp_queue.append(r)

        self.tmp_queue.append(rule)
        return True


class CheckForTCPEstablished(BasicRuleProcessor):
    """Check for TCPService with deprecated 'established' flag.

    The 'established' option is not supported by iptables (or nftables).
    Use stateful rules instead.

    The rule goes with the message.  Neither packet filter has a match for
    that flag, so there is nothing to put in the rule's place: keeping it
    would compile "accept established connections to these ports" into
    "accept everything to these ports", which is a hole rather than a
    stricter reading.  The C++ throws here (fwbuilder
    libfwbuilder/src/fwcompiler/BaseCompiler.cpp, ``abort()``), so it emits
    nothing at all; fwf reports and carries on to show the administrator
    every problem at once, which only works if the offending rule is left
    out.

    Corresponds to C++ ``Compiler::CheckForTCPEstablished``.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        # Check srv for policy rules, osrv for NAT rules
        srv_slot = rule.srv if rule.type == 'PolicyRule' else getattr(rule, 'osrv', [])
        for srv in srv_slot:
            if isinstance(srv, TCPService):
                established = (srv.data or {}).get('established', False)
                if option_is_true(established):
                    self.compiler.abort(
                        rule,
                        f'TCPService object with option "established" is not '
                        f'supported by firewall platform '
                        f'"{self.compiler.my_platform_name()}". '
                        f'Use stateful rule instead. The rule is left out',
                    )
                    return True

        self.tmp_queue.append(rule)
        return True


class ReplaceClusterInterfaceInItfRE(BasicRuleProcessor):
    """Replace a cluster interface with the member firewall's own.

    A rule that comes from a cluster names the cluster's interface, and
    that interface exists on no machine: the two members may call theirs
    ``eth0`` and ``eth3``.  Compiled as it stands, the rule carries
    ``-i <cluster interface name>`` and matches nothing.

    Ports ``Compiler::replaceClusterInterfaceInItfRE``
    (Compiler.cpp:1102), which the C++ runs ahead of the interface
    negation in every pipeline that reads an interface rule element.  An
    interface the member does not have is left alone; the rule then names
    an interface of another object, which
    ``CheckForDynamicInterfacesOfOtherObjects`` and
    ``CheckInterfaceAgainstAddressFamily`` report.
    """

    def __init__(self, name: str, slot: str) -> None:
        super().__init__(name)
        self._slot = slot

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        from firewallfabrik.core.objects import Interface

        elements = getattr(rule, self._slot)
        if not elements:
            self.tmp_queue.append(rule)
            return True

        new_elements = []
        for obj in elements:
            member_iface = None
            if isinstance(obj, Interface) and obj.is_failover_interface():
                member_iface = obj.get_failover_group().get_interface_for_member(
                    self.compiler.fw
                )
            new_elements.append(member_iface if member_iface is not None else obj)

        setattr(rule, self._slot, new_elements)
        self.tmp_queue.append(rule)
        return True


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


class ExpandMultipleAddressesInNAT(NATRuleProcessor):
    """Replace a Host, Firewall or Interface in a NAT element by its addresses.

    Corresponds to C++ ``NATCompiler::ExpandMultipleAddresses``.  A host
    with several interfaces, or an interface with several addresses, stands
    for all of them, so the rule has to carry every one: the print rule
    would otherwise silently translate to the first address only.  Which
    elements are expanded follows the rule type, because a NONAT rule has
    no translated elements and a Redirect rule has no translated
    destination.
    """

    def _expand_slot(self, objects: list) -> list:
        """Expand one element list, replacing composite objects.

        A dynamic interface keeps its object: its address is only known at
        run time.  A loopback interface is skipped when it is reached
        through its parent host, because NAT never applies to it.

        An interface that carries a MAC address next to its addresses gives
        the same ``CombinedAddress`` the policy side builds, so the rule
        asks for the address *and* the MAC.  Without it the printer sees two
        objects and renders whichever sorts first, which turns "this host"
        into "anything with this MAC".
        """
        result = []
        for obj in objects:
            if isinstance(obj, Interface):
                if obj.is_dynamic():
                    result.append(obj)
                elif obj.is_loopback():
                    continue
                else:
                    result.extend(self._expand_interface(obj, obj.device))
            elif isinstance(obj, Host):
                for iface in getattr(obj, 'interfaces', []):
                    if iface.is_loopback():
                        continue
                    if iface.is_dynamic():
                        result.append(iface)
                    else:
                        result.extend(self._expand_interface(iface, obj))
            else:
                result.append(obj)

        def _sort_key(o):
            addr = getattr(o, 'get_address', lambda: None)()
            if addr is not None:
                try:
                    return _ipa.ip_address(addr).packed
                except (ValueError, TypeError):
                    pass
            return b'\xff' * 16

        result.sort(key=_sort_key)
        return result

    @staticmethod
    def _expand_interface(iface: Interface, host) -> list:
        """Return what one interface contributes, pairing MAC and address.

        The same three cases as ``Compiler._expand_interface``, minus the
        address-family filter, which the NAT pipeline leaves to
        ``DropIPv4Rules`` / ``DropIPv6Rules``.
        """
        addresses = []
        phys_address = None
        for addr in iface.addresses:
            if not addr.get_address():
                continue
            if isinstance(addr, PhysAddress):
                phys_address = addr
            else:
                addresses.append(addr)

        if phys_address is None or not host_matches_by_mac(host):
            return addresses
        if not addresses:
            return [phys_address]
        return [CombinedAddress(addr, phys_address) for addr in addresses]

    def _expand(self, rule: CompRule, slot: str) -> None:
        """Expand one slot of *rule*, flagging it if nothing is left.

        An empty element means "any", so a slot that held objects and holds
        none afterwards has to leave with the rule rather than widen it.
        """
        elements = getattr(rule, slot)
        expanded = self._expand_slot(elements)
        if elements and not expanded:
            rule.has_empty_re = True
            rule.empty_re_reason = (
                'the addresses it names carry nothing this rule can match on'
            )
        setattr(rule, slot, expanded)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        rt = rule.nat_rule_type
        if rt in (NATRuleType.NONAT, NATRuleType.Return):
            self._expand(rule, 'osrc')
            self._expand(rule, 'odst')
        elif rt in (NATRuleType.SNAT, NATRuleType.SDNAT, NATRuleType.DNAT):
            self._expand(rule, 'osrc')
            self._expand(rule, 'odst')
            self._expand(rule, 'tsrc')
            self._expand(rule, 'tdst')
        elif rt == NATRuleType.Redirect:
            self._expand(rule, 'osrc')
            self._expand(rule, 'odst')
            self._expand(rule, 'tsrc')

        return True


class NATSpecialCaseWithUnnumberedInterface(NATRuleProcessor):
    """Take an interface that has no address out of a NAT rule.

    An unnumbered interface and a bridge port carry no IP address, so
    neither can be matched as one.  Firewall Builder removes such an object
    from the element the rule translates on and keeps the rule if anything
    else is left, which is what an administrator naming several objects
    means (``NATCompiler_ipt::specialCaseWithUnnumberedInterface``,
    NATCompiler_ipt.cpp:970).  The element it looks at follows the rule
    type: the original source for Masquerade and SNAT, the original
    destination for DNAT.

    Shared by both NAT pipelines.  The nftables one had nothing here, and
    its print rule reports an addressless object and leaves out the *whole*
    rule - so a rule translating "this network and that bridge port"
    translated the network on one platform and nothing at all on the other.
    Neither NAT pipeline has the ``CheckForUnnumbered`` that makes this
    unreachable in the policy pipelines, here or in fwbuilder.
    """

    def __init__(self, name: str = 'handle unnumbered interfaces in NAT rules') -> None:
        super().__init__(name)

    @staticmethod
    def _drop_unnumbered(rule, slot: str) -> bool:
        """Return whether the rule still has something to match on.

        An element that was "any" to begin with stays "any"; one that this
        empties has lost everything the rule named, and an empty element
        reads as "any" downstream - which would translate every packet.
        """
        elements = getattr(rule, slot)
        if not elements:
            return True
        remaining = [
            obj
            for obj in elements
            if not (
                isinstance(obj, Interface)
                and (obj.is_unnumbered() or obj.is_bridge_port())
            )
        ]
        setattr(rule, slot, remaining)
        return bool(remaining)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        keep = True
        rule_type = rule.nat_rule_type
        if rule_type in (NATRuleType.Masq, NATRuleType.SNAT):
            keep = self._drop_unnumbered(rule, 'osrc')
        elif rule_type == NATRuleType.DNAT:
            keep = self._drop_unnumbered(rule, 'odst')
        if keep:
            self.tmp_queue.append(rule)
        return True


class NATCheckForDynamicInterfacesOfOtherObjects(NATRuleProcessor):
    """Leave out a NAT rule naming a dynamic interface of another object.

    A dynamic interface has no address until the firewall runs, and the
    generated script can only ask the host it runs on: an interface of
    another object has none to give.  Both back ends then write something
    that looks right and is not.  iptables writes ``$i_<name>``, a shell
    variable nothing assigns - ``getaddr`` only fills the ones for this
    firewall's own interfaces - so the command loses its argument and the
    activation stops with every chain already at DROP.  nftables writes
    ``@i_<name>``, a named set whose loader reads the *local* interface of
    that name, which silently translates for the wrong host.

    Ported from ``NATCompiler_ipt::checkForDynamicInterfacesOfOtherObjects``,
    whose C++ abort() throws, and shared by both NAT pipelines: the nftables
    one had no such check at all, so its version of the rule went out with
    no message either.  The policy pipelines have the mirror of this.
    """

    def __init__(self, name: str = 'check dynamic interfaces of other objects') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False
        fw = self.compiler.fw
        for slot in ('osrc', 'odst'):
            for obj in getattr(rule, slot):
                if not isinstance(obj, Interface) or not obj.is_dynamic():
                    continue
                if any(iface.id == obj.id for iface in fw.interfaces):
                    continue
                # An interface of the cluster this firewall is a member of
                # is not "another object"
                # (`NATCompiler_ipt::checkForDynamicInterfacesOfOtherObjects`
                # asks `isChildOf(cluster)` next to `isChildOf(fw)`).
                cluster = self.compiler.get_cluster()
                if cluster is not None and obj.device_id == cluster.id:
                    continue
                # `device` is the host or firewall the interface belongs to.
                device = getattr(obj, 'device', None)
                parent_name = getattr(device, 'name', '') or 'another object'
                self.compiler.abort(
                    rule,
                    f"Can not build rule using dynamic interface '{obj.name}' "
                    f"of the object '{parent_name}' because its address is "
                    'unknown. The rule is left out',
                )
                return True
        self.tmp_queue.append(rule)
        return True


class AddVirtualAddress(NATRuleProcessor):
    """Register virtual addresses needed for NAT with the OS configurator.

    Corresponds to C++ NATCompiler_ipt::addVirtualAddress.  Shared by
    both NAT pipelines: a virtual address is an interface address the
    firewall has to carry, which has nothing to do with the packet
    filter the rules are compiled for.
    For SNAT rules, registers TSrc as a virtual address if it is not
    an address on the firewall. For DNAT rules, registers ODst.
    For SNetnat/DNetnat, registers the network object.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        nat_comp = self.compiler

        if rule.nat_rule_type in (NATRuleType.SNAT, NATRuleType.DNAT):
            if rule.nat_rule_type == NATRuleType.SNAT:
                a = rule.tsrc[0] if rule.tsrc else None
            else:
                a = rule.odst[0] if rule.odst else None

            if a is None:
                return True

            # Skip non-regular interfaces
            if isinstance(a, Interface) and not a.is_regular():
                return True

            # AddressRange targets cannot be turned into interface aliases
            # (neither fwf nor fwbuilder implement that), so we simply skip
            # the virtual-address hook for them.  The DNAT/SNAT rule itself
            # is still compiled; the kernel only needs the virtual address
            # when a local process actually has to bind to the mapped IP,
            # which is not the common case.
            # An address the *cluster* carries is not a virtual address
            # either: the failover daemon puts it on the interface, and
            # adding it here would put it on every member at once
            # (`NATCompiler_ipt::addVirtualAddress` asks both).
            cluster = nat_comp.get_cluster()
            if (
                not nat_comp.complex_match(a, nat_comp.fw)
                and not (cluster is not None and nat_comp.complex_match(a, cluster))
                and not isinstance(a, AddressRange)
                and nat_comp.oscnf is not None
            ):
                nat_comp.oscnf.add_virtual_address_for_nat(a)

            return True

        if rule.nat_rule_type in (NATRuleType.SNetnat, NATRuleType.DNetnat):
            if rule.nat_rule_type == NATRuleType.SNetnat:
                a = rule.tsrc[0] if rule.tsrc else None
            else:
                a = rule.odst[0] if rule.odst else None

            if (
                a is not None
                and isinstance(a, Network | NetworkIPv6)
                and nat_comp.oscnf is not None
            ):
                # A NETMAP rule maps a whole network, so the firewall has to
                # answer for every address in it, not just the network
                # address.  This is fwbuilder's Network overload of
                # addVirtualAddressForNAT.
                nat_comp.oscnf.add_virtual_address_for_nat(a, expand_network=True)

            return True

        return True


def _prefix_length(obj) -> int | None:
    """Return the prefix length of a network object, or None.

    A netmask is stored as written, dotted for IPv4 and as a length for
    IPv6, so both spellings have to answer the same question -
    :func:`netmask_prefix_length` is the one reader that takes all of them.
    """
    if not isinstance(obj, (Network, NetworkIPv6)):
        return None
    return netmask_prefix_length(obj.get_address(), obj.get_netmask())


class VerifyRules(NATRuleProcessor):
    """Verify correctness of NAT rules.

    Corresponds to C++ ``NATCompiler_ipt::VerifyRules``, whose own
    regression firewall (`firewall2-4`, "tests for error conditions in
    NATCompiler_ipt::VerifyRules") is what the messages are worded after.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.get_neg('tsrc'):
            self.compiler.abort(rule, 'Can not use negation in translated source')
            return True

        if rule.get_neg('tdst'):
            self.compiler.abort(rule, 'Can not use negation in translated destination')
            return True

        if rule.get_neg('tsrv'):
            self.compiler.abort(rule, 'Can not use negation in translated service')
            return True

        # A translated service is one service or "Original".  Several of
        # them cannot be written out at all: the printer takes the first
        # and the rest of the translation is silently lost.
        if len(rule.tsrv) > 1:
            self.compiler.abort(
                rule,
                "Translated service should be 'Original' or should contain "
                'single object.',
            )
            return True

        if rule.tsrv and isinstance(rule.tsrv[0], Group):
            self.compiler.abort(rule, 'Can not use group in translated service.')
            return True

        if rule.nat_rule_type == NATRuleType.SNAT and rule.tsrc:
            tsrc = rule.tsrc[0]
            # A source translation writes one address, so a network object
            # would go out as its network address - every connection
            # translated to the `.0` of the network.
            if isinstance(tsrc, (Network, NetworkIPv6)):
                self.compiler.abort(
                    rule, 'Can not use network object in translated source.'
                )
                return True
            # An unnumbered interface never carries an address, so there is
            # nothing to translate the source to.  Corresponds to C++
            # NATCompiler_ipt::VerifyRules.
            if isinstance(tsrc, Interface) and tsrc.is_unnumbered():
                self.compiler.abort(
                    rule,
                    'Can not use unnumbered interface in Translated Source '
                    'of a Source translation rule.',
                )
                return True

        # A one-to-one network map needs the two networks to be the same
        # size.  NETMAP copies the host part across, so mapping a /24 onto
        # a /25 puts two source addresses on one translated address and
        # nothing says so.
        #
        # The C++ guards the destination case with `!tsrc->isAny()`, which
        # is never true for a destination map, so that half of its check
        # has never run; fwf asks about the element the rule translates.
        for kind, original, translated in (
            (NATRuleType.SNetnat, rule.osrc, rule.tsrc),
            (NATRuleType.DNetnat, rule.odst, rule.tdst),
        ):
            if rule.nat_rule_type != kind or not translated:
                continue
            first = _prefix_length(original[0]) if original else None
            second = _prefix_length(translated[0])
            if first is None or second is None or first != second:
                side = 'source' if kind == NATRuleType.SNetnat else 'destination'
                self.compiler.abort(
                    rule,
                    f'Original and translated {side} should both be networks '
                    'of the same size.',
                )
                return True

        self.tmp_queue.append(rule)
        return True


# The rule elements that can hold an address, per rule type.  A service
# element cannot, and an interface element holds interfaces.
_ADDRESS_SLOTS = {
    'PolicyRule': ('src', 'dst'),
    'NATRule': ('osrc', 'odst', 'tsrc', 'tdst'),
    'RoutingRule': ('rdst', 'rgtw'),
}


def address_range_problem(obj) -> str:
    """Return why *obj* names an address range neither tool takes, or ``''``.

    A range whose end is below its start describes nothing.  The two
    packet filters disagree about how bad that is: iptables takes the
    command and says "xt_iprange: range 10.0.0.9-10.0.0.1 is reversed and
    will never match", so the rule is installed and dead; nftables answers
    "Range negative size" and refuses the **whole** ruleset, so the
    firewall never gets the new policy at all.  Both verified against
    iptables 1.8.11 and nft 1.1.6.

    Firewall Builder corrects the value in its editor
    (``AddressRangeDialog::applyChanges`` moves the end up to the start)
    and its compiler never asks again.  A data file written by another
    tool, by hand, or by a FirewallFabrik older than this release carries
    whatever it carries.
    """
    if not isinstance(obj, AddressRange):
        return ''
    start = obj.get_start_address()
    end = obj.get_end_address()
    if not start or not end:
        return ''
    try:
        start_ip = _ipa.ip_address(start)
        end_ip = _ipa.ip_address(end)
    except ValueError:
        return ''
    if start_ip.version != end_ip.version or start_ip <= end_ip:
        return ''
    return f'runs from {start} down to {end}, which is not a range'


#: The object types whose editors write an address and a netmask that the
#: compilers read back as a pair.  PhysAddress carries a MAC, AddressRange
#: carries two endpoints and DNSName / AddressTable carry a name or a file,
#: so none of them is asked here.
_INET_ADDRESS_TYPES = (IPv4, IPv6, Network, NetworkIPv6)


def _inet_addresses_in(obj) -> list:
    """Every address object *obj* contributes that carries such a pair.

    Same walk as :func:`_macs_in`: an interface contributes its own
    addresses and a host or firewall the addresses of all its interfaces,
    because that is what the rule element ends up standing for.
    """
    if isinstance(obj, _INET_ADDRESS_TYPES):
        return [obj]
    if isinstance(obj, Interface):
        children = list(getattr(obj, 'addresses', []))
    elif isinstance(obj, Host):
        children = [
            addr
            for iface in getattr(obj, 'interfaces', [])
            for addr in getattr(iface, 'addresses', [])
        ]
    else:
        return []
    return [addr for addr in children if isinstance(addr, _INET_ADDRESS_TYPES)]


def inet_address_problem(obj) -> str:
    """Return why the address of *obj* cannot be compiled, or ``''``.

    The print rules pair the address with the netmask and print what comes
    out.  They used to answer a pair they could not read by leaving the
    netmask out and matching the address alone, so a rule written for a
    whole network was installed as a rule about a single host, in a script
    that loads without a word - which is what issue #154 was.

    :func:`netmask_prefix_length` closed most of that by taking every
    spelling a netmask reaches the compilers in.  What is left is a value
    that means nothing at all, and this is where it stops instead of
    turning into a rule about something else.  It is no longer reachable
    from the GUI - the editors normalise since this release - but a data
    file written by another tool, by hand, or by an older FirewallFabrik
    carries whatever it carries.
    """
    for addr in _inet_addresses_in(obj):
        address = addr.get_address()
        if not address:
            continue
        try:
            _ipa.ip_address(address)
        except ValueError:
            return (
                f'The address of "{addr.name}" is "{address}", which is not an '
                'IP address; iptables stops the activation over it and nftables '
                'refuses the whole ruleset.'
            )
        mask = addr.get_netmask()
        if not mask:
            continue
        if netmask_prefix_length(address, mask) is None:
            return (
                f'The netmask of "{addr.name}" is "{mask}", which is not a '
                f'netmask; the rule would match the single address {address} '
                'where a whole network is meant.'
            )
    return ''


def _macs_in(obj) -> list[str]:
    """Every MAC address *obj* contributes to a rule element.

    Deliberately not ``get_mac_only_address``, which answers the different
    question of whether an object can be matched on the ethernet header
    *alone*.  A host that carries an IP and a MAC contributes both, and the
    MAC half is emitted next to the address, so it has to be asked here
    too.
    """
    if isinstance(obj, CombinedAddress):
        return [obj.get_phys_address()] if obj.has_phys_address() else []
    if isinstance(obj, PhysAddress):
        return [obj.get_address() or '']
    if isinstance(obj, Interface):
        children = list(getattr(obj, 'addresses', []))
    elif isinstance(obj, Host):
        children = [
            addr
            for iface in getattr(obj, 'interfaces', [])
            for addr in getattr(iface, 'addresses', [])
        ]
    else:
        return []
    return [
        addr.get_address() or '' for addr in children if isinstance(addr, PhysAddress)
    ]


def mac_address_problem(obj) -> str:
    """Return why *obj* names a MAC neither tool takes, or ``''``.

    A physAddress carries free text from its editor and nothing has ever
    checked it - not here and not in Firewall Builder, whose
    ``physAddress`` class stores the string unread.  The value then goes
    straight into ``-m mac --mac-source`` and into ``ether saddr``, where
    iptables answers "Invalid MAC address specified." and stops the
    activation script with every chain already at DROP, and nftables
    answers a syntax error and refuses the whole ruleset.

    An object that carries no MAC at all is not this check's business: the
    print rules have reported and dropped that one since they were
    written, and a Host that simply has no physAddress must not lose its
    rule over it.
    """
    for mac in _macs_in(obj):
        if mac and not normalize_mac_address(mac):
            return f'"{mac}" is not a MAC address'
    return ''


class VerifyAddresses(BasicRuleProcessor):
    """Leave out a rule naming an address or netmask the compilers cannot read.

    Dropping the netmask instead is what the print rules do on their own,
    and that narrows a rule about a network down to a rule about one host
    without saying so, so the rule goes and the message names the value.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in _ADDRESS_SLOTS.get(rule.type, ('src', 'dst')):
            for obj in getattr(rule, slot, None) or []:
                problem = inet_address_problem(obj)
                if not problem:
                    continue
                self.compiler.error(
                    rule,
                    f'{problem} The rule is left out. Correct the address in '
                    'the object.',
                )
                return True

        self.tmp_queue.append(rule)
        return True


class VerifyMacAddresses(BasicRuleProcessor):
    """Leave out a rule naming a MAC address neither packet filter takes.

    Dropping the object instead would widen the rule to every host, and
    letting it through costs the activation on iptables and the whole
    ruleset on nftables, so the rule goes and the message names the value.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in _ADDRESS_SLOTS.get(rule.type, ('src', 'dst')):
            for obj in getattr(rule, slot, None) or []:
                problem = mac_address_problem(obj)
                if not problem:
                    continue
                self.compiler.error(
                    rule,
                    f'{problem}; iptables stops the activation over it and '
                    'nftables refuses the whole ruleset, so the rule is left '
                    'out. Correct the MAC address of the object.',
                )
                return True

        self.tmp_queue.append(rule)
        return True


class VerifyAddressRanges(BasicRuleProcessor):
    """Leave out a rule naming an address range that runs backwards.

    Writing the ends the other way round would cover addresses the
    administrator did not name, and dropping the element would widen the
    rule to every address, so the rule goes.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in _ADDRESS_SLOTS.get(rule.type, ('src', 'dst')):
            for obj in getattr(rule, slot, None) or []:
                problem = address_range_problem(obj)
                if not problem:
                    continue
                self.compiler.error(
                    rule,
                    f'Address range "{obj.name}" {problem}; iptables installs a '
                    'rule that can never match and nftables refuses the whole '
                    'ruleset, so the rule is left out. Correct the range in the '
                    'address range object.',
                )
                return True

        self.tmp_queue.append(rule)
        return True


# Three things an object is named after do not go into an iptables or nft
# rule, they go into the shell script the rules are wrapped in, and every
# guard written so far looked at the rule.  The data file of a run-time
# address table is read with `grep -Ev ... <file>` on iptables and handed
# to `check_address_table_file "<file>"` on nftables; a run-time DNS name
# is a bare word in `$IPTABLES -s <name>` and an argument of
# `load_dns_name "..." "<name>" ...`; and the name of a dynamic interface
# reaches `getaddr <iface>` and `load_interface_address "..." "<iface>"
# ...`.  A bare word is shell syntax outright, and inside double quotes a
# `$`, a backtick and a backslash are still expansion, substitution and
# escape - so a name holding one of them runs a command as root at the
# moment every chain is already set to DROP.
#
# Only a positive alphabet settles that, the same reasoning as for the
# rate-limit table name, the ToS value and the chain name.  A host name
# has letters, digits, dots, dashes and underscores; a path adds the
# separator and the `%DATADIR%` marker a stored file name may still carry;
# an interface name adds the colon of an alias and the wildcard the
# compiler turns into a glob.
_SCRIPT_HOST_NAME_RE = re.compile(r'[0-9A-Za-z_.-]+')
_SCRIPT_DATA_FILE_RE = re.compile(r'[0-9A-Za-z_./%-]+')
_SCRIPT_INTERFACE_RE = re.compile(r'[0-9A-Za-z_.:-]+[*+]?')

_SCRIPT_LITERAL_PROBLEM = (
    'which the generated activation script passes to a shell command: "$", '
    'a backtick, a semicolon and the like are syntax there and would run as '
    'root at the moment every chain is already set to drop'
)


def script_literal_problem(obj, fw=None) -> str:
    """Return why *obj*'s name cannot reach the script, or an empty string.

    Only the three run-time kinds are asked.  A compile-time address table
    and a compile-time DNS name are resolved by the compiler itself and
    never reach the script, and an interface with an address contributes
    the address rather than its name.
    """
    if is_run_time_address_table(obj):
        value = get_address_table_source(obj, fw)
        if fw is not None and '%DATADIR%' in value:
            # The token stands for the firewall's own "Data directory"
            # setting, and it is only resolved for a table read *on* the
            # firewall (AddressTable::getFilename).  With the setting empty
            # the token stays in the path and the script reads a directory
            # of that name, which does not exist: the activation stops on
            # the firewall over a file the compiler could have named here.
            # fwbuilder refuses to compile at all
            # (MultiAddressRunTime::getSourceNameAsPath answers an empty
            # path and processMultiAddressObjectsInRE aborts over it).
            # Without a firewall the token is what the resolution leaves
            # behind and says nothing about the setting, so it is only a
            # problem once a firewall has been asked.
            return (
                'is read from a file below "%DATADIR%" and the firewall names '
                'no data directory, so the script would look for a directory '
                'called "%DATADIR%"'
            )
        if value and not _SCRIPT_DATA_FILE_RE.fullmatch(value):
            return f'is read from the file "{value}", {_SCRIPT_LITERAL_PROBLEM}'
        return ''
    if isinstance(obj, DNSName) and _is_runtime(obj):
        value = (obj.data or {}).get('dnsrec') or obj.name
        if value and not _SCRIPT_HOST_NAME_RE.fullmatch(str(value)):
            return f'resolves the name "{value}", {_SCRIPT_LITERAL_PROBLEM}'
        return ''
    if isinstance(obj, Interface) and obj.is_dynamic():
        value = obj.name or ''
        if value and not _SCRIPT_INTERFACE_RE.fullmatch(value):
            return f'is the interface "{value}", {_SCRIPT_LITERAL_PROBLEM}'
    return ''


class VerifyScriptLiterals(BasicRuleProcessor):
    """Leave out a rule whose object names reach the script as shell text.

    A run-time address table, a run-time DNS name and a dynamic interface
    are the three objects the compiler cannot resolve itself, so their
    names travel into the generated script and are read there.  Emitting
    the rule without the object would widen it to every address, so the
    rule goes and the object is named.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        fw = getattr(self.compiler, 'fw', None)
        for slot in _ADDRESS_SLOTS.get(rule.type, ('src', 'dst')):
            for obj in getattr(rule, slot, None) or []:
                problem = script_literal_problem(obj, fw)
                if not problem:
                    continue
                self.compiler.error(
                    rule,
                    f'Object "{obj.name}" {problem}. The rule is left out; rename it.',
                )
                return True

        self.tmp_queue.append(rule)
        return True


class VerifyTimeIntervals(BasicRuleProcessor):
    """Leave out a rule whose time object names an hour or a day there is not.

    Neither packet filter can carry the value: iptables stops the
    activation script over a time of day past 23:59 and silently drops an
    eighth weekday, nftables refuses the whole ruleset over either.  See
    ``interval_problem`` for the netfilter sources that say so.  Rendering
    the rule without its time restriction would run it around the clock,
    so the rule goes and the message names the time object.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for interval in getattr(rule, 'when', None) or []:
            problem = interval_problem(interval.data or {})
            if not problem:
                continue
            self.compiler.error(
                rule,
                f'Time object "{interval.name}": {problem}. Neither iptables '
                'nor nftables can carry it, so the rule is left out. Correct '
                'the time object.',
            )
            return True

        self.tmp_queue.append(rule)
        return True
