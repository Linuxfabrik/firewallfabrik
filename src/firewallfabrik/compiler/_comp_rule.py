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

"""CompRule dataclass and rule-loading helpers for the compilation pipeline.

CompRule is a mutable in-memory copy of a Rule used throughout the
compiler's processor chain.  SQLAlchemy model objects referenced from
element lists (src, dst, srv, …) are accessed read-only; the compiler
only mutates CompRule structure.
"""

from __future__ import annotations

import copy
import dataclasses
import uuid
from collections import defaultdict
from typing import Any

import sqlalchemy

from firewallfabrik.core._util import SLOT_VALUES
from firewallfabrik.core.objects import (
    Address,
    Direction,
    Group,
    Host,
    Interface,
    Interval,
    NATAction,
    NATRuleType,
    PolicyAction,
    RoutingRuleType,
    Rule,
    RuleSet,
    Service,
    group_membership,
    rule_elements,
)


@dataclasses.dataclass
class CompRule:
    """Mutable in-memory rule copy for the compilation pipeline."""

    id: uuid.UUID
    type: str  # 'PolicyRule', 'NATRule', 'RoutingRule'
    position: int
    label: str
    comment: str
    options: dict  # copy of Rule.options JSON
    negations: dict  # copy of Rule.negations JSON

    # Rule elements — lists of resolved SQLAlchemy model objects.
    # Empty list [] = element is "any" (matches everything).
    src: list = dataclasses.field(default_factory=list)
    dst: list = dataclasses.field(default_factory=list)
    srv: list = dataclasses.field(default_factory=list)
    itf: list = dataclasses.field(default_factory=list)
    when: list = dataclasses.field(default_factory=list)

    # NAT-specific elements
    osrc: list = dataclasses.field(default_factory=list)
    odst: list = dataclasses.field(default_factory=list)
    osrv: list = dataclasses.field(default_factory=list)
    tsrc: list = dataclasses.field(default_factory=list)
    tdst: list = dataclasses.field(default_factory=list)
    tsrv: list = dataclasses.field(default_factory=list)
    itf_inb: list = dataclasses.field(default_factory=list)
    itf_outb: list = dataclasses.field(default_factory=list)

    # Routing-specific elements
    rdst: list = dataclasses.field(default_factory=list)
    rgtw: list = dataclasses.field(default_factory=list)
    ritf: list = dataclasses.field(default_factory=list)

    # Action/direction (from Rule columns, stored as enums)
    action: PolicyAction | NATAction | None = None
    direction: Direction | None = None
    nat_rule_type: NATRuleType | None = None
    routing_rule_type: RoutingRuleType | None = None

    # State flags
    disabled: bool = False
    fallback: bool = False
    hidden: bool = False

    # Compilation metadata (set during processing)
    abs_rule_number: int = 0
    ipt_chain: str = ''
    ipt_target: str = ''
    rule_weight: int = 0
    compiler_message: str = ''

    # Interface resolution (set by InterfaceAndDirection, read by PrintRule)
    iface_label: str = ''  # '', 'nil', or interface name
    nat_iface_in: str = ''
    nat_iface_out: str = ''

    # Action/logging metadata
    stored_action: str = ''
    nft_log: bool = False  # nftables inline log + verdict
    force_state_check: bool = False
    upstream_rule_chain: str = ''  # iptables logging chain tracking
    final: bool = False  # marks terminal logging rule
    parent_rule_num: str = ''  # parent rule position for log prefix
    subrule_suffix: str = ''  # label suffix for subrules

    # Negation flags
    src_single_object_negation: bool = False
    dst_single_object_negation: bool = False
    itf_single_object_negation: bool = False
    osrc_single_object_negation: bool = False
    odst_single_object_negation: bool = False

    # Optimization flags
    ipt_multiport: bool = False  # iptables -m multiport
    merged_tcp_udp: bool = False  # nftables meta l4proto { tcp, udp }

    # Rule validity
    has_empty_re: bool = False

    def clone(self) -> CompRule:
        """Create a deep copy of this rule.

        Element lists are shallow-copied (new lists, same model objects),
        because the compiler never mutates the model objects themselves.
        """
        new = copy.copy(self)
        # Give the clone its own element lists
        for slot in SLOT_VALUES:
            setattr(new, slot, list(getattr(self, slot)))
        new.options = dict(self.options) if self.options else {}
        new.negations = dict(self.negations) if self.negations else {}
        return new

    def get_option(self, key: str, default: Any = None) -> Any:
        if self.options:
            val = self.options.get(key, default)
            if isinstance(val, str):
                if val.lower() == 'true':
                    return True
                if val.lower() == 'false':
                    return False
            return val
        return default

    def set_option(self, key: str, value: object) -> None:
        if self.options is None:
            self.options = {}
        self.options[key] = value

    def get_neg(self, slot: str) -> bool:
        """Return True if the given slot is negated."""
        if self.negations:
            return bool(self.negations.get(slot, False))
        return False

    def set_neg(self, slot: str, value: bool) -> None:
        if self.negations is None:
            self.negations = {}
        self.negations[slot] = value

    # Convenience "any" checks (empty list = any)
    def is_src_any(self) -> bool:
        return len(self.src) == 0

    def is_dst_any(self) -> bool:
        return len(self.dst) == 0

    def is_srv_any(self) -> bool:
        return len(self.srv) == 0

    def is_itf_any(self) -> bool:
        return len(self.itf) == 0

    # NAT-specific convenience
    def is_osrc_any(self) -> bool:
        return len(self.osrc) == 0

    def is_odst_any(self) -> bool:
        return len(self.odst) == 0

    def is_osrv_any(self) -> bool:
        return len(self.osrv) == 0

    def is_tsrc_any(self) -> bool:
        return len(self.tsrc) == 0

    def is_tdst_any(self) -> bool:
        return len(self.tdst) == 0

    def is_tsrv_any(self) -> bool:
        return len(self.tsrv) == 0


def _resolve_objects(session, target_ids):
    """Batch-resolve a set of UUIDs to their model objects.

    Looks up objects across Address, Service, Host, Interface, Interval,
    and Group tables.  Returns a dict mapping UUID -> model object.
    """
    if not target_ids:
        return {}

    result = {}
    id_list = list(target_ids)

    # Query each table that might hold referenced objects
    for model_class in (Address, Service, Host, Interface, Interval, Group):
        rows = (
            session.execute(
                sqlalchemy.select(model_class).where(
                    model_class.id.in_(id_list),
                ),
            )
            .scalars()
            .all()
        )
        for obj in rows:
            result[obj.id] = obj

    return result


def load_rules(session, rule_set: RuleSet) -> list[CompRule]:
    """Load all rules from a RuleSet and return them as CompRule instances.

    Queries the Rule objects for the given RuleSet, fetches the
    rule_elements association rows, batch-resolves target UUIDs to model
    objects, and constructs CompRule instances with populated element lists.
    """
    # 1. Fetch rules ordered by position
    rules = (
        session.execute(
            sqlalchemy.select(Rule)
            .where(Rule.rule_set_id == rule_set.id)
            .order_by(Rule.position),
        )
        .scalars()
        .all()
    )

    if not rules:
        return []

    rule_ids = [r.id for r in rules]

    # 2. Fetch all rule_elements rows for these rules, preserving order
    elem_rows = session.execute(
        sqlalchemy.select(rule_elements)
        .where(
            rule_elements.c.rule_id.in_(rule_ids),
        )
        .order_by(rule_elements.c.position),
    ).all()

    # 3. Collect all target UUIDs and batch-resolve
    all_target_ids = {row.target_id for row in elem_rows}
    obj_map = _resolve_objects(session, all_target_ids)

    # 4. Group element rows by (rule_id, slot)
    elements_by_rule: dict[uuid.UUID, dict[str, list]] = defaultdict(
        lambda: defaultdict(list),
    )
    for row in elem_rows:
        obj = obj_map.get(row.target_id)
        if obj is not None:
            # Skip "Any" and "Dummy" sentinel objects — they represent
            # "match anything" and should not appear in element lists.
            obj_name = getattr(obj, 'name', '')
            if obj_name in ('Any', 'Dummy'):
                continue
            elements_by_rule[row.rule_id][row.slot].append(obj)

    # 5. Build CompRule instances
    comp_rules = []
    for rule in rules:
        elems = elements_by_rule.get(rule.id, {})

        # Determine action/direction from the rule type columns
        action = None
        direction = None
        nat_rule_type = None
        routing_rule_type = None

        if rule.policy_action is not None:
            action = PolicyAction(rule.policy_action)
        if rule.nat_action is not None:
            action = NATAction(rule.nat_action)
        if rule.policy_direction is not None:
            direction = Direction(rule.policy_direction)
        if rule.nat_rule_type is not None:
            nat_rule_type = NATRuleType(rule.nat_rule_type)
        if rule.routing_rule_type is not None:
            routing_rule_type = RoutingRuleType(rule.routing_rule_type)

        # Check disabled via options
        disabled = False
        if rule.options:
            val = rule.options.get('disabled', False)
            if isinstance(val, str):
                disabled = val.lower() in ('true', '1', 'yes')
            else:
                disabled = bool(val)

        comp_rule = CompRule(
            id=rule.id,
            type=rule.type,
            position=rule.position,
            label=rule.label or '',
            comment=rule.comment or '',
            options=dict(rule.options) if rule.options else {},
            negations=dict(rule.negations) if rule.negations else {},
            # Element lists — get from resolved elements, empty = "any"
            src=elems.get('src', []),
            dst=elems.get('dst', []),
            srv=elems.get('srv', []),
            itf=elems.get('itf', []),
            when=elems.get('when', []),
            osrc=elems.get('osrc', []),
            odst=elems.get('odst', []),
            osrv=elems.get('osrv', []),
            tsrc=elems.get('tsrc', []),
            tdst=elems.get('tdst', []),
            tsrv=elems.get('tsrv', []),
            itf_inb=elems.get('itf_inb', []),
            itf_outb=elems.get('itf_outb', []),
            rdst=elems.get('rdst', []),
            rgtw=elems.get('rgtw', []),
            ritf=elems.get('ritf', []),
            action=action,
            direction=direction,
            nat_rule_type=nat_rule_type,
            routing_rule_type=routing_rule_type,
            disabled=disabled,
            fallback=rule.fallback,
            hidden=rule.hidden,
            compiler_message=rule.compiler_message or '',
        )
        comp_rules.append(comp_rule)

    return comp_rules


def expand_group(session, group, *, _seen: set | None = None) -> list:
    """Recursively expand a Group object into its leaf member objects.

    Returns a flat list of non-group objects (Address, Service, Host, etc.).
    Handles circular references via the _seen set.
    """
    if _seen is None:
        _seen = set()

    if group.id in _seen:
        return []
    _seen.add(group.id)

    # Query member IDs from the group_membership table, preserving order
    member_ids = (
        session.execute(
            sqlalchemy.select(group_membership.c.member_id)
            .where(
                group_membership.c.group_id == group.id,
            )
            .order_by(group_membership.c.position),
        )
        .scalars()
        .all()
    )

    if not member_ids:
        return []

    # Resolve member objects
    obj_map = _resolve_objects(session, set(member_ids))

    result = []
    for mid in member_ids:
        obj = obj_map.get(mid)
        if obj is None:
            continue
        if isinstance(obj, Group):
            result.extend(expand_group(session, obj, _seen=_seen))
        else:
            result.append(obj)

    return result
