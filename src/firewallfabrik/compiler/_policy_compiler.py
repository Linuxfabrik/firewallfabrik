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

"""PolicyCompiler base class for policy rule set compilation.

Corresponds to fwbuilder's PolicyCompiler, rewritten for SQLAlchemy models
and CompRule dataclasses.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

import sqlalchemy

from firewallfabrik.compiler._comp_rule import load_rules
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.compiler.processors._generic import (
    Begin,
    ConvertAnyToNotFWForShadowing,
    ConvertToAtomic,
    DetectShadowing,
    DropRuleWithEmptyRE,
    EliminateDuplicatesInDST,
    EliminateDuplicatesInSRC,
    EliminateDuplicatesInSRV,
    ExpandGroups,
)
from firewallfabrik.compiler.processors._policy import (
    ExpandMultipleAddresses,
    InterfacePolicyRules,
    ItfNegation,
    is_mangle_only_rule_set,
    normalize_fw_part_of_any,
)
from firewallfabrik.core.objects import (
    Firewall,
    Interface,
    Policy,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


class PolicyCompiler(Compiler):
    """Compiler for policy rule sets (filter rules)."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
    ) -> None:
        super().__init__(session, fw, ipv6_policy)
        #: Rules the compiler was handed rather than read from the rule
        #: set: the cluster rules a member needs to see the other members.
        #: They go in front of the top rule set with negative positions,
        #: which is where `AutomaticRules::addMgmtRule` puts them.
        self.automatic_rules: list = []
        #: Which chains each chain jumps into.  A rule the pipeline moves
        #: into a temporary chain is still reached through the chain it
        #: came from, and what a match or a target may do is decided by the
        #: hook, not by the name of the chain the rule ends up in - so the
        #: checks that ask "is this the output chain" have to be able to
        #: follow the jumps.
        self.upstream_chains: dict[str, list[str]] = defaultdict(list)

    def insert_upstream_chain(self, parent: str, child: str) -> None:
        """Record that *parent* jumps into *child*."""
        self.upstream_chains[parent].append(child)

    def is_chain_descendant_of(
        self, chain: str, ancestor: str, seen: set[str] | None = None
    ) -> bool:
        """Is *chain* reachable from *ancestor* by following the jumps?

        What the kernel allows in a rule is decided by the hook, not by the
        name of the chain the rule is in: a match that registers for
        PREROUTING, INPUT and FORWARD is refused just as much in a chain
        the POSTROUTING chain jumps to.  Every processor that moves a rule
        into a temporary chain records the jump
        (`insert_upstream_chain`), so the question can be asked of the
        chain the rule ended up in.

        A chain can be reached from more than one place, so every parent is
        followed rather than the first one found, and `seen` keeps a jump
        graph that leads back on itself from looping here.
        """
        if chain == ancestor:
            return True
        if seen is None:
            seen = set()
        if chain in seen:
            return False
        seen.add(chain)
        return any(
            chain in children and self.is_chain_descendant_of(parent, ancestor, seen)
            for parent, children in self.upstream_chains.items()
        )

    def prolog(self) -> int:
        """Initialize compiler: load rules, assign labels, return count."""
        super().prolog()

        if self.source_ruleset is None:
            # Find the first Policy ruleset on this firewall
            policy = (
                self.session.execute(
                    sqlalchemy.select(Policy).where(
                        Policy.device_id == self.fw.id,
                    ),
                )
                .scalars()
                .first()
            )
            if policy is not None:
                self.source_ruleset = policy

        if self.source_ruleset is None:
            return 0

        # Load rules into CompRule instances
        self.rules = load_rules(self.session, self.source_ruleset)

        # "Assume firewall is part of any" is stored in five spellings and
        # every reader asks a number, so it is normalised once, here, the
        # way `PolicyCompiler_ipt::prolog` does it.
        normalize_fw_part_of_any(self.rules, self.fw)

        # The automatic cluster rules belong in front of the policy that
        # runs in the built-in chains, and nowhere else: a rule set that
        # is only reached by a Branch rule does not carry them, and
        # neither does a mangle-only one (`AutomaticRules::AutomaticRules`
        # picks the top Policy and skips a mangle-only rule set).
        if (
            self.automatic_rules
            and self.source_ruleset.top
            and not is_mangle_only_rule_set(self.source_ruleset)
        ):
            self.rules = [rule.clone() for rule in self.automatic_rules] + self.rules

        label_prefix = ''
        if self.source_ruleset.name != 'Policy':
            label_prefix = self.source_ruleset.name

        rule_counter = 0
        for comp_rule in self.rules:
            if not comp_rule.label:
                if comp_rule.is_itf_any():
                    comp_rule.label = self.create_rule_label(
                        label_prefix, 'global', comp_rule.position
                    )
                else:
                    iface_names = [
                        obj.name for obj in comp_rule.itf if isinstance(obj, Interface)
                    ]
                    comp_rule.label = self.create_rule_label(
                        label_prefix, ','.join(iface_names), comp_rule.position
                    )

            comp_rule.abs_rule_number = rule_counter
            rule_counter += 1

        return rule_counter

    def compile(self) -> None:
        """Override in platform-specific subclasses to add processors."""
        pass

    def add_rule_filter(self) -> None:
        """Add the processor that selects the rules this pass compiles.

        Override in platform-specific subclasses.  Every pipeline that
        reads the firewall's rules has to start with it, the shadowing
        pass included: the filter run and the mangle run see different
        rules, and a pass that skips the filter reasons about rules its
        own table never installs.
        """

    def can_match_inbound_in_postrouting(self, rule) -> bool:
        """Whether this back end can match *rule*'s incoming device there.

        The kernel offers it: since commit 28f8bfd1ac94 ("netfilter: Support
        iif matches in POSTROUTING", first in v5.5) the POST_ROUTING hook is
        entered with the device a routed packet came in on.  What differs is
        the back end, which is why the shared processor asks the compiler
        instead of deciding for itself.  The conservative answer belongs
        here: a back end that has not said it can, cannot.
        """
        return False

    def run_shadowing_pass(self) -> None:
        """Run a separate shadowing detection pass before the main compilation.

        Shadowing detection is platform-independent: it reasons about the
        logical coverage of one rule by another, not about iptables- or
        nftables-specific output. It therefore lives in the base class so
        both backends run the exact same detection and can never diverge
        (see issue #136).

        The pass builds its own processor pipeline that only produces
        warnings/errors via ``self.warning()`` / ``self.abort()`` without
        affecting the main compilation output. It runs before any negation
        processing so negated rule elements are still flagged as negated and
        are correctly skipped by DetectShadowing.

        Pipeline: Begin -> ItfNegation -> InterfacePolicyRules ->
        ConvertAnyToNotFWForShadowing -> ConvertToAtomic (full Cartesian
        product) -> DetectShadowing.

        Corresponds to fwbuilder's separate shadowing detection pass.
        """
        # Save the main processor chain and build the shadowing pipeline on a
        # fresh one, then restore the original chain afterwards.
        saved_processors = self.rule_processors
        self.rule_processors = []

        # The SplitIf*AnyForShadowing helpers are intentionally omitted (they
        # are ``#if 0`` in the C++ source): including them produced synthetic
        # fw->fw atomic variants from rules with "any" source or destination,
        # which then appeared to be shadowed by earlier rules that legitimately
        # targeted the firewall itself - emitting false positives.
        # On copies: the processors below expand groups and host objects in
        # place, and the main pass compiles the same rule objects afterwards.
        self.add(Begin('Detecting rule shadowing', clone=True))
        # The filter pass and the mangle pass compile different rules, so
        # they have to detect shadowing among different rules too
        # (PolicyCompiler_ipt::compile calls addRuleFilter() here as well).
        # Without it the mangle pass compares rules it never installs, and
        # the filter pass compares the rules of a mangle-only rule set,
        # which it drops right afterwards.
        self.add_rule_filter()
        # "Not eth1" is not a rule about eth1.  InterfacePolicyRules splits
        # the element into one rule per interface and does not ask whether
        # it is negated, so without this the comparison below is made
        # against exactly the interfaces the rule was written to leave out:
        # a shadowed pair goes unreported and an unrelated one is reported.
        # The C++ runs the full negation here for that reason, and says so
        # (PolicyCompiler_ipt::compile: "use full negation rule processor in
        # shadowing detection").
        self.add(ItfNegation('process negation in Itf'))
        # One rule per interface, or two rules naming different interfaces,
        # which can never see the same packet, are compared as if they could.
        self.add(InterfacePolicyRules('process interface policy rules'))
        self.add(ConvertAnyToNotFWForShadowing("convert 'any' to '!fw'"))
        # The comparison asks whether one address contains another, which a
        # group or a host object cannot answer: both have to be down to plain
        # addresses first.  Without this a rule with a host in its source was
        # never seen as covered by a rule with the network it sits in.
        self.add(ExpandGroups('expand groups'))
        self.add(EliminateDuplicatesInSRC('eliminate duplicates in SRC'))
        self.add(EliminateDuplicatesInDST('eliminate duplicates in DST'))
        self.add(EliminateDuplicatesInSRV('eliminate duplicates in SRV'))
        self.add(ExpandMultipleAddresses('expand multiple addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements', quiet=True))
        self.add(ConvertToAtomic('convert to atomic rules'))
        self.add(DetectShadowing('Detect shadowing'))

        self.run_rule_processors()

        self.rule_processors = saved_processors
