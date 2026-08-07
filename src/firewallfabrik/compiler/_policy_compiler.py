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

        Pipeline: Begin -> ConvertAnyToNotFWForShadowing ->
        ConvertToAtomic (full Cartesian product) -> DetectShadowing.

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
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))
        self.add(ConvertToAtomic('convert to atomic rules'))
        self.add(DetectShadowing('Detect shadowing'))

        self.run_rule_processors()

        self.rule_processors = saved_processors
