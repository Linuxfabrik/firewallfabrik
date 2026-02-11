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
