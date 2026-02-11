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

"""RoutingCompiler base class for routing rule set compilation.

Corresponds to fwbuilder's RoutingCompiler, rewritten for SQLAlchemy
models and CompRule dataclasses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy

from firewallfabrik.compiler._comp_rule import load_rules
from firewallfabrik.compiler._compiler import Compiler
from firewallfabrik.core.objects import (
    Firewall,
    Routing,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


class RoutingCompiler(Compiler):
    """Compiler for routing rule sets."""

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
            routing = (
                self.session.execute(
                    sqlalchemy.select(Routing).where(
                        Routing.device_id == self.fw.id,
                    ),
                )
                .scalars()
                .first()
            )
            if routing is not None:
                self.source_ruleset = routing

        if self.source_ruleset is None:
            return 0

        # Load rules into CompRule instances
        self.rules = load_rules(self.session, self.source_ruleset)

        rule_counter = 0
        for comp_rule in self.rules:
            if not comp_rule.label:
                comp_rule.label = self.create_rule_label('', 'main', comp_rule.position)
            comp_rule.abs_rule_number = rule_counter
            rule_counter += 1

        return rule_counter

    def compile(self) -> None:
        pass
