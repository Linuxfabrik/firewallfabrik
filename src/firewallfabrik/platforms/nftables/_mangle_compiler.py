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

"""MangleCompiler_nft: mangle-table compilation for nftables.

A packet mark and a traffic class have to be set before the kernel makes
its routing decision, which the filter hooks run after.  nftables places
such rules the same way iptables does: in chains that hook in at the
mangle priority.  This compiler is the policy compiler restricted to the
rules that carry those options.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from firewallfabrik.platforms.nftables._policy_compiler import (
    KeepMangleTableRules,
    PolicyCompiler_nft,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator
    from firewallfabrik.core.objects import Firewall


class MangleCompiler_nft(PolicyCompiler_nft):
    """Policy compiler that fills the nftables mangle table."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
        oscnf: OSConfigurator | None = None,
    ) -> None:
        super().__init__(session, fw, ipv6_policy, oscnf)
        self.my_table = 'mangle'
        # All five hooks exist at the mangle priority: a rule keeps the
        # chain an earlier processor picked for it, which may well be
        # input, forward or output rather than pre-/postrouting.
        self.chain_rules = {
            'prerouting': [],
            'input': [],
            'forward': [],
            'output': [],
            'postrouting': [],
        }

    def add_rule_filter(self) -> None:
        self.add(KeepMangleTableRules('keep only rules that require the mangle table'))
