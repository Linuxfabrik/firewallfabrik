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

"""Automatic rules for iptables: conntrack and failover.

Corresponds to fwbuilder's iptlib/automatic_rules_ipt.py.
Creates CompRule instances for conntrack established/related rules
and cluster failover protocol rules (VRRP, heartbeat, openais).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import (
    Direction,
    Firewall,
    PolicyAction,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


class AutomaticRulesIpt:
    """Generate automatic rules for iptables compilation."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
    ) -> None:
        self.session = session
        self.fw = fw

    def add_conntrack_rule(self) -> list[CompRule]:
        """Create ESTABLISHED,RELATED conntrack rules.

        Returns accept rules for established/related connections on all
        non-loopback interfaces.
        """
        rules = []
        for iface in self.fw.interfaces:
            if iface.is_loopback():
                continue

            rule = CompRule(
                id=uuid.uuid4(),
                type='PolicyRule',
                position=-1,
                label='CONNTRACK',
                comment='Roles: established,related',
                itf=[iface],
                action=PolicyAction.Accept,
                direction=Direction.Both,
            )
            rule.ipt_chain = 'INPUT'
            rules.append(rule)

            rule2 = rule.clone()
            rule2.id = uuid.uuid4()
            rule2.ipt_chain = 'OUTPUT'
            rules.append(rule2)

            rule3 = rule.clone()
            rule3.id = uuid.uuid4()
            rule3.ipt_chain = 'FORWARD'
            rules.append(rule3)

        return rules

    def add_failover_rules(
        self,
        cluster_protocol: str = '',
    ) -> list[CompRule]:
        """Create failover protocol rules (VRRP, heartbeat, openais).

        Returns rules allowing the failover protocol's multicast/broadcast
        traffic between cluster members.
        """
        rules = []

        if not cluster_protocol:
            return rules

        if cluster_protocol == 'vrrp':
            rules.extend(self._add_vrrp_rules())
        elif cluster_protocol == 'heartbeat':
            rules.extend(self._add_heartbeat_rules())
        elif cluster_protocol == 'openais':
            rules.extend(self._add_openais_rules())

        return rules

    def _add_vrrp_rules(self) -> list[CompRule]:
        """VRRP rules: allow VRRP multicast (224.0.0.18, protocol 112)."""
        rules = []
        for iface in self.fw.interfaces:
            if iface.is_loopback():
                continue

            # Allow VRRP protocol (IP protocol 112) to multicast address
            rule = CompRule(
                id=uuid.uuid4(),
                type='PolicyRule',
                position=-1,
                label='VRRP',
                comment='Roles: automatic VRRP rule',
                itf=[iface],
                action=PolicyAction.Accept,
                direction=Direction.Both,
            )
            rules.append(rule)

        return rules

    def _add_heartbeat_rules(self) -> list[CompRule]:
        """Heartbeat rules: allow UDP port 694."""
        rules = []
        for iface in self.fw.interfaces:
            if iface.is_loopback():
                continue

            rule = CompRule(
                id=uuid.uuid4(),
                type='PolicyRule',
                position=-1,
                label='Heartbeat',
                comment='Roles: automatic heartbeat rule',
                itf=[iface],
                action=PolicyAction.Accept,
                direction=Direction.Both,
            )
            rules.append(rule)

        return rules

    def _add_openais_rules(self) -> list[CompRule]:
        """OpenAIS rules: allow UDP port 5405."""
        rules = []
        for iface in self.fw.interfaces:
            if iface.is_loopback():
                continue

            rule = CompRule(
                id=uuid.uuid4(),
                type='PolicyRule',
                position=-1,
                label='OpenAIS',
                comment='Roles: automatic openais rule',
                itf=[iface],
                action=PolicyAction.Accept,
                direction=Direction.Both,
            )
            rules.append(rule)

        return rules
