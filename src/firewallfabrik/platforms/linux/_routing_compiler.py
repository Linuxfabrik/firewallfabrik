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

"""Linux routing compiler: generates 'ip route' commands.

Corresponds to fwbuilder's iptlib/routing_compiler_ipt.py.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._routing_compiler import RoutingCompiler
from firewallfabrik.compiler._rule_processor import RoutingRuleProcessor
from firewallfabrik.compiler.processors._generic import Begin
from firewallfabrik.core.objects import (
    Address,
    Firewall,
    Interface,
    Network,
    NetworkIPv6,
)
from firewallfabrik.core.options import RuleOption

if TYPE_CHECKING:
    import sqlalchemy.orm


class RoutingCompilerLinux(RoutingCompiler):
    """Compiles routing rules into 'ip route' commands for Linux."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
    ) -> None:
        super().__init__(session, fw, ipv6_policy)
        self.ecmp_rules_buffer: dict[str, str] = {}
        self.ecmp_comments_buffer: dict[str, str] = {}
        self.have_default_route: bool = False

    def compile(self) -> None:
        banner = f" Compiling routing rules for '{self.fw.name}'"
        self.info(banner)

        self.add(Begin())
        self.add(RoutingPrintRule('generate ip route commands'))
        self.run_rule_processors()

    def epilog(self) -> None:
        """Output ECMP routing rules if any exist."""
        if self.ecmp_rules_buffer:
            for key, comment in self.ecmp_comments_buffer.items():
                self.output.write(comment)
                rule_cmd = self.ecmp_rules_buffer.get(key, '')
                if rule_cmd:
                    self.output.write(rule_cmd)
                    self.output.write('\n')


class RoutingPrintRule(RoutingRuleProcessor):
    """Generates 'ip route' commands from routing CompRules."""

    def __init__(self, name: str = 'generate ip route commands') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        output = self._routing_rule_to_string(rule)
        if output:
            self.compiler.output.write(output)
            self.compiler.output.write('\n')

        self.tmp_queue.append(rule)
        return True

    def _routing_rule_to_string(self, rule: CompRule) -> str:
        """Convert a routing CompRule to an 'ip route' command string."""
        parts = ['ip route add']

        dst = self._print_rdst(rule)
        gtw = self._print_rgtw(rule)
        itf = self._print_ritf(rule)
        metric = rule.get_option(RuleOption.METRIC, 0)

        if dst:
            parts.append(dst)
        if gtw:
            parts.append(f'via {gtw}')
        if itf:
            parts.append(f'dev {itf}')
        if metric and int(metric) > 0:
            parts.append(f'metric {metric}')

        return ' '.join(parts)

    def _print_rdst(self, rule: CompRule) -> str:
        """Print routing destination."""
        if not rule.rdst:
            return 'default'
        obj = rule.rdst[0]
        addr = self._print_addr(obj)
        return addr if addr else 'default'

    def _print_rgtw(self, rule: CompRule) -> str:
        """Print routing gateway."""
        if not rule.rgtw:
            return ''
        obj = rule.rgtw[0]
        return self._print_addr(obj)

    def _print_ritf(self, rule: CompRule) -> str:
        """Print routing interface."""
        if not rule.ritf:
            return ''
        obj = rule.ritf[0]
        if isinstance(obj, Interface):
            return obj.name
        return ''

    def _print_addr(self, obj) -> str:
        """Print an address object as CIDR notation."""
        if not isinstance(obj, Address):
            return ''

        addr_str = obj.get_address()
        mask_str = obj.get_netmask()
        if not addr_str:
            return ''

        if mask_str and isinstance(obj, (Network, NetworkIPv6)):
            try:
                net = ipaddress.ip_network(f'{addr_str}/{mask_str}', strict=False)
                return str(net)
            except ValueError:
                return addr_str

        return addr_str
