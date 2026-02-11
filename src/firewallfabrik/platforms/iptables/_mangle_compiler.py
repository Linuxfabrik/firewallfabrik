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

"""MangleTableCompiler_ipt: Mangle table compilation for iptables.

Corresponds to fwbuilder's iptlib/mangle_compiler_ipt.py.
Inherits from PolicyCompiler_ipt with my_table="mangle".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from firewallfabrik.compiler._rule_processor import PolicyRuleProcessor
from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator
    from firewallfabrik.core.objects import Firewall


def _version_compare(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""

    def _normalize(v):
        return [int(x) for x in v.split('.') if x.isdigit()]

    parts1 = _normalize(v1) if v1 else [0]
    parts2 = _normalize(v2) if v2 else [0]
    for a, b in zip(parts1, parts2, strict=False):
        if a < b:
            return -1
        if a > b:
            return 1
    if len(parts1) < len(parts2):
        return -1
    if len(parts1) > len(parts2):
        return 1
    return 0


class MangleTableCompiler_ipt(PolicyCompiler_ipt):
    """Compiler for the mangle table in iptables.

    Inherits from PolicyCompiler_ipt with my_table="mangle".
    Overrides add_rule_filter() to keep only mangle-relevant rules.
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
        oscnf: OSConfigurator | None = None,
        minus_n_commands: dict | None = None,
    ) -> None:
        super().__init__(session, fw, ipv6_policy, oscnf, minus_n_commands)
        self.my_table = 'mangle'
        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False

    def add_rule_filter(self) -> None:
        """Add KeepMangleTableRules instead of DropMangleTableRules."""
        self.add(KeepMangleTableRules('keep only rules that require mangle table'))

    def flush_and_set_default_policy(self) -> str:
        return ''

    def print_automatic_rules(self) -> str:
        return ''

    def print_automatic_rules_for_mangle_table(
        self, have_connmark: bool, have_connmark_in_output: bool
    ) -> str:
        """Generate automatic rules for the mangle table."""
        result = ''
        version = self.fw.version or ''
        ipv6 = self.ipv6_policy

        iptables_cmd = '$IP6TABLES' if ipv6 else '$IPTABLES'
        opt_wait = '-w ' if _version_compare(version, '1.4.20') >= 0 else ''

        if have_connmark:
            result += (
                f'{iptables_cmd} {opt_wait}-t mangle '
                f'-A PREROUTING -j CONNMARK --restore-mark\n'
            )

        if have_connmark_in_output:
            result += (
                f'{iptables_cmd} {opt_wait}-t mangle '
                f'-A OUTPUT -j CONNMARK --restore-mark\n'
            )

        # TCPMSS clamping for iptables >= 1.3.0
        if _version_compare(version, '1.3.0') >= 0 and self.fw.get_option(
            'clamp_mss_to_mtu', False
        ):
            result += (
                f'{iptables_cmd} {opt_wait}-t mangle '
                f'-A POSTROUTING -p tcp --tcp-flags SYN,RST SYN '
                f'-j TCPMSS --clamp-mss-to-pmtu\n'
            )

        return result

    def have_connmark_rules(self) -> bool:
        return self.have_connmark

    def have_connmark_rules_in_output(self) -> bool:
        return self.have_connmark_in_output


class KeepMangleTableRules(PolicyRuleProcessor):
    """Filter that keeps only rules destined for the mangle table.

    Keeps rules with tagging, routing, classification, CONNMARK,
    or rules from mangle-only rulesets.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        # Keep rules with tagging, routing, or classification options
        if (
            rule.get_option('tagging', False)
            or rule.get_option('routing', False)
            or rule.get_option('classification', False)
        ):
            self.tmp_queue.append(rule)
            return True

        # Keep rules with put_in_mangle_table option
        if rule.get_option('put_in_mangle_table', False):
            self.tmp_queue.append(rule)
            return True

        # Handle branch rules that need mangle table
        if rule.action == PolicyAction.Branch and rule.get_option(
            'ipt_branch_in_mangle', False
        ):
            self.tmp_queue.append(rule)
            return True

        # Check if rule belongs to a mangle-only ruleset
        if (
            self.compiler
            and self.compiler.source_ruleset
            and hasattr(self.compiler.source_ruleset, 'options')
        ):
            rs_opts = self.compiler.source_ruleset.options or {}
            mangle_only = rs_opts.get('mangle_only_rule_set', False)
            if isinstance(mangle_only, str):
                mangle_only = mangle_only.lower() == 'true'
            if mangle_only:
                self.tmp_queue.append(rule)
                return True

        # Drop all other rules (they go to filter table)
        return True
