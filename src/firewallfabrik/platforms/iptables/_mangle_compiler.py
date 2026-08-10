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
from firewallfabrik.platforms.iptables._utils import (
    TARGET_FIRST_RELEASE,
    get_iptables_version,
    get_wait_option,
    version_compare,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.compiler._os_configurator import OSConfigurator
    from firewallfabrik.core.objects import Firewall


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

    def _automatic_rule_line(self, rule: str) -> str:
        """Wrap one automatic mangle rule in the current output format.

        fwbuilder builds these rules from ``_startRuleLine()`` /
        ``_endRuleLine()`` of the print rule processor
        (MangleTableCompiler_ipt::printAutomaticRulesForMangleTable), so
        they follow the same format as every other rule: a
        ``$IPTABLES -t mangle -A ...`` command in shell mode and a bare
        ``echo "-A ..."`` line in iptables-restore mode.  Emitting the
        shell command inside the ``( ... ) | $IPTABLES_RESTORE`` subshell
        would run it outside the restore stream, and the restore of the
        mangle table right afterwards would wipe the rule again.
        """
        if bool(self.fw.get_option('use_iptables_restore')):
            return f'echo "-A {rule}"\n'

        version = get_iptables_version(self.fw)
        iptables_cmd = '$IP6TABLES' if self.ipv6_policy else '$IPTABLES'
        opt_wait = get_wait_option(version)
        if opt_wait:
            opt_wait += ' '
        return f'{iptables_cmd} {opt_wait}-t mangle -A {rule}\n'

    def print_automatic_rules_for_mangle_table(
        self, have_connmark: bool, have_connmark_in_output: bool
    ) -> str:
        """Generate automatic rules for the mangle table."""
        result = ''
        version = get_iptables_version(self.fw)
        ipv6 = self.ipv6_policy

        # The rules that save a mark to the connection are already left out
        # of a ruleset whose tool has no CONNMARK target, so the ones that
        # restore it have nothing to restore and would only stop the
        # activation script (netfilter iptables extensions: CONNMARK reached
        # ip6tables in 1.3.5, libip6t_CONNMARK.c).
        connmark_ok = (
            version_compare(version, TARGET_FIRST_RELEASE['CONNMARK'][bool(ipv6)]) >= 0
        )

        if have_connmark and connmark_ok:
            result += self._automatic_rule_line('PREROUTING -j CONNMARK --restore-mark')

        if have_connmark_in_output and connmark_ok:
            result += self._automatic_rule_line('OUTPUT -j CONNMARK --restore-mark')

        # TCPMSS clamping.  Matches fwbuilder's
        # PolicyCompiler_PrintRule::_clampTcpToMssRule (and
        # MangleTableCompiler_ipt::print_automatic_rules): the rule is
        # emitted on the FORWARD chain (not POSTROUTING) of the mangle
        # table, guarded by the platform's IP-forwarding option.  For
        # IPv6 the TCPMSS target requires ip6tables >= 1.3.8.
        if version_compare(version, '1.3.0') >= 0 and self.fw.get_option(
            'clamp_mss_to_mtu'
        ):
            if ipv6:
                ipforw_raw = self.fw.get_option('linux24_ipv6_forward')
                min_version_ok = version_compare(version, '1.3.8') >= 0
            else:
                ipforw_raw = self.fw.get_option('linux24_ip_forward')
                min_version_ok = True
            ipforw_str = str(ipforw_raw or '').strip()
            ipforw = ipforw_str in ('', '1', 'On', 'on', 'True', 'true')
            if ipforw and min_version_ok:
                result += self._automatic_rule_line(
                    'FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN '
                    '-j TCPMSS --clamp-mss-to-pmtu'
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
