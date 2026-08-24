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

from firewallfabrik.compiler.processors._policy import (
    KeepMangleTableRules as SharedKeepMangleTableRules,
)
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

        # TCPMSS clamping.  From 1.3.0 on the rule belongs to the mangle
        # table; the filter-table form the older releases want is emitted
        # by PolicyCompiler_ipt.print_automatic_rules, from the same
        # method, so the two tables cannot disagree about whether the
        # firewall gets one at all
        # (MangleTableCompiler_ipt::printAutomaticRulesForMangleTable).
        if version_compare(version, '1.3.0') >= 0:
            clamp = self.clamp_tcp_to_mss_rule()
            if clamp.startswith('#'):
                result += clamp
            elif clamp:
                result += self._automatic_rule_line(clamp)

        return result

    def have_connmark_rules(self) -> bool:
        return self.have_connmark

    def have_connmark_rules_in_output(self) -> bool:
        return self.have_connmark_in_output


class KeepMangleTableRules(SharedKeepMangleTableRules):
    """Keep only the rules that require the mangle table.

    The iptables spelling of the built-in chains, and the one hook the
    CLASSIFY target does not register for.
    """

    CLASSIFY_FORBIDDEN_CHAINS = ('PREROUTING',)
