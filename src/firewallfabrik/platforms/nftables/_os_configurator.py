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

"""OS configurator for nftables.

Generates nftables-specific preamble: flush ruleset, table/chain
declarations, default policies, and automatic rules (established,
related, etc.).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from firewallfabrik.compiler._os_configurator import OSConfigurator
from firewallfabrik.core.objects import Firewall

if TYPE_CHECKING:
    import sqlalchemy.orm


class OSConfigurator_nft(OSConfigurator):
    """OS configurator for nftables."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6: bool = False,
    ) -> None:
        super().__init__(session, fw, ipv6)

    def my_platform_name(self) -> str:
        return 'nftables'

    def generate_preamble(self) -> str:
        """Generate the nftables script preamble.

        Returns:
            The '#!/usr/sbin/nft -f' shebang and flush command.
        """
        lines = [
            '#!/usr/sbin/nft -f',
            '',
            'flush ruleset',
            '',
        ]
        return '\n'.join(lines)

    def generate_filter_table_header(self, have_ipv6: bool = False) -> str:
        """Generate the inet filter table and chain declarations.

        Uses `inet` family for dual-stack when IPv6 is present,
        otherwise uses `ip` family.
        """
        family = 'inet' if have_ipv6 else 'ip'

        lines = [
            f'table {family} filter {{',
        ]
        return '\n'.join(lines) + '\n'

    def generate_chain_header(
        self,
        chain_name: str,
        chain_type: str = 'filter',
        hook: str = 'input',
        priority: str | int = 'filter',
        policy: str = 'drop',
    ) -> str:
        """Generate a chain declaration with hook and policy.

        Example output:
            chain input {
                type filter hook input priority 0; policy drop;
        """
        lines = [
            f'    chain {chain_name} {{',
            f'        type {chain_type} hook {hook} priority {priority}; policy {policy};',
        ]
        return '\n'.join(lines) + '\n'

    def generate_chain_footer(self) -> str:
        """Close a chain block."""
        return '    }\n'

    def generate_table_footer(self) -> str:
        """Close a table block."""
        return '}\n'

    def generate_nat_table_header(self, have_ipv6: bool = False) -> str:
        """Generate the NAT table declaration.

        Uses `ip` family for NAT (nftables NAT in inet family requires
        kernel >= 5.2, so we use ip/ip6 for broader compatibility).
        """
        family = 'ip'
        lines = [
            f'table {family} nat {{',
        ]
        return '\n'.join(lines) + '\n'

    def generate_automatic_rules(self) -> str:
        """Generate automatic rules for the filter table.

        These are rules that are always present regardless of user
        policy, like accepting established/related connections.
        """
        rules = []

        # Accept established/related connections
        if self.fw.get_option('accept_established', False):
            rules.append('        ct state established,related accept')

        # Drop invalid packets
        drop_invalid = self.fw.get_option('drop_invalid', False)
        log_invalid = self.fw.get_option('log_invalid', False)
        if drop_invalid:
            if log_invalid:
                rules.append('        ct state invalid log prefix "INVALID " drop')
            else:
                rules.append('        ct state invalid drop')

        # Drop new TCP without SYN
        if self.fw.get_option('drop_new_tcp_with_no_syn', False):
            rules.append('        tcp flags != syn ct state new drop')

        return '\n'.join(rules) + '\n' if rules else ''
