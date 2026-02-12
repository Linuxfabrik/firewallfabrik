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
from firewallfabrik.core.objects import Firewall, Interface
from firewallfabrik.driver._configlet import Configlet
from firewallfabrik.driver._interface_properties import (
    LinuxInterfaceProperties,
    get_interface_var_name,
)

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
        self.known_interfaces: list[str] = []

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

    # -- Shell functions (reuses linux24 configlets) --

    def print_shell_functions(self) -> str:
        """Generate shell utility functions for interface management.

        Expands the linux24 ``shell_functions`` and ``update_addresses``
        configlets which provide ``getaddr()``, ``getnet()``,
        ``diff_intf()``, ``update_addresses_of_interface()``,
        ``missing_address()``, etc.
        """
        parts = []

        shell_functions = Configlet('linux24', 'shell_functions')
        parts.append(shell_functions.expand())

        update_addr = Configlet('linux24', 'update_addresses')
        parts.append(update_addr.expand())

        return '\n'.join(parts)

    # -- Interface configuration --

    def print_verify_interfaces_commands(self) -> str:
        """Generate interface verification commands."""
        interfaces = []
        for iface in self.fw.interfaces:
            name = iface.name
            if name and '*' not in name and name not in interfaces:
                interfaces.append(name)

        verify = Configlet('linux24', 'verify_interfaces')
        verify.set_variable('have_interfaces', len(interfaces))
        verify.set_variable('interfaces', ' '.join(interfaces))
        return verify.expand()

    def print_interface_configuration_commands(self) -> str:
        """Generate interface address configuration commands."""
        int_prop = LinuxInterfaceProperties()

        script = Configlet('linux24', 'configure_interfaces')
        script.remove_comments()
        script.collapse_empty_strings(True)

        need_promote_command = False
        gencmd: list[str] = []

        for iface in self.fw.interfaces:
            should_manage, update_addresses, ignore_addresses = (
                int_prop.manage_ip_addresses(iface)
            )

            if should_manage:
                gencmd.append(
                    self._print_update_address_command(
                        iface, update_addresses, ignore_addresses
                    )
                )
                need_promote_command = need_promote_command or len(update_addresses) > 2

            self.known_interfaces.append(iface.name)

        script.set_variable('have_interfaces', len(self.fw.interfaces) > 0)
        script.set_variable('need_promote_command', need_promote_command)
        script.set_variable('configure_interfaces_script', '\n'.join(gencmd))
        return script.expand() + '\n'

    @staticmethod
    def _print_update_address_command(
        iface: Interface,
        update_addresses: list[str],
        ignore_addresses: list[str],
    ) -> str:
        """Format an update_addresses_of_interface shell command."""
        update_addresses.insert(0, iface.name)
        return (
            f'update_addresses_of_interface '
            f'"{" ".join(update_addresses)}" '
            f'"{" ".join(ignore_addresses)}"'
        )

    def print_dynamic_addresses_configuration_commands(self) -> str:
        """Generate commands to get dynamic interface addresses."""
        result = ''
        for iface in self.fw.interfaces:
            if not iface.is_dynamic():
                continue
            name = iface.name
            if '*' in name:
                continue

            var_name = get_interface_var_name(iface)
            var_name_v6 = get_interface_var_name(iface, suffix='v6')
            result += f'getaddr {name}  {var_name}\n'
            result += f'getaddr6 {name}  {var_name_v6}\n'
            result += f'getnet {name}  {var_name}_network\n'
            result += f'getnet6 {name}  {var_name_v6}_network\n'

        return result

    def print_commands_to_clear_known_interfaces(self) -> str:
        """Generate commands to clear addresses on unknown interfaces."""
        if not self.fw.get_option('clear_unknown_interfaces', False):
            return ''
        if not self.known_interfaces:
            return ''
        return (
            f'clear_addresses_except_known_interfaces '
            f'"{" ".join(self.known_interfaces)}"\n'
        )
