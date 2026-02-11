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

"""OS configurator for Linux 2.4+ (iptables platform).

Generates OS-level shell script configuration sections: kernel parameters,
tool paths, module loading, interface configuration, etc.

Corresponds to fwbuilder's iptlib/os_configurator_linux24.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from firewallfabrik.compiler._os_configurator import OSConfigurator
from firewallfabrik.core.objects import Firewall, Interface
from firewallfabrik.driver._configlet import Configlet
from firewallfabrik.driver._interface_properties import LinuxInterfaceProperties
from firewallfabrik.platforms.iptables._utils import get_interface_var_name

if TYPE_CHECKING:
    import sqlalchemy.orm


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


class OSConfigurator_linux24(OSConfigurator):
    """OS configurator for Linux 2.4+ with iptables."""

    # Default tool paths
    TOOLS: ClassVar[list[tuple[str, str]]] = [
        ('LSMOD', 'lsmod'),
        ('MODPROBE', 'modprobe'),
        ('IPTABLES', 'iptables'),
        ('IP6TABLES', 'ip6tables'),
        ('IPTABLES_RESTORE', 'iptables_restore'),
        ('IP6TABLES_RESTORE', 'ip6tables_restore'),
        ('IP', 'ip'),
        ('IFCONFIG', 'ifconfig'),
        ('VCONFIG', 'vconfig'),
        ('BRCTL', 'brctl'),
        ('IFENSLAVE', 'ifenslave'),
        ('IPSET', 'ipset'),
        ('LOGGER', 'logger'),
    ]

    DEFAULT_TOOL_PATHS: ClassVar[dict[str, str]] = {
        'lsmod': 'lsmod',
        'modprobe': 'modprobe',
        'iptables': 'iptables',
        'ip6tables': 'ip6tables',
        'iptables_restore': 'iptables-restore',
        'ip6tables_restore': 'ip6tables-restore',
        'ip': 'ip',
        'ifconfig': 'ifconfig',
        'vconfig': 'vconfig',
        'brctl': 'brctl',
        'ifenslave': 'ifenslave',
        'ipset': 'ipset',
        'logger': 'logger',
    }

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6: bool = False,
    ) -> None:
        super().__init__(session, fw, ipv6)
        self.using_ipset: bool = False
        self.address_table_objects: dict[str, str] = {}
        self.virtual_addresses: list = []
        self.virtual_addresses_for_nat: dict[str, str] = {}
        self.known_interfaces: list[str] = []

        version = fw.version or ''
        if _version_compare(version, '1.4.1.1') >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set', False))

    def my_platform_name(self) -> str:
        return 'Linux24'

    def using_ipset_module(self) -> bool:
        return self.using_ipset

    # -- Firewall options --

    def process_firewall_options(self) -> str:
        """Generate kernel parameter settings from firewall options."""
        version = self.fw.version or ''
        result = ''

        # Kernel variables
        kernel_vars = Configlet('linux24', 'kernel_vars')
        kernel_vars.collapse_empty_strings(True)

        for opt_name in [
            'linux24_ip_dynaddr',
            'linux24_rp_filter',
            'linux24_accept_source_route',
            'linux24_accept_redirects',
            'linux24_log_martians',
            'linux24_icmp_echo_ignore_broadcasts',
            'linux24_icmp_echo_ignore_all',
            'linux24_icmp_ignore_bogus_error_responses',
            'linux24_tcp_window_scaling',
            'linux24_tcp_sack',
            'linux24_tcp_fack',
            'linux24_tcp_syncookies',
            'linux24_tcp_ecn',
            'linux24_tcp_timestamps',
        ]:
            val = str(self.fw.get_option(opt_name, '') or '')
            self._set_configlet_macro_str(val, kernel_vars, opt_name)

        for opt_name in [
            'linux24_tcp_fin_timeout',
            'linux24_tcp_keepalive_interval',
        ]:
            val = self.fw.get_option(opt_name, -1)
            try:
                val = int(val)
            except (ValueError, TypeError):
                val = -1
            self._set_configlet_macro_int(val, kernel_vars, opt_name)

        result += kernel_vars.expand()

        # Conntrack settings
        conntrack = Configlet('linux24', 'conntrack')
        conntrack.collapse_empty_strings(True)

        if _version_compare(version, '1.4.0') >= 0:
            conntrack.set_variable('iptables_version_ge_1_4', '1')
            conntrack.set_variable('iptables_version_lt_1_4', '0')
        else:
            conntrack.set_variable('iptables_version_ge_1_4', '0')
            conntrack.set_variable('iptables_version_lt_1_4', '1')

        for opt_name in [
            'linux24_conntrack_max',
            'linux24_conntrack_hashsize',
            'linux24_conntrack_tcp_be_liberal',
        ]:
            val = self.fw.get_option(opt_name, -1)
            try:
                val = int(val)
            except (ValueError, TypeError):
                val = -1
            self._set_configlet_macro_int(val, conntrack, opt_name)

        result += conntrack.expand()
        return result

    def _set_configlet_macro_str(
        self,
        val: str,
        configlet: Configlet,
        opt_name: str,
    ) -> None:
        if val:
            configlet.set_variable(f'if_{opt_name}', '1')
            configlet.set_variable(opt_name, val)
        else:
            configlet.set_variable(f'if_{opt_name}', '0')

    def _set_configlet_macro_int(
        self,
        val: int,
        configlet: Configlet,
        opt_name: str,
    ) -> None:
        if val >= 0:
            configlet.set_variable(f'if_{opt_name}', '1')
            configlet.set_variable(opt_name, str(val))
        else:
            configlet.set_variable(f'if_{opt_name}', '0')

    # -- Shell functions --

    def print_shell_functions(self, have_ipv6: bool = False) -> str:
        """Generate shell functions for the script."""
        parts = []

        shell_functions = Configlet('linux24', 'shell_functions')
        parts.append(shell_functions.expand())

        check_utils = Configlet('linux24', 'check_utilities')
        check_utils.remove_comments()
        check_utils.collapse_empty_strings(True)

        load_modules = bool(self.fw.get_option('load_modules', False))
        check_utils.set_variable('load_modules', load_modules)

        need_modprobe = (
            load_modules
            or bool(self.fw.get_option('configure_vlan_interfaces', False))
            or bool(self.fw.get_option('configure_bonding_interfaces', False))
        )
        check_utils.set_variable('need_modprobe', need_modprobe)

        use_iptables_restore = bool(self.fw.get_option('use_iptables_restore', False))
        check_utils.set_variable('need_iptables_restore', use_iptables_restore)
        check_utils.set_variable(
            'need_ip6tables_restore', use_iptables_restore and have_ipv6
        )
        check_utils.set_variable('need_ipset', self.using_ipset)

        parts.append(check_utils.expand())

        # Reset iptables
        version = self.fw.version or ''
        reset = Configlet('linux24', 'reset_iptables')
        if _version_compare(version, '1.4.20') >= 0:
            reset.set_variable('opt_wait', '-w')
        else:
            reset.set_variable('opt_wait', '')
        parts.append(reset.expand())

        # Update addresses
        update_addr = Configlet('linux24', 'update_addresses')
        parts.append(update_addr.expand())

        return '\n'.join(parts)

    # -- Tool paths --

    def print_path_for_all_tools(self, os_name: str = '') -> str:
        """Generate shell variable assignments for tool paths."""
        result = ''

        for var_name, tool_key in self.TOOLS:
            path = ''
            # 1. Check firewall options for user override
            opt_val = self.fw.get_option(f'linux24_path_{tool_key}', '')
            if opt_val:
                path = str(opt_val)
            # 2. Fall back to default paths
            if not path:
                path = self.DEFAULT_TOOL_PATHS.get(tool_key, '')
            if path:
                result += f'{var_name}="{path}"\n'

        return result

    # -- IP forwarding --

    def print_ip_forwarding_commands(self) -> str:
        """Generate IP forwarding configuration commands."""
        ip_fwd = Configlet('linux24', 'ip_forwarding')
        ip_fwd.remove_comments()
        ip_fwd.collapse_empty_strings(True)

        s = str(self.fw.get_option('linux24_ip_forward', '') or '')
        ip_fwd.set_variable('ipv4', bool(s))
        ip_fwd.set_variable('ipv4_forw', 1 if s in ('1', 'On', 'on') else 0)

        s = str(self.fw.get_option('linux24_ipv6_forward', '') or '')
        ip_fwd.set_variable('ipv6', bool(s))
        ip_fwd.set_variable('ipv6_forw', 1 if s in ('1', 'On', 'on') else 0)

        return ip_fwd.expand()

    # -- Module loading --

    def generate_code_for_protocol_handlers(self) -> str:
        """Generate module loading commands."""
        load_modules = Configlet('linux24', 'load_modules')
        load_modules.remove_comments()

        load_modules.set_variable(
            'load_modules', bool(self.fw.get_option('load_modules', False))
        )
        load_modules.set_variable('modules_dir', '/lib/modules/`uname -r`/kernel/net/')

        return load_modules.expand()

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

    def print_run_time_address_tables_code(self) -> str:
        """Generate code for runtime address table loading."""
        rt = Configlet('linux24', 'run_time_address_tables')
        rt.set_variable('using_ipset', 1 if self.using_ipset else 0)

        check_cmds = []
        load_cmds = []
        for name, source in self.address_table_objects.items():
            check_cmds.append(f'check_file "{name}" "{source}"')
            load_cmds.append(f'reload_address_table "{name}" "{source}"')

        rt.set_variable('check_files_commands', '\n'.join(check_cmds))
        rt.set_variable('load_files_commands', '\n'.join(load_cmds))

        return rt.expand()

    def add_virtual_address_for_nat(self, addr) -> None:
        """Register a virtual address needed for NAT."""
        if not self.fw.get_option('manage_virtual_addr', False):
            return
        self.virtual_addresses.append(addr)

    def register_multi_address_object(self, name: str, source: str) -> None:
        """Register an address table object for runtime loading."""
        self.address_table_objects[name] = source
