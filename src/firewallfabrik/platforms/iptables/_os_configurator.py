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

import re
from typing import TYPE_CHECKING, ClassVar

from firewallfabrik.compiler._os_configurator import OSConfigurator
from firewallfabrik.core.objects import (
    Firewall,
    Interface,
)
from firewallfabrik.driver._configlet import Configlet
from firewallfabrik.driver._interface_properties import LinuxInterfaceProperties
from firewallfabrik.platforms.iptables._utils import (
    get_interface_var_name,
    get_iptables_version,
    get_wait_option,
    normalize_set_name,
    version_compare,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

# An address table file may list addresses of both families.  Only the ones
# the current tool understands may reach it, so the generated loop pipes the
# file through one of these.  The test is on the first field, because a line
# may carry a trailing comment.
ADDRESS_TABLE_V4_FILTER = "awk '$1 !~ /:/'"
ADDRESS_TABLE_V6_FILTER = "awk '$1 ~ /:/'"


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
        self.address_table_objects: dict[str, tuple[str, bool, str]] = {}
        self.virtual_addresses: list = []
        self.virtual_addresses_for_nat: dict[str, str] = {}
        self.known_interfaces: list[str] = []

        # ipset started out as an IPv4-only extension: `libipt_set.c` is
        # `.family = NFPROTO_IPV4` up to and including 1.4.8, and only the
        # family-neutral `libxt_set.c` of 1.4.9 gave ip6tables a `set` match
        # (netfilter extensions/). An older ip6tables answers "Couldn't load
        # match 'set'", which stops the activation script, so the ruleset
        # falls back to reading the table file into a shell variable.
        version = get_iptables_version(fw)
        first_release = '1.4.9' if ipv6 else '1.4.1.1'
        if version_compare(version, first_release) >= 0:
            self.using_ipset = bool(fw.get_option('use_m_set'))

    def my_platform_name(self) -> str:
        return 'Linux24'

    def using_ipset_module(self) -> bool:
        return self.using_ipset

    # -- Firewall options --

    def process_firewall_options(self, have_ipv6: bool = False) -> str:
        """Generate kernel parameter settings from firewall options.

        When *have_ipv6* is true, the redirect / source-route hardening
        settings are also applied to the IPv6 stack
        (``/proc/sys/net/ipv6/conf/all/...``). These two knobs are the
        only IPv4 hardening sysctls with an IPv6 equivalent that exists
        on supported kernels (RHEL 8+).
        """
        version = get_iptables_version(self.fw)
        # One entry per configlet.  `Configlet.expand()` drops the trailing
        # newline when it collapses empty lines, so the blocks have to be
        # joined explicitly - concatenating them glues the last sysctl of
        # one block to the first of the next (fwbuilder writes an `endl`
        # between them, OSConfigurator_linux24.cpp:197).
        blocks: list[str] = []

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
            'linux24_tcp_syncookies',
            'linux24_tcp_ecn',
            'linux24_tcp_timestamps',
        ]:
            # linux24_tcp_fack is intentionally omitted: FACK was removed
            # from the kernel (replaced by RACK) and the sysctl is a no-op
            # on supported kernels, so emitting it is pointless.
            val = str(self.fw.get_option(opt_name) or '')
            self._set_configlet_macro_str(val, kernel_vars, opt_name)

        for opt_name in [
            'linux24_tcp_fin_timeout',
            'linux24_tcp_keepalive_interval',
        ]:
            val = self.fw.get_option(opt_name)
            try:
                val = int(val)
            except (ValueError, TypeError):
                val = -1
            # fwbuilder convention: 0 means "not set" for these two options
            # (see OSConfigurator_linux24.cpp).  Setting them to 0 in the
            # kernel would be destructive: tcp_fin_timeout=0 closes TIME_WAIT
            # sockets instantly and tcp_keepalive_intvl=0 disables probe
            # spacing.  `.fwb` imports frequently carry a literal 0 even
            # when the admin left the GUI field empty.
            if val == 0:
                val = -1
            self._set_configlet_macro_int(val, kernel_vars, opt_name)

        # IPv6 counterparts for the two hardening knobs that have one.
        # The value is shared with the IPv4 setting; the line is only
        # emitted when the firewall handles IPv6.
        v6_redirects = have_ipv6 and bool(
            str(self.fw.get_option('linux24_accept_redirects') or '')
        )
        v6_source_route = have_ipv6 and bool(
            str(self.fw.get_option('linux24_accept_source_route') or '')
        )
        kernel_vars.set_variable('if_accept_redirects_v6', '1' if v6_redirects else '0')
        kernel_vars.set_variable(
            'if_accept_source_route_v6', '1' if v6_source_route else '0'
        )

        blocks.append(kernel_vars.expand())

        # Conntrack settings
        conntrack = Configlet('linux24', 'conntrack')
        conntrack.collapse_empty_strings(True)

        if version_compare(version, '1.4.0') >= 0:
            conntrack.set_variable('iptables_version_ge_1_4', '1')
            conntrack.set_variable('iptables_version_lt_1_4', '0')
        else:
            conntrack.set_variable('iptables_version_ge_1_4', '0')
            conntrack.set_variable('iptables_version_lt_1_4', '1')

        # The conntrack configlet uses unprefixed macro names
        # ({{$conntrack_max}}), unlike kernel_vars which keeps the
        # "linux24_" prefix.  Map each firewall option key to the macro
        # name the configlet actually expects, otherwise the sysctl
        # lines are silently dropped (the {{if}} block evaluates to
        # false for an unknown variable).
        for opt_name, macro_name in [
            ('linux24_conntrack_max', 'conntrack_max'),
            ('linux24_conntrack_hashsize', 'conntrack_hashsize'),
            ('linux24_conntrack_tcp_be_liberal', 'conntrack_tcp_be_liberal'),
        ]:
            val = self.fw.get_option(opt_name)
            try:
                val = int(val)
            except (ValueError, TypeError):
                val = -1
            # A stored 0 means "leave the kernel setting alone", not
            # "set it to zero", which is what Firewall Builder writes
            # above the same two lines (OSConfigurator_linux24.cpp:
            # "if conntrack_max and conntrack_hashsize are equal to 0, we
            # do not add commands from the configlet").  Both values are
            # load-bearing: `nf_conntrack_max` of 0 makes
            # `ct_count > nf_conntrack_max` true for every new connection
            # (net/netfilter/nf_conntrack_core.c), so the box logs
            # "table full, dropping packet" and stops passing traffic the
            # moment the script runs; and `nf_conntrack_hash_resize`
            # answers 0 with -EINVAL, so that line fails outright.  A
            # `.fwb` written by Firewall Builder carries 0 for both
            # whenever the administrator left the fields alone.
            if val == 0 and macro_name in ('conntrack_hashsize', 'conntrack_max'):
                val = -1
            self._set_configlet_macro_int(val, conntrack, macro_name)

        blocks.append(conntrack.expand())
        return '\n'.join(block for block in blocks if block)

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
        parts.append('')

        check_utils = Configlet('linux24', 'check_utilities')
        check_utils.remove_comments()
        check_utils.collapse_empty_strings(True)

        load_modules = bool(self.fw.get_option('load_modules'))
        check_utils.set_variable('load_modules', load_modules)
        check_utils.set_variable('need_modprobe', load_modules)

        use_iptables_restore = bool(self.fw.get_option('use_iptables_restore'))
        check_utils.set_variable('need_iptables_restore', use_iptables_restore)
        check_utils.set_variable(
            'need_ip6tables_restore', use_iptables_restore and have_ipv6
        )
        check_utils.set_variable('need_ipset', self.using_ipset)

        parts.append(check_utils.expand())

        # Reset iptables
        version = get_iptables_version(self.fw)
        reset = Configlet('linux24', 'reset_iptables')
        reset.set_variable('opt_wait', get_wait_option(version))
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
            opt_val = self.fw.get_option(f'linux24_path_{tool_key}')
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

        s = str(self.fw.get_option('linux24_ip_forward') or '')
        ip_fwd.set_variable('ipv4', bool(s))
        ip_fwd.set_variable('ipv4_forw', 1 if s in ('1', 'On', 'on') else 0)

        s = str(self.fw.get_option('linux24_ipv6_forward') or '')
        ip_fwd.set_variable('ipv6', bool(s))
        ip_fwd.set_variable('ipv6_forw', 1 if s in ('1', 'On', 'on') else 0)

        return ip_fwd.expand()

    # -- Module loading --

    def generate_code_for_protocol_handlers(self) -> str:
        """Generate module loading commands."""
        load_modules = Configlet('linux24', 'load_modules')
        load_modules.remove_comments()

        load_modules.set_variable(
            'load_modules', bool(self.fw.get_option('load_modules'))
        )
        load_modules.set_variable('modules_dir', '/lib/modules/$(uname -r)/kernel/net/')

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
                virtual = self.virtual_addresses_for_nat.get(iface.name, '')
                if virtual and self.fw.get_option('manage_virtual_addr'):
                    update_addresses.append(virtual)
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

    def _dynamic_interface_variables(self) -> dict[str, Interface]:
        """Map every shell variable a dynamic interface can appear as.

        ``getaddr`` / ``getnet`` fill one variable per interface and address
        family, plus the ``_network`` variants, and the print rules write
        exactly these names into the generated commands.
        """
        variables: dict[str, Interface] = {}
        for iface in self.fw.interfaces:
            if not iface.is_dynamic():
                continue
            for base in (
                get_interface_var_name(iface),
                get_interface_var_name(iface, suffix='v6'),
            ):
                variables[base] = iface
                variables[f'{base}_network'] = iface
        return variables

    def _wrap_address_table(
        self, command: str, address_table_file: str, ipv6: bool = False
    ) -> str:
        """Wrap *command* in the loop that reads one address per file line.

        Without the ipset module an address table has no kernel object, so
        the rule is written once per address: the loop assigns each line to
        the ``$at_<table>`` variable the command carries.  Ports fwbuilder's
        ``OSConfigurator_linux24::addressTableWrapper``, plus the address
        family filter fwbuilder is missing.
        """
        match = re.search(r'\$(at_\S+)', command)
        if match is None or not address_table_file:
            return command

        lines = [line for line in command.split('\n') if line.strip()]
        if len(lines) > 1:
            lines = ['{', *lines, '}']

        wrappers = Configlet('linux24', 'run_time_wrappers')
        wrappers.collapse_empty_strings(True)
        wrappers.set_variable('ipv6', 0)
        wrappers.set_variable('address_table', 1)
        wrappers.set_variable('no_wrapper', 0)
        wrappers.set_variable('wildcard_interface', 0)
        wrappers.set_variable('one_dyn_addr', 0)
        wrappers.set_variable('two_dyn_addr', 0)
        wrappers.set_variable('address_table_file', address_table_file)
        wrappers.set_variable('address_table_var', match.group(1)[len('at_') :])
        wrappers.set_variable(
            'address_table_family_filter',
            ADDRESS_TABLE_V6_FILTER if ipv6 else ADDRESS_TABLE_V4_FILTER,
        )
        wrappers.set_variable('command', '\n'.join(lines))
        return wrappers.expand()

    def print_run_time_wrappers(
        self, command: str, ipv6: bool = False, address_table_file: str = ''
    ) -> str:
        """Wrap *command* in the shell code that fills in dynamic addresses.

        A rule that matches on the address of a dynamic interface cannot name
        it at compile time, so the print rules write a ``$i_<interface>``
        variable instead.  Nothing assigns that variable on its own:
        ``getaddr`` (configlets/linux24/shell_functions) only fills
        ``$i_<interface>_list``, and a wildcard interface such as ``ppp*``
        does not even get a ``getaddr`` call, because which interfaces it
        covers is only known on the firewall.  Without this wrapper the
        command runs with an empty argument, which iptables rejects
        ("Bad argument") and which stops the activation script.

        Ports fwbuilder's ``OSConfigurator_linux24::printRunTimeWrappers``
        and renders the ``run_time_wrappers`` configlet, which loops over the
        address list and skips a run where the interface has no address.
        """
        if not command.strip():
            return command

        # The address-table loop goes innermost, so an interface wrapper
        # around it still applies to every address the table contributes.
        if not self.using_ipset:
            command = self._wrap_address_table(command, address_table_file, ipv6)

        variables = self._dynamic_interface_variables()
        used: list[str] = []
        wildcard_family = ''
        for match in re.finditer(r'\$(i_[A-Za-z0-9_]+)', command):
            iface = variables.get(match.group(1))
            if iface is None:
                continue
            if '*' in iface.name:
                # Only one wildcard interface per rule, the same limit
                # fwbuilder documents in the configlet.  The loop resolves
                # the address into $addr, so the variable is replaced.
                wildcard_family = iface.name.split('*', 1)[0]
                command = command[: match.start()] + '$addr' + command[match.end() :]
                break
            if match.group(1) not in used:
                used.append(match.group(1))

        if not wildcard_family and not used:
            return command if command.endswith('\n') else command + '\n'

        lines = [line for line in command.split('\n') if line.strip()]
        if len(lines) > 1:
            lines = ['{', *lines, '}']
        command = '\n'.join(lines)

        wrappers = Configlet('linux24', 'run_time_wrappers')
        wrappers.collapse_empty_strings(True)
        wrappers.set_variable('ipv6', 1 if ipv6 else 0)
        wrappers.set_variable('address_table', 0)
        wrappers.set_variable('no_wrapper', 0)
        wrappers.set_variable('wildcard_interface', 1 if wildcard_family else 0)
        wrappers.set_variable('interface_family_name', wildcard_family)
        wrappers.set_variable(
            'one_dyn_addr', 1 if not wildcard_family and len(used) == 1 else 0
        )
        wrappers.set_variable(
            'two_dyn_addr', 1 if not wildcard_family and len(used) > 1 else 0
        )
        for index, var in enumerate(used[:2], start=1):
            # The configlet spells the variable as ``i_{{$intf_N_var_name}}``,
            # so it wants the name without the ``i_`` prefix.
            wrappers.set_variable(f'intf_{index}_var_name', var[2:])
        wrappers.set_variable('command', command)

        return wrappers.expand() + '\n'

    def print_commands_to_clear_known_interfaces(self) -> str:
        """Generate commands to clear addresses on unknown interfaces."""
        if not self.fw.get_option('clear_unknown_interfaces'):
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
        checked = set()
        for name, (source, ipv6, base_name) in self.address_table_objects.items():
            # The file is the same for both families, so it is checked once.
            if (base_name, source) not in checked:
                check_cmds.append(f'check_file "{base_name}" "{source}"')
                checked.add((base_name, source))
            load_cmds.append(
                f'reload_address_table "{name}" "{source}" "{"-6" if ipv6 else "-4"}"'
            )

        rt.set_variable('check_files_commands', '\n'.join(check_cmds))
        rt.set_variable('load_files_commands', '\n'.join(load_cmds))

        return rt.expand()

    def print_bridge_interface_configuration_commands(self) -> str:
        """Generate bridge interface configuration commands.

        Iterates all interfaces with ``type == "bridge"`` in their
        options, generates ``sync_bridge_interfaces`` to
        create/delete bridges, then ``update_bridge`` for each bridge
        to synchronise ports, and finally configures STP.

        Mirrors fwbuilder's
        ``OSConfigurator_linux24::printBridgeInterfaceConfigurationCommands``.
        """
        bridges: list[Interface] = []
        for iface in self.fw.interfaces:
            if iface.get_option('type') == 'bridge':
                bridges.append(iface)

        if not bridges:
            return ''

        # Include the update_bridge configlet (shell helper functions).
        bridge_configlet = Configlet('linux24', 'update_bridge')
        gencmd: list[str] = []

        # 1. Sync: create missing / delete extraneous bridge interfaces.
        bridge_names = [b.name for b in bridges]
        gencmd.append(f'sync_bridge_interfaces {" ".join(bridge_names)}')

        # 2. For each bridge, update its ports and configure STP.
        for bridge in bridges:
            port_names = [
                sub.name
                for sub in bridge.sub_interfaces
                if sub.get_option('type', '') not in ('vlan',)
            ]
            gencmd.append(f'update_bridge {bridge.name} "{" ".join(port_names)}"')

            enable_stp = bridge.get_option('enable_stp', False)
            stp_val = 1 if enable_stp else 0
            gencmd.append(f'$IP link set {bridge.name} type bridge stp_state {stp_val}')

        return bridge_configlet.expand() + '\n' + '\n'.join(gencmd) + '\n'

    def register_multi_address_object(
        self, name: str, source: str, ipv6: bool = False
    ) -> None:
        """Register an address table object for runtime loading.

        *name* is the base name; an ipset set carries one address family, so
        a table used by both rulesets is registered once per family and each
        set is filled from the same file with only the addresses that belong
        to it.
        """
        self.address_table_objects[normalize_set_name(name, ipv6)] = (
            source,
            ipv6,
            normalize_set_name(name),
        )
