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

"""CompilerDriver base class: orchestrates the full compilation process.

Handles firewall/cluster object lookup, script assembly from configlets,
and output file management.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
)
from firewallfabrik.core.options import FirewallOption
from firewallfabrik.driver._configlet import Configlet

if TYPE_CHECKING:
    from firewallfabrik.core._database import DatabaseManager


class CompilerDriver(BaseCompiler):
    """Orchestrates the full compilation process.

    Handles:
    - Firewall/cluster object lookup
    - Cluster member handling
    - Script assembly from configlets
    - Output file management
    """

    def __init__(self, db: DatabaseManager) -> None:
        super().__init__()
        self.db: DatabaseManager = db
        self.fw: Firewall | None = None
        self.cluster: Cluster | None = None

        # Options
        self.wdir: str = '.'
        self.verbose: int = 0
        self.ipv4_run: bool = True
        self.ipv6_run: bool = True
        self.single_rule_compile_on: bool = False
        self.single_rule_id: str = ''
        self.test_mode: bool = False
        self.debug_rule_policy: int = -1
        self.debug_rule_nat: int = -1
        self.debug_rule_routing: int = -1
        self.file_name_setting: str = ''
        self.prepend_cluster_name: bool = False
        self.source_dir: str = '.'

        # Output
        self.file_names: dict[str, str] = {}
        self.remote_file_names: dict[str, str] = {}
        self.all_errors: list[str] = []
        self.all_warnings: list[str] = []

    def run(
        self,
        cluster_id: str,
        fw_id: str,
        single_rule_id: str,
    ) -> str:
        """Platform-specific compilation. Override in subclasses."""
        return ''

    # -- Option validation --

    # Firewall options recognised by the C++ Firewall Builder that are not
    # yet implemented in the Python compiler.  When a user has any of these
    # set to a non-default (truthy) value the compilation still succeeds,
    # but the option is silently ignored — which is dangerous because the
    # generated script may not match the user's intent.  We emit a warning
    # for each one so nothing is overlooked.
    _UNSUPPORTED_BOOL_OPTIONS: ClassVar[list[tuple[str, str]]] = [
        ('use_ULOG', 'ULOG/NFLOG logging is not yet supported; falling back to LOG'),
        (
            'log_tcp_seq',
            'logging TCP sequence numbers (--log-tcp-sequence) is not yet supported',
        ),
        ('log_tcp_opt', 'logging TCP options (--log-tcp-options) is not yet supported'),
        ('log_ip_opt', 'logging IP options (--log-ip-options) is not yet supported'),
        ('use_numeric_log_levels', 'numeric syslog log levels are not yet supported'),
        ('log_all', 'unconditional logging of all rules is not yet supported'),
        ('use_kerneltz', 'kernel timezone for log timestamps is not yet supported'),
        (
            'configure_bridge_interfaces',
            'bridge interface configuration is not yet supported',
        ),
    ]

    def _warn_unsupported_options(self, options: dict) -> None:
        """Emit warnings for recognised but unimplemented firewall options."""
        for opt, msg in self._UNSUPPORTED_BOOL_OPTIONS:
            if options.get(opt, False):
                self.warning(msg)

        # Non-boolean ULOG parameters — only relevant when use_ULOG is set,
        # but warn individually so the user sees exactly what is ignored.
        for opt, flag in [
            ('ulog_nlgroup', '--ulog-nlgroup / --nflog-group'),
            ('ulog_cprange', '--ulog-cprange / --nflog-range'),
            ('ulog_qthreshold', '--ulog-qthreshold / --nflog-threshold'),
        ]:
            val = options.get(opt)
            if val is not None and val != '' and val != 0 and val != -1:
                self.warning(f'{flag} is not yet supported (option {opt!r} ignored)')

    # -- Script assembly --

    def assemble_script(
        self,
        fw: Firewall,
        os_family: str,
        filter_output: str,
        nat_output: str,
        routing_output: str,
        mangle_output: str = '',
        prolog_output: str = '',
        epilog_output: str = '',
    ) -> str:
        """Assemble the final script from configlets and compiled sections."""
        if not os_family:
            os_family = 'linux24'

        skeleton = Configlet(os_family, 'script_skeleton', default_prefix='linux24')
        skeleton.collapse_empty_strings(True)

        # Set variables
        skeleton.set_variable('shell_debug', '')
        skeleton.set_variable('firewall_dir', '/etc/fw')
        skeleton.set_variable('timestamp', time.strftime('%c'))
        skeleton.set_variable('user', os.environ.get('USER', 'unknown'))
        skeleton.set_variable('platform', fw.platform)
        skeleton.set_variable('fw_version', fw.version)
        skeleton.set_variable('comment', (fw.comment or '').replace('\n', '\n# '))

        # Content sections
        skeleton.set_variable('have_filter', '1' if filter_output else '0')
        skeleton.set_variable('have_nat', '1' if nat_output else '0')
        skeleton.set_variable('have_mangle', '1' if mangle_output else '0')
        skeleton.set_variable('have_routing', '1' if routing_output else '0')

        skeleton.set_variable('filter_rules', filter_output)
        skeleton.set_variable('nat_rules', nat_output)
        skeleton.set_variable('mangle_rules', mangle_output)
        skeleton.set_variable('routing_rules', routing_output)
        skeleton.set_variable('prolog_script', prolog_output)
        skeleton.set_variable('epilog_script', epilog_output)

        # Error/warning section
        messages = []
        for e in self.all_errors:
            messages.append(f'# Error: {e}')
        for w in self.all_warnings:
            messages.append(f'# Warning: {w}')
        skeleton.set_variable('errors_and_warnings', '\n'.join(messages))

        return skeleton.expand()

    def determine_output_file_names(
        self,
        fw: Firewall,
        cluster_name: str = '',
    ) -> None:
        """Set output file names based on firewall name and options."""
        fw_name = fw.name

        if self.file_name_setting:
            file_name = self.file_name_setting
        else:
            base_name = fw_name
            if cluster_name and self.prepend_cluster_name:
                base_name = f'{cluster_name}_{base_name}'
            base_name = base_name.replace(' ', '_').replace('/', '_')
            file_name = f'{base_name}.fw'

        output_dir = self.wdir if self.wdir else '.'
        self.file_names[str(fw.id)] = str(Path(output_dir) / file_name)

        # Compute remote file name from firewall options
        firewall_dir = fw.get_option(FirewallOption.FIREWALL_DIR, '/etc/fw')
        script_name = fw.get_option(FirewallOption.SCRIPT_NAME_ON_FIREWALL, '')
        if script_name:
            remote_file_name = str(script_name)
        else:
            remote_file_name = f'{firewall_dir}/{file_name}'

        self.remote_file_names[str(fw.id)] = remote_file_name
