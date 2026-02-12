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
from typing import TYPE_CHECKING

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
)
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
        firewall_dir = fw.get_option('firewall_dir', '/etc/fw') or '/etc/fw'
        script_name = fw.get_option('script_name_on_firewall', '')
        if script_name:
            remote_file_name = str(script_name)
        else:
            remote_file_name = f'{firewall_dir}/{file_name}'

        self.remote_file_names[str(fw.id)] = remote_file_name
