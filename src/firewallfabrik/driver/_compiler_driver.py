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

import difflib
import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core.objects import (
    Cluster,
    Firewall,
)
from firewallfabrik.platforms._defaults import get_known_keys

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

    def check_interface_addresses(self, fw: Firewall) -> str:
        """Validate IP addresses of a firewall's regular interfaces.

        Mirrors the pre-compile sanity check in fwbuilder's
        ``CompilerDriver::processFirewallOrCluster`` (CompilerDriver.cpp).
        For every regular interface (not dynamic, unnumbered, or bridge
        port) every IPv4/IPv6 address child must be a routable unicast
        address with a non-zero netmask. An address of 0.0.0.0 / :: or
        a netmask of /0 is almost always a misconfiguration and makes
        the generated rules ambiguous, so the compile is aborted.

        Returns a human-readable error string, or an empty string on
        success.
        """
        for iface in fw.interfaces:
            if not iface.is_regular():
                continue
            for addr in iface.addresses:
                addr_str = addr.get_address()
                if not addr_str:
                    continue
                try:
                    ip = ipaddress.ip_address(addr_str)
                except ValueError:
                    continue
                if int(ip) == 0:
                    return (
                        f'Interface {iface.name} (id={iface.id}) has IP '
                        f'address {addr_str}.'
                    )
                mask_str = addr.get_netmask()
                if not mask_str:
                    continue
                try:
                    nm = ipaddress.ip_address(mask_str)
                except ValueError:
                    continue
                if int(nm) == 0:
                    return (
                        f'Interface {iface.name} (id={iface.id}) has '
                        f'invalid netmask {mask_str}.'
                    )
        return ''

    # -- Option validation --

    # Firewall options recognised by the C++ Firewall Builder that are not
    # yet implemented in the Python compiler.  When a user has any of these
    # set to a non-default (truthy) value the compilation still succeeds,
    # but the option is silently ignored — which is dangerous because the
    # generated script may not match the user's intent.  We emit a warning
    # for each one so nothing is overlooked.
    _UNSUPPORTED_BOOL_OPTIONS: ClassVar[list[tuple[str, str]]] = [
        (
            'use_ULOG',
            'ULOG is deprecated and has been removed from modern Linux kernels; falling back to LOG',
        ),
    ]

    def _warn_unsupported_options(self, options: dict, fw=None) -> None:
        """Emit warnings for recognised but unimplemented firewall options."""
        for opt, msg in self._UNSUPPORTED_BOOL_OPTIONS:
            if options.get(opt, False):
                self.warning(msg)
        if fw is not None:
            self._warn_misspelled_options(options, fw)

    def _warn_misspelled_options(self, options: dict, fw) -> None:
        """Warn about an option key that looks like a misspelled one.

        get_option() falls back to the schema when a key is absent, so a
        key nobody reads is silently ignored - which is what the option
        schema was written to prevent (docs/developer-guide/
        PlatformDefaults.md).  Reporting every unknown key is no use: a
        data file imported from Firewall Builder carries the options of
        every platform it ever knew, and none of those is a mistake here.
        A key that is one edit away from a real one is a different matter,
        and that is the case worth a word.
        """
        try:
            known = get_known_keys(fw.platform, fw.host_os or '')
        except (ModuleNotFoundError, FileNotFoundError):
            # A data file can name a platform this compiler has no schema
            # for, and then there is nothing to compare against.
            return
        for key in sorted(set(options) - known):
            close = difflib.get_close_matches(key, known, n=1, cutoff=0.85)
            if close:
                self.warning(
                    f'the firewall option "{key}" is not one this compiler '
                    f'reads and looks like "{close[0]}"; it is ignored'
                )

    def determine_output_file_names(
        self,
        fw: Firewall,
        cluster_name: str = '',
    ) -> None:
        """Set output file names based on firewall name and options."""
        fw_name = fw.name

        # Three tiers, the way fwbuilder resolves it
        # (CompilerDriver::getOutputFileNameInternal): the -o given on the
        # command line wins, then the firewall's own "Compiler > Output file
        # name", then the name derived from the object.  The middle one used
        # to be missing, so a compile from the command line or from cron
        # ignored the setting and wrote a different file than the GUI, which
        # has always passed the option through as -o.
        option_name = str(fw.get_option('output_file') or '').strip()
        if self.file_name_setting:
            file_name = self.file_name_setting
        elif option_name:
            file_name = option_name
        else:
            base_name = fw_name
            if cluster_name and self.prepend_cluster_name:
                base_name = f'{cluster_name}_{base_name}'
            base_name = base_name.replace(' ', '_').replace('/', '_')
            file_name = f'{base_name}.fw'

        output_dir = self.wdir if self.wdir else '.'
        self.file_names[str(fw.id)] = str(Path(output_dir) / file_name)

        # Compute remote file name from firewall options. The installer
        # directory ("Installer > Directory on the firewall") is combined
        # with either the user-supplied "Compiler > Script name on the
        # firewall" (as a filename) or the basename of the local output
        # file. An absolute value in "Script name on the firewall" is
        # honoured as-is. Only the basename of file_name is used, so a
        # full path in "Compiler > Output file name" does not leak into
        # the remote path.
        firewall_dir = (fw.get_option('firewall_dir') or '/etc/fw').rstrip('/')
        script_name = fw.get_option('script_name_on_firewall') or ''
        if script_name:
            if script_name.startswith('/'):
                remote_file_name = script_name
            else:
                remote_file_name = f'{firewall_dir}/{script_name}'
        else:
            remote_file_name = f'{firewall_dir}/{Path(file_name).name}'

        self.remote_file_names[str(fw.id)] = remote_file_name
