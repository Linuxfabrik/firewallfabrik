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

import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core._options import option_is_true
from firewallfabrik.core.objects import (
    AddressRange,
    Cluster,
    Firewall,
    MultiAddressRunTime,
    PhysAddress,
    netmask_prefix_length,
)
from firewallfabrik.platforms._defaults import get_known_keys

if TYPE_CHECKING:
    from firewallfabrik.core._database import DatabaseManager


def _one_edit_apart(typed: str, known: str) -> bool:
    """Is *typed* what *known* looks like after a single slip of the hand?

    One character inserted, dropped or replaced, or two neighbouring ones
    written in the other order.  That is what a typo is, and it is what
    separates `log_perfix` from `log_prefix` (a swap) and
    `acept_established` from `accept_established` (a dropped letter).

    A similarity ratio cannot draw that line.  `install_script`,
    `log_limit_suffix` and `activation` are option names an imported
    `.fwb` carries in every firewall, and each of them scores above 0.85
    against a name this compiler does read - so the whole reference
    corpus was told twice per firewall that Firewall Builder had made a
    typo.  None of the three is within one edit.
    """
    if typed == known or abs(len(typed) - len(known)) > 1:
        return False
    # Strip what the two have in common at either end; the edit is what
    # is left over, and it is at most one character on each side - two
    # when they are the same two characters in the other order.
    shortest = min(len(typed), len(known))
    head = 0
    while head < shortest and typed[head] == known[head]:
        head += 1
    tail = 0
    while tail < shortest - head and typed[-1 - tail] == known[-1 - tail]:
        tail += 1
    rest_typed = typed[head : len(typed) - tail]
    rest_known = known[head : len(known) - tail]
    if len(rest_typed) <= 1 and len(rest_known) <= 1:
        return True
    return len(rest_typed) == 2 and rest_typed == rest_known[::-1]


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

    def my_platform_name(self) -> str:
        """The platform this driver compiles for.

        Answered by the driver rather than read off the firewall object:
        a firewall imported from a `.fwb` file always says "iptables",
        because Firewall Builder has no other Linux platform, and
        compiling it with `fwf-nft` is an ordinary thing to do.  Same
        method, same meaning, as on the compilers.
        """
        raise NotImplementedError

    def firewall_option(self, fw, key: str):
        """The firewall's value for *key*, or the default of this platform.

        The one accessor for a firewall option in a driver.  Reading
        `fw.options` directly and supplying a fallback there puts a
        second default next to the one in `defaults.yaml`, and the two
        drift: `configure_interfaces` defaults to on in the schema and
        every driver read it as off, so a firewall whose data file does
        not carry the key got a script that configured no addresses
        (docs/developer-guide/PlatformDefaults.md).
        """
        return fw.get_option(key, platform=self.my_platform_name())

    def error(self, rule_or_msg, msg: str | None = None) -> None:
        """Record an error and put it where the caller reads it.

        `BaseCompiler.error` keeps a message for the compiler that is
        running, and the driver collects those from every sub-compiler
        into ``all_errors`` afterwards.  Its own messages have no such
        collector: a condition found before the first sub-compiler starts
        - no firewall id, a prolog placement the output format cannot
        have - wrote no script, and the CLI, which decides on
        ``all_errors`` and the returned string, counted the firewall as
        compiled and exited 0.
        """
        seen = len(self._errors)
        super().error(rule_or_msg, msg)
        self.all_errors.extend(self._errors[seen:])

    def warning(self, rule_or_msg, msg: str | None = None) -> None:
        """Record a warning and put it where the caller reads it.

        See :meth:`error`.
        """
        seen = len(self._warnings)
        super().warning(rule_or_msg, msg)
        self.all_warnings.extend(self._warnings[seen:])

    def run(
        self,
        cluster_id: str,
        fw_id: str,
        single_rule_id: str,
    ) -> str:
        """Platform-specific compilation. Override in subclasses."""
        return ''

    def warn_about_missing_top_rule_sets(self, fw, policies, nats) -> None:
        """Say when the firewall has rule sets but none of them is the top one.

        Only the top rule set is compiled into the built-in chains; every
        other one becomes a chain of its own that runs where a rule with
        the Branch action jumps to it.  A firewall whose only Policy rule
        set is not marked "top" therefore compiles into a chain nothing
        ever reaches - a script that installs no filtering at all and
        reports success.  fwbuilder says the same thing
        (``CompilerDriver::commonChecks2``, "Missing top level Policy
        ruleset"); this wording adds what it costs, because the state is
        easy to arrive at in the editor.
        """
        for rule_sets, what in ((policies, 'Policy'), (nats, 'NAT')):
            if not rule_sets:
                continue
            if any(rs.top for rs in rule_sets):
                continue
            names = ', '.join(f'"{rs.name}"' for rs in rule_sets)
            self.warning(
                f'{fw.name}: none of the {what} rule sets ({names}) is the '
                f'top rule set, so none of them is installed in the built-in '
                f'chains. Mark the one that applies to all traffic as the top '
                f'rule set, or point a rule with the Branch action at it'
            )

    def check_interface_addresses(self, fw: Firewall) -> str:
        """Validate IP addresses of a firewall's regular interfaces.

        Mirrors the pre-compile sanity check in fwbuilder's
        ``CompilerDriver::processFirewallOrCluster`` (CompilerDriver.cpp).
        For every regular interface (not dynamic, unnumbered, or bridge
        port) every IPv4/IPv6 address child must be a routable unicast
        address with a non-zero netmask. An address of 0.0.0.0 / :: or
        a netmask of /0 is almost always a misconfiguration and makes
        the generated rules ambiguous, so the compile is aborted.

        A value neither ``ipaddress`` nor the tools can read is aborted on
        as well.  It used to be skipped here, and the compilers answer
        such a netmask by leaving it out and matching the address alone -
        so the interface of a firewall silently stood for one host instead
        of for its network, in a script that loads without a word.

        Returns a human-readable error string, or an empty string on
        success.
        """
        for iface in fw.interfaces:
            if not iface.is_regular():
                continue
            for addr in iface.addresses:
                # Only an address/netmask pair is this check's business.  A
                # physAddress child of the same interface carries a MAC,
                # which VerifyMacAddresses checks, and neither an address
                # range nor a run-time object carries a netmask at all.
                if isinstance(addr, (AddressRange, MultiAddressRunTime, PhysAddress)):
                    continue
                addr_str = addr.get_address()
                if not addr_str:
                    continue
                try:
                    ip = ipaddress.ip_address(addr_str)
                except ValueError:
                    return (
                        f'Interface {iface.name} (id={iface.id}) has IP '
                        f'address {addr_str}, which is not an address any '
                        'compiler can read. Give it the address it has on '
                        'the firewall.'
                    )
                if int(ip) == 0:
                    # Naming the address alone leaves the administrator with
                    # nothing to act on, and the two ways out are not
                    # obvious: the interface either gets its address or
                    # gets told that it has none.
                    return (
                        f'Interface {iface.name} (id={iface.id}) has IP '
                        f'address {addr_str}. Give it the address it has on '
                        'the firewall, or mark it dynamic if it gets one at '
                        'boot time, or unnumbered if it never has one.'
                    )
                mask_str = addr.get_netmask()
                if not mask_str:
                    continue
                prefix = netmask_prefix_length(addr_str, mask_str)
                if prefix is None:
                    return (
                        f'Interface {iface.name} (id={iface.id}) has '
                        f'netmask {mask_str}, which is not a netmask. Every '
                        f'rule naming this interface would match the single '
                        f'address {addr_str} instead of its network.'
                    )
                if prefix == 0:
                    return (
                        f'Interface {iface.name} (id={iface.id}) has '
                        f'invalid netmask {mask_str}. Every rule naming this '
                        'interface would match every address.'
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
            'configure_bonding_interfaces',
            'the generated script does not create or remove bonding interfaces; '
            'they have to exist on the firewall before it runs',
        ),
        (
            'configure_vlan_interfaces',
            'the generated script does not create or remove VLAN interfaces; '
            'they have to exist on the firewall before it runs',
        ),
        (
            'use_ULOG',
            'ULOG is deprecated and has been removed from modern Linux kernels; falling back to LOG',
        ),
    ]

    def _warn_unsupported_options(self, options: dict, fw=None) -> None:
        """Emit warnings for recognised but unimplemented firewall options."""
        for opt, msg in self._UNSUPPORTED_BOOL_OPTIONS:
            if option_is_true(options.get(opt, False)):
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
            for candidate in sorted(known):
                if _one_edit_apart(key, candidate):
                    self.warning(
                        f'the firewall option "{key}" is not one this compiler '
                        f'reads and looks like "{candidate}"; it is ignored'
                    )
                    break

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
