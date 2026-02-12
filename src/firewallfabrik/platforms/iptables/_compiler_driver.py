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

"""CompilerDriver_ipt: iptables compilation orchestrator.

Corresponds to fwbuilder's iptlib/compiler_driver_ipt.py.

This is the main entry point for iptables compilation. The run() method
orchestrates: preprocessor -> NAT compilation -> policy/mangle compilation ->
routing compilation -> script assembly -> file writing.
"""

from __future__ import annotations

import io
import os
import socket
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy

from firewallfabrik.compiler._base import CompilerStatus
from firewallfabrik.core.objects import (
    NAT,
    Firewall,
    Policy,
    Routing,
    RuleSet,
)
from firewallfabrik.driver._compiler_driver import CompilerDriver
from firewallfabrik.driver._configlet import Configlet

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.core._database import DatabaseManager

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


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


def _indent(n: int, text: str) -> str:
    """Indent every line of text by n spaces."""
    if not text:
        return text
    prefix = ' ' * n
    lines = text.split('\n')
    return '\n'.join(prefix + line if line else line for line in lines)


def _prepend(prefix: str, text: str) -> str:
    """Prepend a string to every non-empty line."""
    if not text:
        return text
    lines = text.split('\n')
    return '\n'.join(prefix + line if line else '' for line in lines)


class CompilerDriver_ipt(CompilerDriver):
    """Orchestrates full iptables compilation.

    Creates and runs NAT, policy, mangle, and routing compilers,
    then assembles the output into a shell script using configlets.
    """

    def __init__(self, db: DatabaseManager) -> None:
        super().__init__(db)
        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False
        self.have_nat: bool = False
        self.have_dynamic_interfaces: bool = False

        # Prolog/epilog tracking
        self.prolog_done: bool = False
        self.epilog_done: bool = False

    def run(
        self,
        cluster_id: str,
        fw_id: str,
        single_rule_id: str,
    ) -> str:
        """Main compilation entry point.

        Performs the full iptables compilation pipeline:
        1. Look up firewall object
        2. Create OS configurator
        3. For each address family (IPv4/IPv6):
           a. Compile NAT rules
           b. Compile policy rules (mangle + filter)
           c. Assemble per-AF script body
        4. Compile routing rules
        5. Assemble final script via script_skeleton configlet
        6. Write output file
        """
        from firewallfabrik.platforms.iptables._os_configurator import (
            OSConfigurator_linux24,
        )

        # -- Look up firewall --
        with self.db.session() as session:
            if fw_id:
                fw_uuid = uuid.UUID(fw_id) if isinstance(fw_id, str) else fw_id
                fw = session.execute(
                    sqlalchemy.select(Firewall).where(
                        Firewall.id == fw_uuid,
                    ),
                ).scalar_one_or_none()
            else:
                self.error('No firewall ID provided')
                return ''

            if fw is None:
                self.error(f'Firewall {fw_id} not found')
                return ''

            self.fw = fw
            generated_script = ''

            try:
                fw_version = fw.version or '(any version)'
                options = fw.options or {}

                # Validate prolog placement with iptables-restore
                prolog_place = options.get('prolog_place', '')
                if prolog_place == 'after_flush' and options.get(
                    'use_iptables_restore', False
                ):
                    self.error(
                        'Prolog place "after policy reset" can not be used'
                        ' when policy is activated with iptables-restore'
                    )
                    return ''

                debug = options.get('debug', False)
                shell_dbg = 'set -x' if debug else ''

                # Create OS configurator
                oscnf = OSConfigurator_linux24(session, fw)

                # Check if firewall has any IPv6 addresses on its
                # interfaces.  Without IPv6 addresses, skip the IPv6
                # compilation pass entirely to avoid emitting rules
                # for address-family-agnostic ("any") elements.
                fw_has_ipv6 = False
                for iface in fw.interfaces:
                    for addr in iface.addresses:
                        if addr.is_v6():
                            fw_has_ipv6 = True
                            break
                    if fw_has_ipv6:
                        break
                if not fw_has_ipv6:
                    self.ipv6_run = False

                # Gather all rule sets
                all_policies = (
                    session.execute(
                        sqlalchemy.select(Policy).where(
                            Policy.device_id == fw.id,
                        ),
                    )
                    .scalars()
                    .all()
                )

                all_nat = (
                    session.execute(
                        sqlalchemy.select(NAT).where(
                            NAT.device_id == fw.id,
                        ),
                    )
                    .scalars()
                    .all()
                )

                have_ipv4 = False
                have_ipv6 = False

                # Chain trackers per table
                minus_n_commands_filter: dict[str, bool] = {}
                minus_n_commands_mangle: dict[str, bool] = {}
                minus_n_commands_nat: dict[str, bool] = {}

                # Determine IPv4/IPv6 run order
                ipv4_6_runs: list[int] = []
                ipv4_6_order = options.get('ipv4_6_order', '')
                if not ipv4_6_order or ipv4_6_order == 'ipv4_first':
                    if self.ipv4_run:
                        ipv4_6_runs.append(AF_INET)
                    if self.ipv6_run:
                        ipv4_6_runs.append(AF_INET6)
                elif ipv4_6_order == 'ipv6_first':
                    if self.ipv6_run:
                        ipv4_6_runs.append(AF_INET6)
                    if self.ipv4_run:
                        ipv4_6_runs.append(AF_INET)

                # Per-address-family compilation loop
                for policy_af in ipv4_6_runs:
                    ipv6_policy = policy_af == AF_INET6

                    # Clear chain trackers between IPv4/IPv6 runs
                    minus_n_commands_filter.clear()
                    minus_n_commands_mangle.clear()
                    minus_n_commands_nat.clear()

                    # Run preprocessor if we have rules
                    nat_count = sum(
                        1
                        for nat_rs in all_nat
                        if self._matching_address_family(nat_rs, policy_af)
                    )
                    policy_count = sum(
                        1
                        for pol_rs in all_policies
                        if self._matching_address_family(pol_rs, policy_af)
                    )

                    if nat_count or policy_count:
                        from firewallfabrik.platforms.linux._preprocessor import (
                            PreprocessorLinux,
                        )

                        prep = PreprocessorLinux(session, fw, ipv6_policy)
                        if single_rule_id:
                            prep.single_rule_compile_mode = True
                        prep.compile()

                    automatic_rules_stream = io.StringIO()
                    automatic_mangle_stream = io.StringIO()
                    filter_rules_stream = io.StringIO()
                    mangle_rules_stream = io.StringIO()
                    nat_rules_stream = io.StringIO()

                    empty_output = True

                    # --- NAT compilation ---
                    top_nat = None
                    for nat_rs in all_nat:
                        if not self._matching_address_family(nat_rs, policy_af):
                            continue
                        if self._is_top_ruleset(nat_rs):
                            top_nat = nat_rs
                            continue
                        result = self._process_nat_rule_set(
                            session,
                            fw,
                            nat_rs,
                            single_rule_id,
                            nat_rules_stream,
                            oscnf,
                            policy_af,
                            minus_n_commands_nat,
                        )
                        if not result:
                            empty_output = False

                    if top_nat is not None:
                        result = self._process_nat_rule_set(
                            session,
                            fw,
                            top_nat,
                            single_rule_id,
                            nat_rules_stream,
                            oscnf,
                            policy_af,
                            minus_n_commands_nat,
                        )
                        if not result:
                            empty_output = False

                    # --- Policy/mangle compilation ---
                    for all_top in range(2):
                        for pol_rs in all_policies:
                            if not self._matching_address_family(pol_rs, policy_af):
                                continue
                            is_top = self._is_top_ruleset(pol_rs)
                            if is_top and all_top == 0:
                                continue
                            if not is_top and all_top == 1:
                                continue

                            result = self._process_policy_rule_set(
                                session,
                                fw,
                                pol_rs,
                                single_rule_id,
                                filter_rules_stream,
                                mangle_rules_stream,
                                automatic_rules_stream,
                                automatic_mangle_stream,
                                oscnf,
                                policy_af,
                                minus_n_commands_filter,
                                minus_n_commands_mangle,
                            )
                            if not result:
                                empty_output = False

                    # Add IPv4/IPv6 section markers
                    if not empty_output and not self.single_rule_compile_on:
                        if ipv6_policy:
                            have_ipv6 = True
                            generated_script += '\n\n'
                            generated_script += '# ================ IPv6\n'
                            generated_script += '\n\n'
                        else:
                            have_ipv4 = True
                            generated_script += '\n\n'
                            generated_script += '# ================ IPv4\n'
                            generated_script += '\n\n'

                    generated_script += self._dump_script(
                        fw,
                        automatic_rules_stream.getvalue(),
                        automatic_mangle_stream.getvalue(),
                        nat_rules_stream.getvalue(),
                        mangle_rules_stream.getvalue(),
                        filter_rules_stream.getvalue(),
                        ipv6_policy,
                    )

                    if self.single_rule_compile_on:
                        generated_script += '\n\n'

                # --- Routing compilation ---
                from firewallfabrik.platforms.linux._routing_compiler import (
                    RoutingCompilerLinux,
                )

                routing_output = ''
                routing_rs = (
                    session.execute(
                        sqlalchemy.select(Routing).where(
                            Routing.device_id == fw.id,
                        ),
                    )
                    .scalars()
                    .first()
                )

                if routing_rs:
                    routing_compiler = RoutingCompilerLinux(session, fw, False)
                    routing_compiler.set_source_ruleset(routing_rs)
                    routing_compiler.source_ruleset = routing_rs

                    if single_rule_id:
                        routing_compiler.single_rule_compile_mode = True
                        routing_compiler.single_rule_id = single_rule_id
                    routing_compiler.verbose = self.verbose > 0
                    routing_compiler.source_dir = self.source_dir

                    routing_rules_count = routing_compiler.prolog()
                    if routing_rules_count > 0:
                        routing_compiler.compile()
                        routing_compiler.epilog()

                    routing_output = routing_compiler.output.getvalue()

                    if routing_compiler.get_errors() or routing_compiler.get_warnings():
                        self.all_errors.extend(routing_compiler.get_errors())
                        self.all_errors.extend(routing_compiler.get_warnings())

                # Single-rule compile mode
                if self.single_rule_compile_on:
                    errors_str = '\n'.join(self.all_errors)
                    return errors_str + generated_script + routing_output

                # --- Script assembly ---
                timestr = time.strftime('%c')
                tz = time.strftime('%Z')
                user_name = os.environ.get('USER', 'unknown')

                script_skeleton = Configlet('linux24', 'script_skeleton')
                script_skeleton.remove_comments()

                script_skeleton.set_variable('shell_debug', shell_dbg)

                # PATH
                path_buf = 'PATH="/sbin:/usr/sbin:/bin:/usr/bin:${PATH}"\nexport PATH\n'
                script_skeleton.set_variable('path', path_buf)

                # Constants configlet
                constants_configlet = Configlet('linux24', 'constants')
                script_skeleton.set_variable('constants', constants_configlet.expand())

                # Tool paths
                script_skeleton.set_variable('tools', oscnf.print_path_for_all_tools())
                script_skeleton.set_variable(
                    'shell_functions', oscnf.print_shell_functions(have_ipv6)
                )
                script_skeleton.set_variable(
                    'run_time_address_tables',
                    oscnf.print_run_time_address_tables_code(),
                )
                script_skeleton.set_variable(
                    'using_ipset', '1' if oscnf.using_ipset_module() else '0'
                )

                # Prolog/epilog scripts
                prolog_script = options.get('prolog_script', '')
                epilog_script = options.get('epilog_script', '')
                script_skeleton.set_variable('prolog_script', prolog_script)
                script_skeleton.set_variable('epilog_script', epilog_script)

                # Interface configuration
                iface_buf = io.StringIO()
                iface_buf.write('# Configure interfaces\n')

                if options.get('configure_interfaces', False):
                    iface_buf.write(oscnf.print_interface_configuration_commands())

                iface_buf.write(oscnf.print_commands_to_clear_known_interfaces())
                iface_buf.write(oscnf.print_dynamic_addresses_configuration_commands())

                script_skeleton.set_variable(
                    'configure_interfaces', _indent(4, iface_buf.getvalue())
                )

                # Verify interfaces
                if options.get('verify_interfaces', False):
                    script_skeleton.set_variable(
                        'verify_interfaces', oscnf.print_verify_interfaces_commands()
                    )
                else:
                    script_skeleton.set_variable('verify_interfaces', '')

                # Prolog placement
                if not prolog_place:
                    prolog_place = 'top'

                script_skeleton.set_variable(
                    'prolog_top', 1 if prolog_place == 'top' else 0
                )
                script_skeleton.set_variable(
                    'prolog_after_interfaces',
                    1 if prolog_place == 'after_interfaces' else 0,
                )
                script_skeleton.set_variable(
                    'prolog_after_flush', 1 if prolog_place == 'after_flush' else 0
                )

                # Module loading
                script_skeleton.set_variable(
                    'load_modules', oscnf.generate_code_for_protocol_handlers()
                )
                script_skeleton.set_variable(
                    'load_modules_with_nat', 'nat' if self.have_nat else ''
                )
                script_skeleton.set_variable(
                    'load_modules_with_ipv6', 'ipv6' if have_ipv6 else ''
                )

                # IP forwarding
                script_skeleton.set_variable(
                    'ip_forward_commands', oscnf.print_ip_forwarding_commands()
                )

                # Script body
                body_buf = io.StringIO()

                body_buf.write(oscnf.process_firewall_options())
                body_buf.write(generated_script)
                body_buf.write(routing_output)
                body_buf.write('\n')

                script_skeleton.set_variable(
                    'script_body', _indent(4, body_buf.getvalue())
                )

                # Metadata
                script_skeleton.set_variable('timestamp', timestr)
                script_skeleton.set_variable('tz', tz)
                script_skeleton.set_variable('user', user_name)
                script_skeleton.set_variable('database', '')

                # Reset commands
                use_ipt_restore = options.get('use_iptables_restore', False)
                script_skeleton.set_variable(
                    'not_using_iptables_restore', 0 if use_ipt_restore else 1
                )

                reset_buf = ''
                if have_ipv4:
                    reset_buf += '    reset_iptables_v4\n'
                if have_ipv6:
                    reset_buf += '    reset_iptables_v6\n'
                script_skeleton.set_variable('reset_all', reset_buf)

                # Block action configlet
                real_version = fw.version or ''
                block_action = Configlet('linux24', 'block_action')
                if _version_compare(real_version, '1.4.20') >= 0:
                    block_action.set_variable('opt_wait', '-w')
                else:
                    block_action.set_variable('opt_wait', '')
                block_action.collapse_empty_strings(True)
                block_action.set_variable('mgmt_access', 0)
                script_skeleton.set_variable('block_action', block_action.expand())

                # Stop action configlet
                stop_action = Configlet('linux24', 'stop_action')
                stop_action.collapse_empty_strings(True)
                stop_action.set_variable('have_ipv4', 1 if have_ipv4 else 0)
                stop_action.set_variable('have_ipv6', 1 if have_ipv6 else 0)
                if _version_compare(real_version, '1.4.20') >= 0:
                    stop_action.set_variable('opt_wait', '-w')
                else:
                    stop_action.set_variable('opt_wait', '')
                script_skeleton.set_variable('stop_action', stop_action.expand())

                # Status action configlet
                status_action = Configlet('linux24', 'status_action')
                status_action.collapse_empty_strings(True)
                script_skeleton.set_variable('status_action', status_action.expand())

                # Top comment configlet
                top_comment = Configlet('linux24', 'top_comment')
                top_comment.set_variable('version', '0.1.0')
                top_comment.set_variable('timestamp', timestr)
                top_comment.set_variable('tz', tz)
                top_comment.set_variable('user', user_name)
                top_comment.set_variable('database', '')

                # Output file names
                cluster_name = ''
                self.determine_output_file_names(fw, cluster_name)

                fw_id_str = str(fw.id)
                local_name = Path(self.file_names.get(fw_id_str, '')).name
                manifest = f'# files: * {local_name}'
                remote = self.remote_file_names.get(fw_id_str, '')
                if remote:
                    manifest += f' {remote}'
                manifest += '\n'
                top_comment.set_variable('manifest', manifest)
                top_comment.set_variable('platform', fw.platform or 'iptables')
                top_comment.set_variable('fw_version', fw_version)
                comment_text = (fw.comment or '').rstrip('\n')
                top_comment.set_variable(
                    'comment', _prepend('# ', comment_text) if comment_text else ''
                )

                script_skeleton.set_variable('top_comment', top_comment.expand())
                script_skeleton.set_variable(
                    'errors_and_warnings', _prepend('# ', '\n'.join(self.all_errors))
                )

                # Write output file
                output_path = self.file_names.get(fw_id_str, '')
                if output_path:
                    self.info(f'Output file name: {output_path}')
                    try:
                        out_p = Path(output_path)
                        out_p.parent.mkdir(parents=True, exist_ok=True)
                        out_p.write_text(script_skeleton.expand(), encoding='utf-8')
                        out_p.chmod(0o755)
                        if self.all_errors:
                            self.info(' Compiled with errors')
                        else:
                            self.info(' Compiled successfully')
                    except OSError as ex:
                        self.error(
                            f'Failed to open file {output_path} for writing: {ex}'
                        )
                        return str(ex)

            except Exception as ex:
                self._status = CompilerStatus.FWCOMPILER_ERROR
                return str(ex)

        return ''

    # -- Helper: process a NAT rule set --

    def _process_nat_rule_set(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        nat_rs: RuleSet,
        single_rule_id: str,
        nat_stream: io.StringIO,
        oscnf,
        policy_af: int,
        minus_n_commands_nat: dict[str, bool],
    ) -> bool:
        """Compile a single NAT rule set. Returns True if output is empty."""
        from firewallfabrik.platforms.iptables._nat_compiler import (
            NATCompiler_ipt,
        )

        ipv6_policy = policy_af == AF_INET6
        branch_name = nat_rs.name

        nat_compiler = NATCompiler_ipt(
            session, fw, ipv6_policy, oscnf, minus_n_commands_nat
        )

        if not self._is_top_ruleset(nat_rs):
            nat_compiler.register_rule_set_chain(branch_name)

        nat_compiler.set_source_ruleset(nat_rs)
        nat_compiler.source_ruleset = nat_rs

        if single_rule_id:
            nat_compiler.single_rule_compile_mode = True
            nat_compiler.single_rule_id = single_rule_id
        nat_compiler.verbose = self.verbose > 0
        nat_compiler.source_dir = self.source_dir
        nat_compiler.debug_rule = self.debug_rule_nat
        nat_compiler.rule_debug_on = self.debug_rule_nat >= 0

        nat_rules_count = nat_compiler.prolog()
        if nat_rules_count > 0:
            nat_compiler.compile()
            nat_compiler.epilog()

        self.have_nat = self.have_nat or (nat_rules_count > 0)

        compiled = nat_compiler.output.getvalue()
        if compiled:
            if not self.single_rule_compile_on:
                nat_stream.write(
                    f"# ================ Table 'nat',  rule set {branch_name}\n"
                )

            if self._is_top_ruleset(nat_rs):
                flush_out = nat_compiler.flush_and_set_default_policy()
                nat_stream.write(flush_out)
                nat_stream.write(nat_compiler.print_automatic_rules())

            nat_stream.write(compiled)
            nat_stream.write('\n')

            if nat_compiler.get_errors() or nat_compiler.get_warnings():
                self.all_errors.extend(nat_compiler.get_errors())
                self.all_errors.extend(nat_compiler.get_warnings())

            return False  # not empty

        if nat_compiler.get_errors() or nat_compiler.get_warnings():
            self.all_errors.extend(nat_compiler.get_errors())
            self.all_errors.extend(nat_compiler.get_warnings())

        return True  # empty

    # -- Helper: process a policy rule set --

    def _process_policy_rule_set(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        pol_rs: RuleSet,
        single_rule_id: str,
        filter_stream: io.StringIO,
        mangle_stream: io.StringIO,
        automatic_rules_stream: io.StringIO,
        automatic_mangle_stream: io.StringIO,
        oscnf,
        policy_af: int,
        minus_n_commands_filter: dict[str, bool],
        minus_n_commands_mangle: dict[str, bool],
    ) -> bool:
        """Compile a single policy rule set for both filter and mangle.

        Returns True if output is empty.
        """
        from firewallfabrik.platforms.iptables._mangle_compiler import (
            MangleTableCompiler_ipt,
        )
        from firewallfabrik.platforms.iptables._policy_compiler import (
            PolicyCompiler_ipt,
        )

        empty_output = True
        ipv6_policy = policy_af == AF_INET6
        branch_name = pol_rs.name

        # --- Mangle table compilation ---
        mangle_compiler = MangleTableCompiler_ipt(
            session, fw, ipv6_policy, oscnf, minus_n_commands_mangle
        )

        if not self._is_top_ruleset(pol_rs):
            mangle_compiler.register_rule_set_chain(branch_name)

        mangle_compiler.set_source_ruleset(pol_rs)
        mangle_compiler.source_ruleset = pol_rs

        if single_rule_id:
            mangle_compiler.single_rule_compile_mode = True
            mangle_compiler.single_rule_id = single_rule_id
        mangle_compiler.verbose = self.verbose > 0
        mangle_compiler.source_dir = self.source_dir
        mangle_compiler.have_dynamic_interfaces = self.have_dynamic_interfaces

        mangle_rules_count = mangle_compiler.prolog()
        if mangle_rules_count > 0:
            mangle_compiler.compile()
            mangle_compiler.epilog()

            self.have_connmark |= mangle_compiler.have_connmark_rules()
            self.have_connmark_in_output |= (
                mangle_compiler.have_connmark_rules_in_output()
            )

            compiled = mangle_compiler.output.getvalue()
            if compiled:
                if not self.single_rule_compile_on:
                    mangle_stream.write(
                        f"# ================ Table 'mangle', rule set {branch_name}\n"
                    )
                mangle_stream.write(compiled)
                empty_output = False

            if mangle_compiler.get_errors() or mangle_compiler.get_warnings():
                self.all_errors.extend(mangle_compiler.get_errors())
                self.all_errors.extend(mangle_compiler.get_warnings())

        # --- Filter table compilation ---
        policy_compiler = PolicyCompiler_ipt(
            session, fw, ipv6_policy, oscnf, minus_n_commands_filter
        )

        if single_rule_id:
            policy_compiler.single_rule_compile_mode = True
            policy_compiler.single_rule_id = single_rule_id
        policy_compiler.verbose = self.verbose > 0
        policy_compiler.source_dir = self.source_dir
        policy_compiler.have_dynamic_interfaces = self.have_dynamic_interfaces
        policy_compiler.debug_rule = self.debug_rule_policy
        policy_compiler.rule_debug_on = self.debug_rule_policy >= 0

        if not self._is_top_ruleset(pol_rs):
            policy_compiler.register_rule_set_chain(branch_name)

        policy_compiler.set_source_ruleset(pol_rs)
        policy_compiler.source_ruleset = pol_rs

        policy_rules_count = policy_compiler.prolog()
        if policy_rules_count > 0:
            policy_compiler.compile()
            policy_compiler.epilog()

            compiled = policy_compiler.output.getvalue()
            if compiled:
                empty_output = False
                if not self.single_rule_compile_on:
                    filter_stream.write(
                        f"# ================ Table 'filter', rule set {branch_name}\n"
                    )
                filter_stream.write(compiled)

            if policy_compiler.get_errors() or policy_compiler.get_warnings():
                self.all_errors.extend(policy_compiler.get_errors())
                self.all_errors.extend(policy_compiler.get_warnings())

        # Automatic rules for filter table (only for top rule set, once)
        auto_pos = automatic_rules_stream.tell()
        if self._is_top_ruleset(pol_rs) and auto_pos <= 0:
            auto_buf = io.StringIO()

            auto_buf.write(policy_compiler.flush_and_set_default_policy())
            auto_buf.write(policy_compiler.print_automatic_rules())

            auto_text = auto_buf.getvalue()
            if auto_text:
                empty_output = False
                if not self.single_rule_compile_on:
                    automatic_rules_stream.write(
                        "# ================ Table 'filter', automatic rules\n"
                    )
                automatic_rules_stream.write(auto_text)

        # Automatic rules for mangle table (only for top rule set, once)
        auto_mangle_pos = automatic_mangle_stream.tell()
        if self._is_top_ruleset(pol_rs) and auto_mangle_pos <= 0:
            mangle_auto_buf = io.StringIO()
            mangle_auto_buf.write(
                mangle_compiler.print_automatic_rules_for_mangle_table(
                    self.have_connmark, self.have_connmark_in_output
                )
            )

            mangle_auto_text = mangle_auto_buf.getvalue()
            if mangle_auto_text:
                if not self.single_rule_compile_on:
                    automatic_mangle_stream.write(
                        "# ================ Table 'mangle', automatic rules\n"
                    )
                automatic_mangle_stream.write(mangle_auto_text)

        return empty_output

    # -- dumpScript: per-AF script body via configlets --

    def _dump_script(
        self,
        fw: Firewall,
        automatic_rules_script: str,
        automatic_mangle_script: str,
        nat_script: str,
        mangle_script: str,
        filter_script: str,
        ipv6_policy: bool,
    ) -> str:
        """Assemble one AF's compilation output using configlets."""
        have_auto = bool(automatic_rules_script or automatic_mangle_script)
        use_iptables_restore = fw.get_option('use_iptables_restore', False)

        if self.single_rule_compile_on:
            have_auto = False
            conf = Configlet('linux24', 'script_body_single_rule')
            conf.collapse_empty_strings(True)
        elif use_iptables_restore:
            conf = Configlet('linux24', 'script_body_iptables_restore')
        else:
            conf = Configlet('linux24', 'script_body_iptables_shell')

        conf.set_variable('auto', 1 if have_auto else 0)
        conf.set_variable('iptables_restore_format', 1 if use_iptables_restore else 0)

        conf.set_variable('filter', 1 if filter_script else 0)
        conf.set_variable('filter_or_auto', 1 if (have_auto or filter_script) else 0)
        conf.set_variable('filter_auto_script', automatic_rules_script)
        conf.set_variable('filter_script', filter_script)

        conf.set_variable('mangle', 1 if mangle_script else 0)
        conf.set_variable(
            'mangle_or_auto', 1 if (mangle_script or automatic_mangle_script) else 0
        )
        conf.set_variable('mangle_auto_script', automatic_mangle_script)
        conf.set_variable('mangle_script', mangle_script)

        conf.set_variable('nat', 1 if nat_script else 0)
        conf.set_variable('nat_script', nat_script)

        have_script = bool(have_auto or filter_script or mangle_script or nat_script)
        conf.set_variable('have_script', 1 if have_script else 0)
        conf.set_variable('ipv4', 0 if ipv6_policy else 1)
        conf.set_variable('ipv6', 1 if ipv6_policy else 0)

        return conf.expand()

    # -- Utility methods --

    def _matching_address_family(self, ruleset: RuleSet, policy_af: int) -> bool:
        """Check if a rule set matches the given address family."""
        if hasattr(ruleset, 'matching_address_family'):
            return ruleset.matching_address_family(policy_af)
        return True

    def _is_top_ruleset(self, ruleset: RuleSet) -> bool:
        """Check if a rule set is the top-level rule set.

        The ``top`` column on ``RuleSet`` is populated from the
        ``top_rule_set`` XML attribute by the XML reader.
        """
        return bool(ruleset.top)

    def info(self, msg: str) -> None:
        """Print informational message."""
        if self.verbose:
            print(msg)
