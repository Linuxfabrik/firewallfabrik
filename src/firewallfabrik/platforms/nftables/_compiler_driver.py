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

"""CompilerDriver_nft: nftables compilation orchestrator.

This is the main entry point for nftables compilation. The run() method
orchestrates: preprocessor -> NAT compilation -> policy compilation ->
routing compilation -> nft script assembly -> file writing.

Output is a Bash shell script wrapper that applies the compiled nft
rules via a heredoc piped to ``nft -f``.
"""

from __future__ import annotations

import io
import os
import socket
import textwrap
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy

import firewallfabrik
from firewallfabrik.compiler._base import CompilerStatus
from firewallfabrik.core.objects import (
    NAT,
    Firewall,
    Policy,
    Routing,
    RuleSet,
)
from firewallfabrik.core.options._metadata import HOST_COMPILER_DEFAULTS
from firewallfabrik.driver._compiler_driver import CompilerDriver
from firewallfabrik.driver._jinja2_template import Jinja2Template

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.core._database import DatabaseManager

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


def _prepend(prefix: str, text: str) -> str:
    """Prepend a string to every non-empty line."""
    if not text:
        return text
    lines = text.split('\n')
    return '\n'.join(prefix + line if line else '' for line in lines)


class CompilerDriver_nft(CompilerDriver):
    """Orchestrates full nftables compilation.

    Creates and runs NAT and policy compilers, then assembles the
    output into a Bash shell script wrapper.
    """

    def __init__(self, db: DatabaseManager) -> None:
        super().__init__(db)
        self.have_nat: bool = False
        self.have_filter: bool = False

    def run(
        self,
        cluster_id: str,
        fw_id: str,
        single_rule_id: str,
    ) -> str:
        """Main compilation entry point.

        Performs the full nftables compilation pipeline:
        1. Look up firewall object
        2. Create OS configurator
        3. For each address family (IPv4/IPv6):
           a. Compile NAT rules
           b. Compile policy rules
        4. Compile routing rules
        5. Assemble shell script with embedded nft rules
        6. Write output file
        """
        from firewallfabrik.platforms.nftables._os_configurator import (
            OSConfigurator_nft,
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

            try:
                self._warn_unsupported_options(fw)

                # Create OS configurator
                oscnf = OSConfigurator_nft(session, fw)

                # Check if firewall has any IPv6 addresses
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

                # Determine IPv4/IPv6 run order (based on GUI option).
                # Empty means "use default ipv4_first".
                ipv4_6_runs: list[int] = []
                ipv4_6_order = (
                    fw.opt_ipv4_6_order or HOST_COMPILER_DEFAULTS['opt_ipv4_6_order']
                )
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

                # Collect all compiled rules per chain per AF
                # Structure: {chain_name: [rule_lines]}
                filter_chains: dict[str, list[str]] = {
                    'input': [],
                    'forward': [],
                    'output': [],
                }
                nat_chains: dict[str, list[str]] = {
                    'prerouting': [],
                    'postrouting': [],
                    'output': [],
                }

                for policy_af in ipv4_6_runs:
                    ipv6_policy = policy_af == AF_INET6

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

                    # --- NAT compilation ---
                    top_nat = None
                    for nat_rs in all_nat:
                        if not self._matching_address_family(nat_rs, policy_af):
                            continue
                        if self._is_top_ruleset(nat_rs):
                            top_nat = nat_rs
                            continue
                        self._process_nat_rule_set(
                            session,
                            fw,
                            nat_rs,
                            single_rule_id,
                            nat_chains,
                            oscnf,
                            policy_af,
                        )

                    if top_nat is not None:
                        self._process_nat_rule_set(
                            session,
                            fw,
                            top_nat,
                            single_rule_id,
                            nat_chains,
                            oscnf,
                            policy_af,
                        )

                    # --- Policy compilation ---
                    for all_top in range(2):
                        for pol_rs in all_policies:
                            if not self._matching_address_family(pol_rs, policy_af):
                                continue
                            is_top = self._is_top_ruleset(pol_rs)
                            if is_top and all_top == 0:
                                continue
                            if not is_top and all_top == 1:
                                continue

                            self._process_policy_rule_set(
                                session,
                                fw,
                                pol_rs,
                                single_rule_id,
                                filter_chains,
                                oscnf,
                                policy_af,
                            )

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

                # --- Assemble nft rules body ---
                nft_rules_body = self._assemble_nft_rules_body(
                    fw,
                    oscnf,
                    filter_chains,
                    nat_chains,
                    fw_has_ipv6,
                )

                # Single-rule compile mode: return raw rules (no shell wrapper)
                if self.single_rule_compile_on:
                    errors_str = '\n'.join(self.all_errors)
                    return errors_str + nft_rules_body + routing_output

                # --- Determine output file names (needed for manifest) ---
                cluster_name = ''
                self.determine_output_file_names(fw, cluster_name)

                # --- Assemble shell script ---
                script = self._assemble_shell_script(
                    fw,
                    nft_rules_body,
                    routing_output,
                    oscnf,
                )

                # --- Write output file ---
                fw_id_str = str(fw.id)
                output_path = self.file_names.get(fw_id_str, '')
                if output_path:
                    self.info(f'Output file name: {output_path}')
                    try:
                        out_p = Path(output_path)
                        out_p.parent.mkdir(parents=True, exist_ok=True)
                        out_p.write_text(script, encoding='utf-8')
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

    def _process_nat_rule_set(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        nat_rs: RuleSet,
        single_rule_id: str,
        nat_chains: dict[str, list[str]],
        oscnf,
        policy_af: int,
    ) -> None:
        """Compile a single NAT rule set."""
        from firewallfabrik.platforms.nftables._nat_compiler import (
            NATCompiler_nft,
        )

        ipv6_policy = policy_af == AF_INET6

        nat_compiler = NATCompiler_nft(session, fw, ipv6_policy, oscnf)
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

        # Collect per-chain rules from the compiler
        for chain_name, rules in nat_compiler.chain_rules.items():
            if rules:
                nat_chains.setdefault(chain_name, []).extend(rules)

        if nat_compiler.get_errors() or nat_compiler.get_warnings():
            self.all_errors.extend(nat_compiler.get_errors())
            self.all_errors.extend(nat_compiler.get_warnings())

    def _process_policy_rule_set(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        pol_rs: RuleSet,
        single_rule_id: str,
        filter_chains: dict[str, list[str]],
        oscnf,
        policy_af: int,
    ) -> None:
        """Compile a single policy rule set."""
        from firewallfabrik.platforms.nftables._policy_compiler import (
            PolicyCompiler_nft,
        )

        ipv6_policy = policy_af == AF_INET6

        policy_compiler = PolicyCompiler_nft(session, fw, ipv6_policy, oscnf)
        policy_compiler.set_source_ruleset(pol_rs)
        policy_compiler.source_ruleset = pol_rs

        if single_rule_id:
            policy_compiler.single_rule_compile_mode = True
            policy_compiler.single_rule_id = single_rule_id
        policy_compiler.verbose = self.verbose > 0
        policy_compiler.source_dir = self.source_dir
        policy_compiler.debug_rule = self.debug_rule_policy
        policy_compiler.rule_debug_on = self.debug_rule_policy >= 0

        policy_rules_count = policy_compiler.prolog()
        if policy_rules_count > 0:
            policy_compiler.compile()
            policy_compiler.epilog()

        # Collect per-chain rules from the compiler
        for chain_name, rules in policy_compiler.chain_rules.items():
            if rules:
                self.have_filter = True
                filter_chains.setdefault(chain_name, []).extend(rules)

        if policy_compiler.get_errors() or policy_compiler.get_warnings():
            self.all_errors.extend(policy_compiler.get_errors())
            self.all_errors.extend(policy_compiler.get_warnings())

    def _assemble_nft_rules_body(
        self,
        fw: Firewall,
        oscnf,
        filter_chains: dict[str, list[str]],
        nat_chains: dict[str, list[str]],
        have_ipv6: bool,
    ) -> str:
        """Assemble the nft rules body for embedding in a heredoc.

        Returns only the nft-format content (flush ruleset, table/chain
        declarations and inline rules) without any shebang, header
        comments, or routing commands.
        """
        out = io.StringIO()

        out.write('flush ruleset\n')
        out.write('\n')

        # Determine address family
        family = 'inet' if have_ipv6 else 'ip'

        # Default policy from firewall options
        input_policy = 'drop'
        output_policy = 'drop'
        forward_policy = 'drop'

        # --- Filter table ---
        input_rules = ''.join(filter_chains.get('input', []))
        forward_rules = ''.join(filter_chains.get('forward', []))
        output_rules = ''.join(filter_chains.get('output', []))
        have_filter = bool(
            input_rules.strip() or forward_rules.strip() or output_rules.strip()
        )

        if have_filter:
            out.write(f'table {family} filter {{\n')

            # Automatic rules (established/related, etc.)
            auto_rules = oscnf.generate_automatic_rules()

            # Input chain
            out.write('    chain input {\n')
            out.write(
                f'        type filter hook input priority filter; policy {input_policy};\n'
            )
            if auto_rules:
                out.write(auto_rules)
            if input_rules.strip():
                out.write(input_rules)
            out.write('    }\n')
            out.write('\n')

            # Forward chain
            out.write('    chain forward {\n')
            out.write(
                f'        type filter hook forward priority filter; policy {forward_policy};\n'
            )
            if auto_rules:
                out.write(auto_rules)
            if forward_rules.strip():
                out.write(forward_rules)
            out.write('    }\n')
            out.write('\n')

            # Output chain
            out.write('    chain output {\n')
            out.write(
                f'        type filter hook output priority filter; policy {output_policy};\n'
            )
            if auto_rules:
                out.write(auto_rules)
            if output_rules.strip():
                out.write(output_rules)
            out.write('    }\n')

            out.write('}\n')
            out.write('\n')

        # --- NAT table ---
        prerouting_rules = ''.join(nat_chains.get('prerouting', []))
        postrouting_rules = ''.join(nat_chains.get('postrouting', []))
        output_nat_rules = ''.join(nat_chains.get('output', []))
        have_nat = bool(
            prerouting_rules.strip()
            or postrouting_rules.strip()
            or output_nat_rules.strip()
        )

        if have_nat:
            # NAT uses ip family (not inet) for broader compatibility
            nat_family = 'ip'
            out.write(f'table {nat_family} nat {{\n')

            # Prerouting chain (DNAT)
            out.write('    chain prerouting {\n')
            out.write('        type nat hook prerouting priority dstnat;\n')
            if prerouting_rules.strip():
                out.write(prerouting_rules)
            out.write('    }\n')

            # Output chain (local NAT — DNAT for locally-originated traffic)
            if output_nat_rules.strip():
                out.write('\n')
                out.write('    chain output {\n')
                out.write('        type nat hook output priority dstnat;\n')
                out.write(output_nat_rules)
                out.write('    }\n')

            out.write('\n')

            # Postrouting chain (SNAT/masquerade)
            out.write('    chain postrouting {\n')
            out.write('        type nat hook postrouting priority srcnat;\n')
            if postrouting_rules.strip():
                out.write(postrouting_rules)
            out.write('    }\n')

            out.write('}\n')
            out.write('\n')

        return out.getvalue()

    def _assemble_shell_script(
        self,
        fw: Firewall,
        nft_rules_body: str,
        routing_output: str,
        oscnf=None,
    ) -> str:
        """Assemble the complete shell script using the Jinja2 template."""
        timestr = time.strftime('%c')
        tz = time.strftime('%Z')
        user_name = os.environ.get('USER', 'unknown')

        debug = fw.opt_debug
        shell_debug = 'set -x' if debug else ''

        prolog_script = fw.opt_prolog_script or ''
        epilog_script = fw.opt_epilog_script or ''
        prolog_place = fw.opt_prolog_place or HOST_COMPILER_DEFAULTS['opt_prolog_place']

        nft_path = fw.opt_nft_path or '/usr/sbin/nft'

        # Build comment block
        comment_text = (fw.comment or '').rstrip('\n')
        comment = _prepend('#  ', comment_text) if comment_text else ''

        # Build errors/warnings block
        errors_and_warnings = ''
        if self.all_errors:
            errors_and_warnings = '\n'.join(f'# {err}' for err in self.all_errors)

        # Management access for block action
        mgmt_access = bool(fw.opt_mgmt_access)
        ssh_management_address = fw.opt_mgmt_addr or ''

        # IP forwarding commands
        ip_forward_commands = self._get_ip_forward_commands(fw)

        # Interface configuration
        configure_interfaces = fw.opt_configure_interfaces
        verify_interfaces_opt = fw.opt_verify_interfaces
        ip_path = fw.opt_ip_path or 'ip'

        shell_functions = ''
        configure_interfaces_code = ''
        verify_interfaces_code = ''

        if oscnf is not None:
            # Include shell functions when any interface feature is enabled
            need_shell_functions = (
                configure_interfaces
                or verify_interfaces_opt
                or any(iface.is_dynamic() for iface in fw.interfaces)
            )
            if need_shell_functions:
                shell_functions = oscnf.print_shell_functions()

            if configure_interfaces:
                buf = io.StringIO()
                buf.write(oscnf.print_interface_configuration_commands())
                buf.write(oscnf.print_commands_to_clear_known_interfaces())
                buf.write(oscnf.print_dynamic_addresses_configuration_commands())
                raw = textwrap.dedent(buf.getvalue()).strip()
                configure_interfaces_code = textwrap.indent(raw, '    ')

            if verify_interfaces_opt:
                raw = textwrap.dedent(oscnf.print_verify_interfaces_commands()).strip()
                verify_interfaces_code = textwrap.indent(raw, '    ')

        # Build manifest line for installer
        fw_id_str = str(fw.id)
        local_name = Path(self.file_names.get(fw_id_str, '')).name
        manifest = f'# files: * {local_name}'
        remote = self.remote_file_names.get(fw_id_str, '')
        if remote:
            manifest += f' {remote}'

        context = {
            'version': firewallfabrik.__version__,
            'timestamp': timestr,
            'tz': tz,
            'user': user_name,
            'comment': comment,
            'errors_and_warnings': errors_and_warnings,
            'manifest': manifest,
            'shell_debug': shell_debug,
            'nft_path': nft_path,
            'prolog_script': prolog_script,
            'epilog_script': epilog_script,
            'prolog_place': prolog_place,
            'nft_rules_body': nft_rules_body,
            'routing_output': routing_output,
            'ip_forward_commands': ip_forward_commands,
            'mgmt_access': mgmt_access,
            'ssh_management_address': ssh_management_address,
            'shell_functions': shell_functions,
            'configure_interfaces_code': configure_interfaces_code,
            'verify_interfaces_code': verify_interfaces_code,
            'ip_path': ip_path,
        }

        template = Jinja2Template('nftables', 'script.sh.j2')
        return template.render(context)

    def _get_ip_forward_commands(self, fw: Firewall) -> str:
        """Generate IP forwarding sysctl commands."""
        lines = []

        ipv4_fwd = str(fw.opt_ip_forward or '')
        if ipv4_fwd:
            val = 1 if ipv4_fwd in ('1', 'On', 'on') else 0
            lines.append(f'echo {val} > /proc/sys/net/ipv4/ip_forward')

        ipv6_fwd = str(fw.opt_ipv6_forward or '')
        if ipv6_fwd:
            val = 1 if ipv6_fwd in ('1', 'On', 'on') else 0
            lines.append(f'echo {val} > /proc/sys/net/ipv6/conf/all/forwarding')

        return '\n'.join(lines)

    # -- Utility methods --

    def _matching_address_family(self, ruleset: RuleSet, policy_af: int) -> bool:
        """Check if a rule set matches the given address family."""
        if hasattr(ruleset, 'matching_address_family'):
            return ruleset.matching_address_family(policy_af)
        return True

    def _is_top_ruleset(self, ruleset: RuleSet) -> bool:
        """Check if a rule set is the top-level rule set."""
        return bool(ruleset.top)

    def info(self, msg: str) -> None:
        """Print informational message."""
        if self.verbose:
            print(msg)
