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
from firewallfabrik.driver._jinja2_template import Jinja2Template
from firewallfabrik.platforms.nftables import __compiler_version__
from firewallfabrik.platforms.nftables._identifiers import nft_object_name

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.core._database import DatabaseManager

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


def _declare_counters(names: list[str]) -> str:
    """Declare the named counter objects an accounting rule counts into.

    A counter has to exist as an object of the table before a rule can name
    it (netfilter nftables doc/stateful-objects.txt).
    """
    if not names:
        return ''
    out = []
    for name in names:
        out.append(f'    counter {name} {{\n    }}\n')
    out.append('\n')
    return ''.join(out)


_SET_LOADERS = {
    'file': 'load_address_table',
    'host': 'load_dns_name',
    'interface': 'load_interface_address',
}


def _declare_address_tables(tables: dict[str, tuple[str, bool, str]]) -> str:
    """Declare the named sets an address table rule matches against.

    The set has to exist before a rule can name it.  ``flags interval``
    makes it hold networks as well as single addresses, which is what an
    address table file may carry, and ``auto-merge`` folds the ones that
    overlap into each other: an interval set otherwise refuses the whole
    element list with "conflicting intervals specified", and a hand-kept
    block list regularly holds a host that is already covered by one of its
    networks (netfilter nftables doc/sets.txt).
    """
    if not tables:
        return ''
    out = []
    for name, (_source, ipv6, _kind) in sorted(tables.items()):
        addr_type = 'ipv6_addr' if ipv6 else 'ipv4_addr'
        out.append(
            f'    set {name} {{\n'
            f'        type {addr_type}\n'
            f'        flags interval\n'
            f'        auto-merge\n'
            f'    }}\n'
        )
    out.append('\n')
    return ''.join(out)


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
        # Whether any rule set asks for IPv6.  Decides the filter and mangle
        # table family (`inet` when both families share one, `ip` otherwise)
        # and, through that, whether a rule has to name its family itself.
        self._any_rs_ipv6: bool = False
        self._branch_chains: set[str] = set()
        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False
        self.filter_counters: list[str] = []
        self.mangle_counters: list[str] = []
        # Address tables rendered as named sets, per table of the ruleset.
        # Each maps the set name to the file the script reads it from.
        self.filter_address_tables: dict[str, tuple[str, bool, str]] = {}
        self.mangle_address_tables: dict[str, tuple[str, bool, str]] = {}
        self.nat_address_tables: dict[str, dict[str, tuple[str, bool, str]]] = {}

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

            iface_err = self.check_interface_addresses(fw)
            if iface_err:
                self.all_errors.append(iface_err)
                return ''

            try:
                options = fw.options or {}

                self._warn_unsupported_options(options)

                # Create OS configurator
                oscnf = OSConfigurator_nft(session, fw)

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

                # Determine whether to run IPv4/IPv6 compilation passes
                # based on the rule sets' explicit address-family flags.
                # If no rule set enables IPv6, skip the IPv6 pass entirely.
                self._any_rs_ipv6 = any(rs.ipv6 for rs in (*all_policies, *all_nat))
                if not self._any_rs_ipv6:
                    self.ipv6_run = False

                # Every branch rule set becomes a regular chain of that name.
                # Each rule set is compiled by a compiler of its own, so the
                # names have to be collected here for the one compiling the
                # rule that jumps into a branch to recognise its target.
                self._branch_chains = {
                    nft_object_name(rs.name)
                    for rs in all_policies
                    if not self._is_top_ruleset(rs)
                }

                # Determine IPv4/IPv6 run order (based on GUI option)
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

                # Collect all compiled rules per chain per AF
                # Structure: {chain_name: [rule_lines]}
                filter_chains: dict[str, list[str]] = {
                    'input': [],
                    'forward': [],
                    'output': [],
                }
                # Rules that set a packet mark or a traffic class need a
                # chain in front of the routing decision, which the filter
                # hooks run after; they go into a table of their own.
                mangle_chains: dict[str, list[str]] = {
                    'prerouting': [],
                    'input': [],
                    'forward': [],
                    'output': [],
                    'postrouting': [],
                }
                # NAT rules are kept per address family: nftables rejects an
                # `ip6` match inside an `ip` table (and vice versa), so each
                # family needs its own NAT table.
                nat_chains: dict[str, dict[str, list[str]]] = {
                    'ip': {'prerouting': [], 'postrouting': [], 'output': []},
                    'ip6': {'prerouting': [], 'postrouting': [], 'output': []},
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
                            self._process_mangle_rule_set(
                                session,
                                fw,
                                pol_rs,
                                single_rule_id,
                                mangle_chains,
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
                        self.all_warnings.extend(routing_compiler.get_warnings())

                # --- Assemble nft rules body ---
                nft_rules_body = self._assemble_nft_rules_body(
                    fw,
                    oscnf,
                    filter_chains,
                    nat_chains,
                    self._any_rs_ipv6,
                    mangle_chains,
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
                        elif self.all_warnings:
                            self.info(' Compiled with warnings')
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
        nat_chains: dict[str, dict[str, list[str]]],
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

        # Collect per-chain rules from the compiler into this rule set's
        # address family, so IPv4 and IPv6 NAT rules land in separate tables.
        family_key = 'ip6' if ipv6_policy else 'ip'
        fam_chains = nat_chains.setdefault(
            family_key, {'prerouting': [], 'postrouting': [], 'output': []}
        )
        for chain_name, rules in nat_compiler.chain_rules.items():
            if rules:
                fam_chains.setdefault(chain_name, []).extend(rules)

        self.nat_address_tables.setdefault(family_key, {}).update(
            nat_compiler.address_tables
        )

        if nat_compiler.get_errors() or nat_compiler.get_warnings():
            self.all_errors.extend(nat_compiler.get_errors())
            self.all_warnings.extend(nat_compiler.get_warnings())

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
        policy_compiler.shared_inet_table = self._any_rs_ipv6
        policy_compiler.branch_chains = self._branch_chains
        if not self._is_top_ruleset(pol_rs):
            policy_compiler.register_rule_set_chain(nft_object_name(pol_rs.name))
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

        # Collect per-chain rules from the compiler.  A branch chain is kept
        # even when it stays empty: nftables refuses the whole ruleset over a
        # jump to a chain that is not declared, and the rule that jumps into
        # this branch lives in another rule set.
        if policy_compiler.rule_set_chain:
            filter_chains.setdefault(policy_compiler.rule_set_chain, [])
        for chain_name, rules in policy_compiler.chain_rules.items():
            if rules:
                self.have_filter = True
                filter_chains.setdefault(chain_name, []).extend(rules)

        for counter in policy_compiler.counters:
            if counter not in self.filter_counters:
                self.filter_counters.append(counter)

        self.filter_address_tables.update(policy_compiler.address_tables)

        if policy_compiler.get_errors() or policy_compiler.get_warnings():
            self.all_errors.extend(policy_compiler.get_errors())
            self.all_warnings.extend(policy_compiler.get_warnings())

    def _process_mangle_rule_set(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        pol_rs: RuleSet,
        single_rule_id: str,
        mangle_chains: dict[str, list[str]],
        oscnf,
        policy_af: int,
    ) -> None:
        """Compile the mangle half of a single policy rule set."""
        from firewallfabrik.platforms.nftables._mangle_compiler import (
            MangleCompiler_nft,
        )

        ipv6_policy = policy_af == AF_INET6

        mangle_compiler = MangleCompiler_nft(session, fw, ipv6_policy, oscnf)
        mangle_compiler.shared_inet_table = self._any_rs_ipv6
        mangle_compiler.set_source_ruleset(pol_rs)
        mangle_compiler.source_ruleset = pol_rs

        if single_rule_id:
            mangle_compiler.single_rule_compile_mode = True
            mangle_compiler.single_rule_id = single_rule_id
        mangle_compiler.verbose = self.verbose > 0
        mangle_compiler.source_dir = self.source_dir
        mangle_compiler.debug_rule = self.debug_rule_policy
        mangle_compiler.rule_debug_on = self.debug_rule_policy >= 0

        mangle_rules_count = mangle_compiler.prolog()
        if mangle_rules_count > 0:
            mangle_compiler.compile()
            mangle_compiler.epilog()

        for chain_name, rules in mangle_compiler.chain_rules.items():
            if rules:
                mangle_chains.setdefault(chain_name, []).extend(rules)

        self.have_connmark = self.have_connmark or mangle_compiler.have_connmark
        self.have_connmark_in_output = (
            self.have_connmark_in_output or mangle_compiler.have_connmark_in_output
        )

        for counter in mangle_compiler.counters:
            if counter not in self.mangle_counters:
                self.mangle_counters.append(counter)

        self.mangle_address_tables.update(mangle_compiler.address_tables)

        if mangle_compiler.get_errors() or mangle_compiler.get_warnings():
            self.all_errors.extend(mangle_compiler.get_errors())
            self.all_warnings.extend(mangle_compiler.get_warnings())

    def _assemble_nft_rules_body(
        self,
        fw: Firewall,
        oscnf,
        filter_chains: dict[str, list[str]],
        nat_chains: dict[str, dict[str, list[str]]],
        have_ipv6: bool,
        mangle_chains: dict[str, list[str]] | None = None,
    ) -> str:
        """Assemble the nft rules body for embedding in a heredoc.

        Returns only the nft-format content (table/chain declarations
        and inline rules) without any shebang, header comments, or
        routing commands.  Each table is flushed individually so that
        rules managed by other tools (Docker, CrowdSec, fail2ban)
        remain untouched.
        """
        options = fw.options or {}
        # The base name comes from the firewall object, so it goes
        # through the sanitiser before it names three nft tables.
        table_name = nft_object_name(options.get('table_name', '') or 'fwf')
        filter_table = f'{table_name}_filter'
        nat_table = f'{table_name}_nat'
        mangle_table = f'{table_name}_mangle'
        mangle_chains = mangle_chains or {}

        out = io.StringIO()

        # Determine address family
        family = 'inet' if have_ipv6 else 'ip'

        # Default policy from firewall options
        input_policy = 'drop'
        output_policy = 'drop'
        forward_policy = 'drop'

        # --- Filter table ---
        # Automatic rules (accept established/related, drop invalid, ...) are
        # emitted in every filter chain. A firewall may carry no explicit
        # policy rules yet still rely on these plus the default-drop policy
        # for its protection, so they too must force the filter table to
        # exist. Otherwise nftables loads an empty ruleset that filters
        # nothing (fail-open), unlike the iptables output which always
        # installs the default-drop chains.
        auto_rules = {
            chain: oscnf.generate_automatic_rules(chain, have_ipv6)
            for chain in ('input', 'forward', 'output')
        }

        input_rules = ''.join(filter_chains.get('input', []))
        forward_rules = ''.join(filter_chains.get('forward', []))
        output_rules = ''.join(filter_chains.get('output', []))
        # Everything else a rule set claimed is a branch chain.  Empty ones
        # are declared too, because nftables refuses the whole ruleset over a
        # jump to a chain that does not exist.
        branch_chains = sorted(
            chain
            for chain in filter_chains
            if chain not in ('input', 'forward', 'output')
        )
        have_filter = bool(
            input_rules.strip()
            or forward_rules.strip()
            or output_rules.strip()
            or any(''.join(filter_chains[chain]).strip() for chain in branch_chains)
            or any(text.strip() for text in auto_rules.values())
        )

        # --- NAT tables (one per address family) ---
        # nftables rejects an `ip6` payload match inside an `ip` table, so
        # IPv4 and IPv6 NAT rules go into separate `ip`/`ip6` tables that
        # share the filter table's name suffix.
        nat_by_family = []
        for fam in ('ip', 'ip6'):
            fam_chains = nat_chains.get(fam, {})
            pre = ''.join(fam_chains.get('prerouting', []))
            post = ''.join(fam_chains.get('postrouting', []))
            outp = ''.join(fam_chains.get('output', []))
            if pre.strip() or post.strip() or outp.strip():
                nat_by_family.append((fam, pre, post, outp))
        have_nat = bool(nat_by_family)

        # --- Mangle table ---
        # A rule that saves its packet mark to the connection needs the mark
        # restored again on the way in, which iptables writes as
        # `-A PREROUTING -j CONNMARK --restore-mark` and nftables as
        # `meta mark set ct mark` (netfilter
        # extensions/libxt_CONNMARK.txlate). It goes in front of everything
        # else in the chain, as in the iptables output.
        restore_mark = '        counter meta mark set ct mark\n'
        auto_mangle = {}
        if self.have_connmark:
            auto_mangle['prerouting'] = restore_mark
        if self.have_connmark_in_output:
            auto_mangle['output'] = restore_mark

        # Only the chains that actually carry a rule are declared: an empty
        # chain at the mangle priority would hook every packet for nothing.
        mangle_by_chain = [
            (chain, auto_mangle.get(chain, '') + ''.join(mangle_chains.get(chain, [])))
            for chain in ('prerouting', 'input', 'forward', 'output', 'postrouting')
        ]
        mangle_by_chain = [(c, r) for c, r in mangle_by_chain if r.strip()]
        have_mangle = bool(mangle_by_chain)

        # Atomically delete our tables before recreating them.
        # "create + delete" ensures deletion works even on first run
        # (plain "delete" fails if the table does not exist yet).
        if have_filter:
            out.write(f'table {family} {filter_table} {{}}\n')
            out.write(f'delete table {family} {filter_table}\n')
        if have_mangle:
            out.write(f'table {family} {mangle_table} {{}}\n')
            out.write(f'delete table {family} {mangle_table}\n')
        for fam, *_ in nat_by_family:
            out.write(f'table {fam} {nat_table} {{}}\n')
            out.write(f'delete table {fam} {nat_table}\n')
        if have_filter or have_mangle or have_nat:
            out.write('\n')

        if have_mangle:
            out.write(f'table {family} {mangle_table} {{\n')
            out.write(_declare_counters(self.mangle_counters))
            out.write(_declare_address_tables(self.mangle_address_tables))
            for index, (chain, rules) in enumerate(mangle_by_chain):
                if index:
                    out.write('\n')
                out.write(f'    chain {chain} {{\n')
                out.write(
                    f'        type filter hook {chain} priority mangle;'
                    ' policy accept;\n'
                )
                out.write(rules)
                out.write('    }\n')
            out.write('}\n')
            out.write('\n')

        if have_filter:
            out.write(f'table {family} {filter_table} {{\n')
            out.write(_declare_counters(self.filter_counters))
            out.write(_declare_address_tables(self.filter_address_tables))

            # Input chain
            out.write('    chain input {\n')
            out.write(
                f'        type filter hook input priority filter; policy {input_policy};\n'
            )
            if auto_rules['input']:
                out.write(auto_rules['input'])
            if input_rules.strip():
                out.write(input_rules)
            out.write('    }\n')
            out.write('\n')

            # Forward chain
            out.write('    chain forward {\n')
            out.write(
                f'        type filter hook forward priority filter; policy {forward_policy};\n'
            )
            if auto_rules['forward']:
                out.write(auto_rules['forward'])
            # TCPMSS clamping on forwarded traffic — nft equivalent of
            # the iptables "-t mangle -A FORWARD -p tcp --tcp-flags
            # SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" rule.  Guarded
            # by `clamp_mss_to_mtu` firewall option and by the
            # platform's IP-forwarding option (matching fwbuilder's
            # PolicyCompiler_PrintRule::_clampTcpToMssRule).
            if fw.get_option('clamp_mss_to_mtu'):
                ipv4_fwd_raw = fw.get_option('linux24_ip_forward')
                ipv6_fwd_raw = fw.get_option('linux24_ipv6_forward')
                _fwd_on = lambda s: (  # noqa: E731
                    str(s or '').strip()
                    in (
                        '',
                        '1',
                        'On',
                        'on',
                        'True',
                        'true',
                    )
                )
                if _fwd_on(ipv4_fwd_raw) or (have_ipv6 and _fwd_on(ipv6_fwd_raw)):
                    out.write(
                        '        tcp flags syn / syn,rst '
                        'counter tcp option maxseg size set rt mtu\n'
                    )
            if forward_rules.strip():
                out.write(forward_rules)
            out.write('    }\n')
            out.write('\n')

            # Output chain
            out.write('    chain output {\n')
            out.write(
                f'        type filter hook output priority filter; policy {output_policy};\n'
            )
            if auto_rules['output']:
                out.write(auto_rules['output'])
            if output_rules.strip():
                out.write(output_rules)
            out.write('    }\n')

            # A branch rule set gets a regular chain: no hook, no policy, so
            # it runs only where a rule jumps to it.  nftables needs the
            # chain declared before the jump, and a chain block may only be
            # written once, so they come last inside the same table.
            for chain in branch_chains:
                out.write('\n')
                out.write(f'    chain {chain} {{\n')
                out.write(''.join(filter_chains[chain]))
                out.write('    }\n')

            out.write('}\n')
            out.write('\n')

        for fam, prerouting_rules, postrouting_rules, output_nat_rules in nat_by_family:
            out.write(f'table {fam} {nat_table} {{\n')
            out.write(_declare_address_tables(self.nat_address_tables.get(fam, {})))

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
        options = fw.options or {}

        user_name = os.environ.get('USER', 'unknown')

        debug = options.get('debug', False)
        shell_debug = 'set -x' if debug else ''

        prolog_script = options.get('prolog_script', '')
        epilog_script = options.get('epilog_script', '')
        prolog_place = options.get('prolog_place', '') or 'top'

        nft_path = options.get('nft_path', '') or '/usr/sbin/nft'

        # Build comment block
        comment_text = (fw.comment or '').rstrip('\n')
        comment = _prepend('#  ', comment_text) if comment_text else ''

        # Build errors/warnings block
        all_messages = self.all_errors + self.all_warnings
        errors_and_warnings = ''
        if all_messages:
            errors_and_warnings = '\n'.join(f'# {err}' for err in all_messages)

        # Management access for block action. The GUI / .fwb store this
        # as the "mgmt_ssh" boolean plus "mgmt_addr" (same keys as the
        # iptables compiler and fwbuilder); the backup SSH rule is only
        # emitted when both are set.
        ssh_management_address = options.get('mgmt_addr', '')
        mgmt_access = bool(options.get('mgmt_ssh', False)) and bool(
            ssh_management_address
        )

        # IP forwarding commands. Indent every line so multi-line output
        # (IPv4 plus IPv6) lines up inside the ip_forward() function body.
        ip_forward_commands = textwrap.indent(
            self._get_ip_forward_commands(fw),
            '    ',
        )

        # Kernel parameters (sysctl) and conntrack tuning. Backend-agnostic
        # /proc/sys writes; without these a firewall switched to nftables
        # would silently lose its kernel-hardening options.
        kernel_vars_commands = ''
        if oscnf is not None:
            raw_kernel_vars = oscnf.process_firewall_options(self._any_rs_ipv6).strip()
            if raw_kernel_vars:
                kernel_vars_commands = textwrap.indent(raw_kernel_vars, '    ')

        # Interface configuration
        configure_interfaces = options.get('configure_interfaces', False)
        verify_interfaces_opt = options.get('verify_interfaces', False)
        ip_path = options.get('ip_path', '') or 'ip'

        shell_functions = ''
        configure_interfaces_code = ''
        verify_interfaces_code = ''

        if oscnf is not None:
            # Include shell functions when any interface feature is enabled
            manage_virtual_addr = bool(
                options.get('manage_virtual_addr', False)
                and oscnf.virtual_addresses_for_nat
            )
            need_shell_functions = (
                configure_interfaces
                or verify_interfaces_opt
                or manage_virtual_addr
                or options.get('configure_bridge_interfaces', False)
                or any(iface.is_dynamic() for iface in fw.interfaces)
            )
            if need_shell_functions:
                shell_functions = oscnf.print_shell_functions()

            if configure_interfaces:
                buf = io.StringIO()
                buf.write(oscnf.print_interface_configuration_commands())

                if options.get('configure_bridge_interfaces', False):
                    buf.write(oscnf.print_bridge_interface_configuration_commands())

                buf.write(oscnf.print_commands_to_clear_known_interfaces())
                buf.write(oscnf.print_dynamic_addresses_configuration_commands())
                raw = textwrap.dedent(buf.getvalue()).strip()
                configure_interfaces_code = textwrap.indent(raw, '    ')
            elif manage_virtual_addr:
                # The addresses a NAT rule needs are added even when the
                # interfaces themselves are configured elsewhere; the firewall
                # has to carry them or it will not answer ARP for them and the
                # translated traffic never arrives.
                raw = oscnf.print_virtual_addresses_for_nat_commands().strip()
                if raw:
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

        # Named table support — only flush our own tables
        # The base name comes from the firewall object, so it goes
        # through the sanitiser before it names three nft tables.
        table_name = nft_object_name(options.get('table_name', '') or 'fwf')
        filter_table = f'{table_name}_filter'
        nat_table = f'{table_name}_nat'
        mangle_table = f'{table_name}_mangle'

        # Determine filter family (must match _assemble_nft_rules_body)
        filter_family = 'inet' if self._any_rs_ipv6 else 'ip'

        context = {
            'version': __compiler_version__,
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
            'kernel_vars_commands': kernel_vars_commands,
            'mgmt_access': mgmt_access,
            'ssh_management_address': ssh_management_address,
            'shell_functions': shell_functions,
            'configure_interfaces_code': configure_interfaces_code,
            'verify_interfaces_code': verify_interfaces_code,
            'filter_family': filter_family,
            'filter_table': filter_table,
            'flush_ruleset': options.get('flush_ruleset', True),
            'ip_path': ip_path,
            'nat_table': nat_table,
            'mangle_table': mangle_table,
            'address_table_code': self._address_table_load_commands(
                filter_family, filter_table, mangle_table, nat_table
            ),
        }

        template = Jinja2Template('nftables', 'script.sh.j2')
        return template.render(context)

    def _address_table_load_commands(
        self,
        filter_family: str,
        filter_table: str,
        mangle_table: str,
        nat_table: str,
    ) -> str:
        """Return one load command per address table set in the ruleset.

        The set lives in the table its rules are in, so a table used by both
        the filter and the NAT rules is loaded once per table.
        """
        lines: list[str] = []
        for table, tables in (
            (filter_table, self.filter_address_tables),
            (mangle_table, self.mangle_address_tables),
        ):
            for name, (source, ipv6, kind) in sorted(tables.items()):
                af = '-6' if ipv6 else '-4'
                loader = _SET_LOADERS[kind]
                lines.append(
                    f'    {loader} "{filter_family}" "{table}" '
                    f'"{name}" "{source}" "{af}"'
                )
        for fam, tables in sorted(self.nat_address_tables.items()):
            for name, (source, ipv6, kind) in sorted(tables.items()):
                af = '-6' if ipv6 else '-4'
                loader = _SET_LOADERS[kind]
                lines.append(
                    f'    {loader} "{fam}" "{nat_table}" "{name}" "{source}" "{af}"'
                )
        return '\n'.join(lines)

    def _get_ip_forward_commands(self, fw: Firewall) -> str:
        """Generate IP forwarding sysctl commands."""
        lines = []

        ipv4_fwd = str(fw.get_option('linux24_ip_forward') or '')
        if ipv4_fwd:
            val = 1 if ipv4_fwd in ('1', 'On', 'on') else 0
            lines.append(f'echo {val} > /proc/sys/net/ipv4/ip_forward')

        ipv6_fwd = str(fw.get_option('linux24_ipv6_forward') or '')
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
