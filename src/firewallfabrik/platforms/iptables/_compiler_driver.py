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
from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy

from firewallfabrik.compiler._base import CompilerStatus
from firewallfabrik.compiler.processors._policy import (
    is_mangle_only_rule_set,
    rule_set_classifies,
    rule_set_has_mangle_rules,
)
from firewallfabrik.core.objects import (
    NAT,
    Firewall,
    Policy,
    Routing,
    RuleSet,
)
from firewallfabrik.driver._compiler_driver import CompilerDriver
from firewallfabrik.driver._configlet import Configlet
from firewallfabrik.platforms.iptables import __compiler_version__
from firewallfabrik.platforms.iptables._utils import (
    get_iptables_version,
    get_wait_option,
    version_compare,
)
from firewallfabrik.platforms.linux._automatic_rules import AutomaticRules
from firewallfabrik.platforms.linux._netfilter import (
    is_valid_mgmt_address,
    mgmt_address_family,
    mgmt_address_is_ipv6,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

    from firewallfabrik.core._database import DatabaseManager

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


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

    def my_platform_name(self) -> str:
        return 'iptables'

    def __init__(self, db: DatabaseManager) -> None:
        super().__init__(db)
        self.have_connmark: bool = False
        self.have_connmark_in_output: bool = False
        self.have_nat: bool = False
        # The chains each NAT rule set used, keyed by rule set name.  A rule
        # with the Branch action reads it to jump into the chain of the
        # branch that belongs to its own chain, instead of being copied into
        # prerouting and postrouting at once.
        self._nat_branch_chains: dict[str, list[str]] = {}
        # The names of the policy rule sets a Branch rule can jump to.
        self._branch_chains: set[str] = set()
        # The branch jumps that close a cycle, by (source, target) rule set
        # name; the kernel refuses such a jump.
        self._branch_loop_edges: set[tuple[str, str]] = set()
        self._mangle_only_branch_chains: set[str] = set()
        self._mangle_branch_chains: set[str] = set()
        self._classifying_branch_chains: set[str] = set()
        # The hash table each rate limit kept per source, destination or
        # port counts in, and the settings the first rule gave it.  The
        # kernel looks the table up by its name and family alone
        # (net/netfilter/xt_hashlimit.c, htable_find_get) and hands the
        # existing one back, configuration and all, so a name reused by
        # another rule set or by the mangle pass has to be noticed here -
        # every rule set and every table is compiled by a compiler of its
        # own, which cannot see what the others named.
        self._hashlimit_tables: dict[str, tuple[int, str, str]] = {}
        self._automatic_rules: list = []

        # Prolog/epilog tracking

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
        with self.compile_session() as session:
            if not fw_id:
                self.error('No firewall ID provided')
                return ''

            cluster, fw = self.get_firewall_and_cluster(session, cluster_id, fw_id)

            if fw is None:
                self.error(f'Firewall {fw_id} not found')
                return ''
            if cluster_id and cluster is None:
                self.error(f'Cluster {cluster_id} not found')
                return ''

            self.fw = fw
            self.cluster = cluster

            # A member firewall inherits the cluster's interfaces and rule
            # sets before anything else looks at it
            # (CompilerDriver::populateClusterElements).  The session is
            # rolled back when the compile ends, so none of it reaches the
            # object tree the editor shows.
            if cluster is not None:
                cluster_problem = self.populate_cluster_elements(session, cluster, fw)
                if cluster_problem:
                    self.error(cluster_problem)
                    return ''
                # A cluster member has to see the other members, or both
                # consider themselves master and conntrackd replicates
                # nothing (AutomaticRules_ipt, called from
                # CompilerDriver_ipt::run before the rule ids are
                # assigned).
                automatic_rules = AutomaticRules(fw, session)
                self._automatic_rules = automatic_rules.build()
                for problem in automatic_rules.problems:
                    self.error(problem)
            generated_script = ''

            iface_err = self.check_interface_addresses(fw)
            if iface_err:
                self.all_errors.append(iface_err)
                return ''

            try:
                fw_version = fw.version or '(any version)'
                options = fw.options or {}

                # Validate prolog placement with iptables-restore
                prolog_place = self.firewall_option(fw, 'prolog_place')
                if prolog_place == 'after_flush' and self.firewall_option(
                    fw, 'use_iptables_restore'
                ):
                    self.error(
                        'Prolog place "after policy reset" can not be used'
                        ' when policy is activated with iptables-restore'
                    )
                    return ''

                self._warn_unsupported_options(options, fw)

                flush_ruleset = self.firewall_option(fw, 'flush_ruleset')
                table_name = self.firewall_option(fw, 'table_name') or 'fwf'
                # Store for use in sub-compiler methods.
                self._flush_ruleset = flush_ruleset
                self._table_name = table_name

                debug = self.firewall_option(fw, 'debug')
                shell_dbg = 'set -x' if debug else ''

                # Create OS configurator
                oscnf = OSConfigurator_linux24(session, fw)

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

                all_routing = (
                    session.execute(
                        sqlalchemy.select(Routing).where(
                            Routing.device_id == fw.id,
                        ),
                    )
                    .scalars()
                    .all()
                )

                # A cluster's rule sets are what its members have in
                # common; a member overrides one by giving a rule set of its
                # own the same name (CompilerDriver::mergeRuleSets).  All
                # three kinds move across, the way the C++ calls the merge
                # once per type (CompilerDriver.cpp:1095): where a cluster
                # keeps the routes its members share, a member compiled
                # without them installs the new packet filter and none of
                # the routes it needs to reach anything.
                if cluster is not None:
                    all_policies = self.merge_rule_sets(
                        cluster, fw, all_policies, Policy
                    )
                    all_nat = self.merge_rule_sets(cluster, fw, all_nat, NAT)
                    all_routing = self.merge_rule_sets(
                        cluster, fw, all_routing, Routing
                    )

                self.warn_about_missing_top_rule_sets(fw, all_policies, all_nat)

                # A Branch rule may point at a rule set of another firewall
                # object; that rule set is compiled into this script, or the
                # jump lands in a chain nothing fills
                # (CompilerDriver::findImportedRuleSets, issue #156).
                imported_policies = self.find_imported_rule_sets(
                    session, fw, list(all_policies), Policy
                )
                imported_nat = self.find_imported_rule_sets(
                    session, fw, list(all_nat), NAT
                )
                self._imported_rule_sets = {
                    rs.id for rs in (*imported_policies, *imported_nat)
                }
                all_policies = [*all_policies, *imported_policies]
                all_nat = [*all_nat, *imported_nat]

                have_ipv4 = False
                have_ipv6 = False

                # Determine whether to run IPv4/IPv6 compilation passes
                # based on the rule sets' explicit address-family flags.
                # If no rule set enables IPv6, skip the IPv6 pass entirely.
                any_rs_ipv6 = any(rs.ipv6 for rs in (*all_policies, *all_nat))
                if not any_rs_ipv6:
                    self.ipv6_run = False

                # Which rule sets a Branch rule can reach.  Each rule set is
                # compiled by a compiler of its own, so the names have to be
                # collected here for the one compiling the branching rule.
                self._branch_chains = {
                    pol_rs.name
                    for pol_rs in all_policies
                    if not self._is_top_ruleset(pol_rs)
                }
                # A jump into a chain that can reach itself is refused
                # by the kernel; only the jump that closes the cycle is
                # named, so the rest of the branch tree stays reachable.
                self._branch_loop_edges = self.find_branch_loop_edges(
                    session, [*all_policies, *all_nat]
                )
                # Of those, the ones that compile into the mangle table
                # alone: a rule branching into one has nothing to jump to in
                # the filter table.
                self._mangle_only_branch_chains = {
                    pol_rs.name
                    for pol_rs in all_policies
                    if not self._is_top_ruleset(pol_rs)
                    and is_mangle_only_rule_set(pol_rs)
                }
                # And the ones holding a rule that tags or classifies: a
                # rule branching into one has to be compiled into the mangle
                # table as well, or nothing ever reaches those rules
                # (CompilerDriver_ipt::findBranchesInMangleTable, which sets
                # the rule's own "branch in mangle table" option for it).
                self._mangle_branch_chains = {
                    pol_rs.name
                    for pol_rs in all_policies
                    if not self._is_top_ruleset(pol_rs)
                    and rule_set_has_mangle_rules(pol_rs)
                }
                # Of those, the ones that assign a traffic class: iptables
                # refuses a jump into them from prerouting.
                self._classifying_branch_chains = {
                    pol_rs.name
                    for pol_rs in all_policies
                    if not self._is_top_ruleset(pol_rs) and rule_set_classifies(pol_rs)
                }

                # Chain trackers per table
                minus_n_commands_filter: dict[str, bool] = {}
                minus_n_commands_mangle: dict[str, bool] = {}
                minus_n_commands_nat: dict[str, bool] = {}

                # Determine IPv4/IPv6 run order
                ipv4_6_runs: list[int] = []
                ipv4_6_order = self.firewall_option(fw, 'ipv4_6_order')
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
                routing_rs = all_routing[0] if all_routing else None

                if routing_rs:
                    routing_compiler = RoutingCompilerLinux(session, fw, False)
                    routing_compiler.set_source_ruleset(routing_rs)
                    routing_compiler.source_ruleset = routing_rs

                    if single_rule_id:
                        routing_compiler.single_rule_compile_mode = True
                        routing_compiler.single_rule_id = single_rule_id
                    routing_compiler.verbose = self.verbose > 0
                    # --xr, the routing counterpart of --xp and --xn.  The
                    # two siblings were handed to their compilers and this
                    # one was not, so the flag did nothing on either
                    # platform although the developer guide documents it.
                    routing_compiler.debug_rule = self.debug_rule_routing
                    routing_compiler.rule_debug_on = self.debug_rule_routing >= 0
                    routing_compiler.source_dir = self.source_dir

                    routing_rules_count = routing_compiler.prolog()
                    if routing_rules_count > 0:
                        routing_compiler.compile()
                        routing_compiler.epilog()

                    routing_output = routing_compiler.output.getvalue()

                    # Configlet.expand() drops the trailing newline of the
                    # rule block, so the first routing command would be
                    # appended to the last iptables command.
                    if routing_output and not generated_script.endswith('\n'):
                        generated_script += '\n'

                    if routing_compiler.get_errors() or routing_compiler.get_warnings():
                        self.all_errors.extend(routing_compiler.get_errors())
                        self.all_warnings.extend(routing_compiler.get_warnings())

                # Single-rule compile mode
                if self.single_rule_compile_on:
                    errors_str = '\n'.join(self.all_errors)
                    return errors_str + generated_script + routing_output

                # --- Script assembly ---
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
                prolog_script = self.firewall_option(fw, 'prolog_script')
                epilog_script = self.firewall_option(fw, 'epilog_script')
                script_skeleton.set_variable('prolog_script', prolog_script)
                script_skeleton.set_variable('epilog_script', epilog_script)

                # Interface configuration
                iface_buf = io.StringIO()
                iface_buf.write('# Configure interfaces\n')

                if self.firewall_option(fw, 'configure_interfaces'):
                    iface_buf.write(oscnf.print_interface_configuration_commands())
                elif self.firewall_option(fw, 'manage_virtual_addr'):
                    # The addresses a NAT rule needs are added even when the
                    # interfaces themselves are configured elsewhere; the
                    # firewall has to carry them or it will not answer ARP for
                    # them and the translated traffic never arrives.
                    iface_buf.write(oscnf.print_virtual_addresses_for_nat_commands())

                if self.firewall_option(fw, 'configure_bridge_interfaces'):
                    iface_buf.write(
                        oscnf.print_bridge_interface_configuration_commands()
                    )

                iface_buf.write(oscnf.print_commands_to_clear_known_interfaces())
                iface_buf.write(oscnf.print_dynamic_addresses_configuration_commands())

                script_skeleton.set_variable(
                    'configure_interfaces', _indent(4, iface_buf.getvalue())
                )

                # Verify interfaces
                if self.firewall_option(fw, 'verify_interfaces'):
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

                body_buf.write(oscnf.process_firewall_options(have_ipv6))
                body_buf.write(generated_script)
                body_buf.write(routing_output)
                body_buf.write('\n')

                script_skeleton.set_variable(
                    'script_body', _indent(4, body_buf.getvalue())
                )

                # Metadata
                script_skeleton.set_variable('user', user_name)
                script_skeleton.set_variable('database', '')

                # Reset commands
                use_ipt_restore = self.firewall_option(fw, 'use_iptables_restore')

                # Who empties the firewall's own chains before the policy
                # goes in.  `iptables-restore` does it itself, by emptying
                # every chain of the table before it reads the first rule -
                # but in coexistence mode it is called with `--noflush`,
                # because the other tools' rules are in those chains too.
                # Then nothing empties them and `reset_all` has to, the way
                # it does for the shell form; without it every activation
                # appends the whole policy again.
                run_reset_all = not use_ipt_restore or not flush_ruleset
                if not flush_ruleset and use_ipt_restore:
                    self.warning(
                        '"Flush entire ruleset" is disabled \u2014 only '
                        "FirewallFabrik's own chains will be flushed so "
                        'that rules created by other tools (e.g. Docker, '
                        'CrowdSec, fail2ban) are preserved. '
                        '"Use iptables-restore" therefore runs with '
                        '--noflush.'
                    )

                script_skeleton.set_variable(
                    'not_using_iptables_restore', 1 if run_reset_all else 0
                )

                reset_buf = ''
                if flush_ruleset:
                    # Default: flush everything for a deterministic state.
                    # On RHEL8+ / modern distros, iptables uses the nftables
                    # backend (iptables-nft). Flush any pre-existing nftables
                    # rules first — iptables -F does not clear them.
                    reset_buf += (
                        '    command -v nft >/dev/null 2>&1 && nft flush ruleset\n'
                    )
                    if have_ipv4:
                        reset_buf += '    reset_iptables_v4\n'
                    if have_ipv6:
                        reset_buf += '    reset_iptables_v6\n'
                else:
                    # Coexistence: only flush FWF's own prefixed chains.
                    if have_ipv4:
                        reset_buf += f'    reset_fwf_chains_v4 "{table_name}"\n'
                    if have_ipv6:
                        reset_buf += f'    reset_fwf_chains_v6 "{table_name}"\n'
                script_skeleton.set_variable('reset_all', reset_buf)

                # Coexistence mode: load configlets for prefixed chain
                # management and wire setup_fwf_jumps into script_body.
                real_version = get_iptables_version(fw)
                opt_wait = get_wait_option(real_version)

                # Always include coexistence helper functions so that
                # switching flush_ruleset on/off produces minimal diffs.
                reset_fwf = Configlet('linux24', 'reset_fwf_chains')
                reset_fwf.set_variable('opt_wait', opt_wait)
                setup_fwf = Configlet('linux24', 'setup_fwf_jumps')
                setup_fwf.set_variable('opt_wait', opt_wait)
                script_skeleton.set_variable(
                    'fwf_chain_functions',
                    reset_fwf.expand() + '\n\n' + setup_fwf.expand(),
                )

                if not flush_ruleset:
                    # Build setup_fwf_jumps calls for v4 and v6.
                    setup_cmds = ''
                    if have_ipv4:
                        setup_cmds += f'        setup_fwf_jumps_v4 "{table_name}"\n'
                    if have_ipv6:
                        setup_cmds += f'        setup_fwf_jumps_v6 "{table_name}"\n'
                    script_skeleton.set_variable(
                        'setup_fwf_jumps_commands',
                        setup_cmds,
                    )
                else:
                    script_skeleton.set_variable(
                        'setup_fwf_jumps_commands',
                        '',
                    )

                # Management SSH access for block/stop actions
                mgmt_ssh = bool(self.firewall_option(fw, 'mgmt_ssh'))
                mgmt_addr = self.firewall_option(fw, 'mgmt_addr')
                mgmt_access = 1 if (mgmt_ssh and mgmt_addr) else 0
                if mgmt_access and not is_valid_mgmt_address(mgmt_addr):
                    # The value goes into a shell command at the one moment
                    # every policy has just been set to DROP, so a space or
                    # a shell metacharacter costs the way back in.
                    self.all_errors.append(
                        f'"{mgmt_addr}" cannot be the address of the backup '
                        'ssh rule; the block action leaves no way in'
                    )
                    mgmt_access = 0
                # The backup rule has to go to the binary that speaks the
                # family of the address.  iptables answers an IPv6 address
                # with "host/network not found", and it does so right after
                # the block action set every policy to DROP, which is the
                # one moment the administrator needs this rule.
                mgmt_tool = (
                    '$IP6TABLES' if mgmt_address_is_ipv6(mgmt_addr) else '$IPTABLES'
                )
                # The rule in the ruleset itself needs an address literal of a
                # family this firewall compiles.  Where that does not hold,
                # only the block and stop actions keep the way in, which is
                # not what the option promises - so say it.
                mgmt_family = mgmt_address_family(mgmt_addr)
                mgmt_reason = ''
                if mgmt_access and not mgmt_family:
                    mgmt_reason = 'is not an IP address'
                elif mgmt_access and not (
                    have_ipv6 if mgmt_family == 'ip6' else have_ipv4
                ):
                    family = 'IPv6' if mgmt_family == 'ip6' else 'IPv4'
                    mgmt_reason = (
                        f'is {family} and this firewall compiles no {family} rule set'
                    )
                if mgmt_reason:
                    self.all_warnings.append(
                        f'The management workstation address "{mgmt_addr}" '
                        f'{mgmt_reason}, so the rule permitting ssh from it is '
                        'only in the block and stop actions, not in the ruleset'
                    )
                mgmt_state_option = (
                    'conntrack --ctstate'
                    if version_compare(real_version, '1.4.4') >= 0
                    else 'state --state'
                )

                # Block action configlet
                block_action = Configlet('linux24', 'block_action')
                block_action.set_variable('opt_wait', opt_wait)
                block_action.collapse_empty_strings(True)
                block_action.set_variable('mgmt_access', mgmt_access)
                block_action.set_variable(
                    'ssh_management_address',
                    mgmt_addr,
                )
                block_action.set_variable('mgmt_tool', mgmt_tool)
                block_action.set_variable('state_module_option', mgmt_state_option)
                script_skeleton.set_variable('block_action', block_action.expand())

                # Stop action configlet — in full-flush mode policies
                # stay at DROP (server stays protected); in coexistence
                # mode policies are restored to ACCEPT so other tools'
                # rules keep working.
                stop_action = Configlet('linux24', 'stop_action')
                stop_action.set_variable('opt_wait', opt_wait)
                stop_action.collapse_empty_strings(True)
                stop_action.set_variable('mgmt_access', mgmt_access)
                stop_action.set_variable(
                    'ssh_management_address',
                    mgmt_addr,
                )
                stop_action.set_variable('mgmt_tool', mgmt_tool)
                stop_action.set_variable('state_module_option', mgmt_state_option)
                stop_action.set_variable(
                    'coexistence_v4',
                    1 if (not flush_ruleset and have_ipv4) else 0,
                )
                stop_action.set_variable(
                    'coexistence_v6',
                    1 if (not flush_ruleset and have_ipv6) else 0,
                )
                script_skeleton.set_variable('stop_action', stop_action.expand())

                # Status action configlet — in coexistence mode checks
                # for FWF-specific chains instead of counting all chains
                # (Docker etc. always add their own chains).  Each family
                # is asked on its own, the way `stop_action` is: a
                # firewall may carry rules for only one of them, and the
                # other tool then answers about a table this script never
                # fills.
                status_action = Configlet('linux24', 'status_action')
                status_action.set_variable('opt_wait', opt_wait)
                status_action.collapse_empty_strings(True)
                status_action.set_variable(
                    'coexistence_v4',
                    1 if (not flush_ruleset and have_ipv4) else 0,
                )
                status_action.set_variable(
                    'coexistence_v6',
                    1 if (not flush_ruleset and have_ipv6) else 0,
                )
                status_action.set_variable(
                    'flush_v4',
                    1 if (flush_ruleset and have_ipv4) else 0,
                )
                status_action.set_variable(
                    'flush_v6',
                    1 if (flush_ruleset and have_ipv6) else 0,
                )
                status_action.set_variable('table_name', table_name)
                script_skeleton.set_variable('status_action', status_action.expand())

                # Top comment configlet
                top_comment = Configlet('linux24', 'top_comment')
                top_comment.set_variable('version', __compiler_version__)
                top_comment.set_variable('user', user_name)
                top_comment.set_variable('database', '')

                # Output file names
                cluster_name = cluster.name if cluster is not None else ''
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
                all_messages = self.all_errors + self.all_warnings
                script_skeleton.set_variable(
                    'errors_and_warnings', _prepend('# ', '\n'.join(all_messages))
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
        # Which chains a branch rule set ended up using decides where a
        # rule branching into it can jump.  Each rule set gets its own
        # compiler, so the answer has to be collected here and handed to
        # the next one, the way CompilerDriver_ipt_nat.cpp:93 and :122 do
        # it.  A branch rule set is compiled before the top one, so a
        # branch of the top rule set finds its entry.
        nat_compiler.branch_ruleset_to_chain_mapping = self._nat_branch_chains
        if not self._flush_ruleset:
            nat_compiler.chain_prefix = self._table_name

        if not self._is_top_ruleset(nat_rs):
            nat_compiler.register_rule_set_chain(branch_name)

        nat_compiler.set_source_ruleset(nat_rs)
        nat_compiler.source_ruleset = nat_rs

        if single_rule_id:
            nat_compiler.single_rule_compile_mode = True
            nat_compiler.single_rule_id = single_rule_id
        nat_compiler.verbose = self.verbose > 0
        # Whether a rule the address-family filter empties is still
        # compiled for the family it does name.
        nat_compiler.other_family_is_compiled = self._other_family_is_compiled(
            nat_rs, policy_af
        )
        nat_compiler.source_dir = self.source_dir
        nat_compiler.debug_rule = self.debug_rule_nat
        nat_compiler.rule_debug_on = self.debug_rule_nat >= 0

        nat_rules_count = nat_compiler.prolog()
        if nat_rules_count > 0:
            nat_compiler.compile()
            nat_compiler.epilog()

        self._nat_branch_chains[branch_name] = nat_compiler.get_used_chains()

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
                self.all_warnings.extend(nat_compiler.get_warnings())

            return False  # not empty

        if nat_compiler.get_errors() or nat_compiler.get_warnings():
            self.all_errors.extend(nat_compiler.get_errors())
            self.all_warnings.extend(nat_compiler.get_warnings())

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

        mangle_compiler.automatic_rules = self._automatic_rules
        mangle_compiler.hashlimit_tables = self._hashlimit_tables
        mangle_compiler.branch_chains = self._branch_chains
        mangle_compiler.branch_loop_edges = self._branch_loop_edges
        mangle_compiler.mangle_only_branch_chains = self._mangle_only_branch_chains
        mangle_compiler.mangle_branch_chains = self._mangle_branch_chains
        mangle_compiler.classifying_branch_chains = self._classifying_branch_chains

        if not self._flush_ruleset:
            mangle_compiler.chain_prefix = self._table_name

        if not self._is_top_ruleset(pol_rs):
            mangle_compiler.register_rule_set_chain(branch_name)

        mangle_compiler.set_source_ruleset(pol_rs)
        mangle_compiler.source_ruleset = pol_rs

        if single_rule_id:
            mangle_compiler.single_rule_compile_mode = True
            mangle_compiler.single_rule_id = single_rule_id
        mangle_compiler.verbose = self.verbose > 0
        # Whether a rule the address-family filter empties is still
        # compiled for the family it does name.
        mangle_compiler.other_family_is_compiled = self._other_family_is_compiled(
            pol_rs, policy_af
        )
        mangle_compiler.source_dir = self.source_dir

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
                self.all_warnings.extend(mangle_compiler.get_warnings())

        # --- Filter table compilation ---
        policy_compiler = PolicyCompiler_ipt(
            session, fw, ipv6_policy, oscnf, minus_n_commands_filter
        )

        policy_compiler.automatic_rules = self._automatic_rules
        policy_compiler.hashlimit_tables = self._hashlimit_tables
        policy_compiler.branch_chains = self._branch_chains
        policy_compiler.branch_loop_edges = self._branch_loop_edges
        policy_compiler.mangle_only_branch_chains = self._mangle_only_branch_chains
        policy_compiler.mangle_branch_chains = self._mangle_branch_chains
        policy_compiler.classifying_branch_chains = self._classifying_branch_chains

        if single_rule_id:
            policy_compiler.single_rule_compile_mode = True
            policy_compiler.single_rule_id = single_rule_id
        if not self._flush_ruleset:
            policy_compiler.chain_prefix = self._table_name
        policy_compiler.verbose = self.verbose > 0
        # Whether a rule the address-family filter empties is still
        # compiled for the family it does name.
        policy_compiler.other_family_is_compiled = self._other_family_is_compiled(
            pol_rs, policy_af
        )
        policy_compiler.source_dir = self.source_dir
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
                self.all_warnings.extend(policy_compiler.get_warnings())

        # Automatic rules for filter table (only for top rule set, once)
        auto_pos = automatic_rules_stream.tell()
        if self._is_top_ruleset(pol_rs) and auto_pos <= 0:
            auto_buf = io.StringIO()

            # The loop above has already collected what the compiler said,
            # so whatever the automatic rules report has to be picked up
            # afterwards or it is lost.
            seen_errors = len(policy_compiler.get_errors())
            seen_warnings = len(policy_compiler.get_warnings())

            auto_buf.write(policy_compiler.flush_and_set_default_policy())
            auto_buf.write(policy_compiler.print_automatic_rules())

            self.all_errors.extend(policy_compiler.get_errors()[seen_errors:])
            self.all_warnings.extend(policy_compiler.get_warnings()[seen_warnings:])

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
        use_iptables_restore = self.firewall_option(fw, 'use_iptables_restore')

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
        # `iptables-restore` empties every chain of a table and deletes
        # every user chain in it before it reads the first rule
        # (netfilter iptables/iptables-restore.c, the `noflush == 0`
        # branch).  On a firewall that shares the machine that is exactly
        # what must not happen: it takes the other tools' rules with it,
        # and the `fwf_*` chains `setup_fwf_jumps` has just created along
        # with them - so the very next line, an `-A fwf_INPUT`, answers
        # "No chain/target/match by that name" and the activation stops
        # with the built-in policies already at DROP.
        noflush = '' if self.firewall_option(fw, 'flush_ruleset') else ' --noflush'
        # Every `iptables` command of the generated script waits for the
        # xtables lock, and the restore has to as well or a firewall that
        # shares the machine loses the race against the tool it shares it
        # with: `iptables-restore` says "Another app is currently holding
        # the xtables lock" and the activation stops.  The option reached
        # the restore programs later than the command
        # (netfilter iptables/iptables-restore.c, v1.6.2), so it has a gate
        # of its own; `parse_wait_time` is the same parser the command
        # uses, which is why the value stands as its own argument.
        wait = ''
        if version_compare(get_iptables_version(fw), '1.6.2') >= 0:
            wait = f' {get_wait_option(get_iptables_version(fw))}'.rstrip()
        conf.set_variable('restore_command', f'$IPTABLES_RESTORE{wait}{noflush}')
        conf.set_variable('restore6_command', f'$IP6TABLES_RESTORE{wait}{noflush}')

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

    def _other_family_is_compiled(self, ruleset, policy_af: int) -> bool:
        """Whether *ruleset* is compiled for the other address family too.

        A rule the address-family filter empties leaves this pass either
        way; whether that is worth a word depends on whether the rule
        survives somewhere else.  Both halves have to be true: the driver
        has to run the other pass at all, and this rule set has to be
        compiled in it.
        """
        other_af = AF_INET if policy_af == AF_INET6 else AF_INET6
        other_runs = self.ipv6_run if other_af == AF_INET6 else self.ipv4_run
        return bool(other_runs) and self._matching_address_family(ruleset, other_af)

    def _matching_address_family(self, ruleset: RuleSet, policy_af: int) -> bool:
        """Check if a rule set matches the given address family."""
        if hasattr(ruleset, 'matching_address_family'):
            return ruleset.matching_address_family(policy_af)
        return True

    def info(self, msg: str) -> None:
        """Print informational message."""
        if self.verbose:
            print(msg)
