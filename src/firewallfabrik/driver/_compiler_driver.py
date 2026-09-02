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

import contextlib
import copy
import ipaddress
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core._options import option_is_true
from firewallfabrik.core.objects import (
    AddressRange,
    Cluster,
    Firewall,
    Interface,
    MultiAddressRunTime,
    NATAction,
    PhysAddress,
    PolicyAction,
    RuleSet,
    StateSyncClusterGroup,
    netmask_prefix_length,
)
from firewallfabrik.platforms._defaults import get_known_keys

if TYPE_CHECKING:
    from firewallfabrik.core._database import DatabaseManager


#: The failover and state sync protocols a Linux host speaks, from
#: Firewall Builder's own host OS resource file
#: (`res/os/linux24.xml`, `/FWBuilderResources/Target/protocols`).  A
#: `.fwb` written for another platform carries `carp` or `pfsync` here,
#: and neither has rules this compiler could generate.
FAILOVER_PROTOCOLS = frozenset({'heartbeat', 'none', 'openais', 'vrrp'})
STATE_SYNC_PROTOCOLS = frozenset({'conntrack'})


def _as_uuid(value):
    """Accept either a UUID or its string spelling."""
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _every_interface(fw):
    """Yield every interface of *fw*, sub-interfaces included.

    ``fw.interfaces`` is the top level alone.  Firewall Builder reads
    the same list with ``getByTypeDeep(Interface::TYPENAME)``
    (CompilerDriver.cpp:443), and it has to: a VLAN interface hangs
    under the interface it tags and carries an address of its own, and
    a bridge port hangs under the bridge.
    """
    pending = list(fw.interfaces)
    seen: set = set()
    while pending:
        iface = pending.pop()
        if iface.id in seen:
            continue
        seen.add(iface.id)
        yield iface
        pending.extend(iface.sub_interfaces)


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
        #: Output file per cluster member, keyed by the member's id: the
        #: `-O` command-line option (`CompilerDriver::configure`).
        self.member_file_names: dict[str, str] = {}
        self.prepend_cluster_name: bool = False
        self.source_dir: str = '.'
        #: Rule sets of other firewall objects pulled into this script by a
        #: Branch rule, filled by the platform driver before it compiles.
        self._imported_rule_sets: set = set()

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

    @contextlib.contextmanager
    def compile_session(self):
        """A session for one compile run, rolled back when it ends.

        Compiling a firewall reads the object tree and writes nothing to
        it - measured over the corpus, a run ends with nothing new, dirty
        or deleted.  Compiling a *cluster member* is the exception:
        Firewall Builder copies the cluster's interfaces and rule sets
        into the member before it starts (``populateClusterElements``),
        and it does that in the live object database.  The GUI compiles
        in the same process as the editor, so doing that here would leave
        the cluster's interfaces on the member firewall in the tree the
        user is looking at.

        Rolling back gives the compile the same freedom without the
        consequence.  ``DatabaseManager.session`` commits and pushes an
        undo state; this one does neither.
        """
        session = self.db.create_session()
        try:
            yield session
        finally:
            session.rollback()
            session.close()

    def get_firewall_and_cluster(self, session, cluster_id, fw_id):
        """Look up the firewall and, when one is named, its cluster.

        Ports ``CompilerDriver::getFirewallAndClusterObjects``.  Returns
        ``(cluster, firewall)``; either may be ``None``, and the caller
        reports what it could not find.
        """
        cluster = None
        if cluster_id:
            cluster = session.get(Cluster, _as_uuid(cluster_id))
        firewall = session.get(Firewall, _as_uuid(fw_id)) if fw_id else None
        return cluster, firewall

    def check_cluster(self, cluster: Cluster) -> str:
        """Say what is wrong with the cluster object, or ``''``.

        Ports ``CompilerDriver::checkCluster``: a cluster needs at least
        one interface, and no two of its interfaces may share a name or an
        address.  Both would produce a member script whose rules contradict
        each other, so the C++ aborts and so does the caller here.
        """
        if not cluster.interfaces:
            return f'{cluster.name}: the cluster has no interfaces'
        seen_names: set[str] = set()
        seen_addresses: dict[str, str] = {}
        for iface in cluster.interfaces:
            if iface.name in seen_names:
                return f'{cluster.name}: duplicate cluster interface {iface.name}'
            seen_names.add(iface.name)
            for addr in iface.addresses:
                text = addr.get_address() if hasattr(addr, 'get_address') else ''
                if not text:
                    continue
                if text in seen_addresses:
                    return (
                        f'{cluster.name}: cluster interfaces {seen_addresses[text]} '
                        f'and {iface.name} both carry the address {text}'
                    )
                seen_addresses[text] = iface.name
        return ''

    def validate_cluster_groups(self, cluster: Cluster) -> str:
        """Say what is wrong with the cluster's groups, or ``''``.

        Ports ``CompilerDriver::validateClusterGroups``.  The protocols a
        Linux host can speak come from the host OS resource file
        (`res/os/linux24.xml`): `vrrp`, `heartbeat`, `openais` and `none`
        for failover, `conntrack` for state sync.  A group naming anything
        else - a `.fwb` written for PF carries `carp` and `pfsync` - has
        no rules this compiler could generate, and an empty failover group
        names no member at all.
        """
        for group in cluster.child_groups:
            if not isinstance(group, StateSyncClusterGroup):
                continue
            protocol = group.get_protocol()
            if protocol not in STATE_SYNC_PROTOCOLS:
                return (
                    f'{cluster.name}: state sync group type "{protocol}" is not '
                    f'supported on Linux'
                )
        for iface in cluster.interfaces:
            group = iface.get_failover_group()
            if group is None:
                continue
            protocol = group.get_protocol()
            if protocol not in FAILOVER_PROTOCOLS:
                return (
                    f'{cluster.name}: failover group type "{protocol}" is not '
                    f'supported on Linux'
                )
            if not group.get_members():
                return (
                    f'{cluster.name}: the failover group of cluster interface '
                    f'"{iface.name}" is empty'
                )
        return ''

    def populate_cluster_elements(self, session, cluster: Cluster, fw: Firewall) -> str:
        """Give the member firewall what it inherits from its cluster.

        Ports ``CompilerDriver::populateClusterElements``
        (CompilerDriver.cpp:1013).  Three things move across:

        * the **state sync group**, whose interface names the link
          conntrackd replicates over.  The member's own interface in that
          group is remembered under ``state_sync_interface``, which is
          what the automatic conntrack rule is written against.
        * every **failover interface**: a copy of the cluster's interface
          is added to the member, marked ``cluster_interface`` and
          pointed at the member's own interface through ``base_device`` /
          ``base_interface_id``.  The copy is what carries the shared
          address, so a rule naming the cluster interface has an object of
          this firewall to resolve to, and the automatic failover rules
          have somewhere to hang.  A cluster interface with no failover
          group is copied only when it is the loopback.
        * the cluster's **rule sets**, see :meth:`merge_rule_sets`.

        Everything written here lives in the compile session and is rolled
        back afterwards, see :meth:`compile_session`.

        Returns a message when the cluster cannot be compiled, ``''``
        otherwise.
        """
        problem = self.check_cluster(cluster) or self.validate_cluster_groups(cluster)
        if problem:
            return problem

        fw.options = {**(fw.options or {}), 'cluster_member': True}
        # Which cluster this firewall belongs to, so that
        # `find_imported_rule_sets` can tell a branch into the cluster's own
        # rule sets - merged in below - from one into a third object's.  An
        # in-memory attribute: it describes this compile run, not the data
        # file (`fw->setInt("parent_cluster_id", ...)` in the C++, which
        # works on a database it throws away).
        fw.parent_cluster_id = cluster.id

        for group in cluster.child_groups:
            if not isinstance(group, StateSyncClusterGroup):
                continue
            for member_iface in group.get_members():
                if (
                    not isinstance(member_iface, Interface)
                    or member_iface.device_id != fw.id
                ):
                    continue
                master = group.get_master_interface_id()
                member_iface.options = {
                    **(member_iface.options or {}),
                    'state_sync_group_member': True,
                    'state_sync_group_id': str(group.id),
                    'state_sync_master': bool(master)
                    and str(master) == str(member_iface.id),
                }
                fw.options = {
                    **(fw.options or {}),
                    'state_sync_group_id': str(group.id),
                    'state_sync_interface': member_iface.name,
                }
                break

        for cluster_iface in list(cluster.interfaces):
            group = cluster_iface.get_failover_group()
            if group is None:
                if cluster_iface.is_loopback():
                    self._copy_cluster_interface(session, fw, cluster_iface, None)
                continue
            member_iface = group.get_interface_for_member(fw)
            if member_iface is None:
                continue
            member_iface.options = {
                **(member_iface.options or {}),
                'failover_group_id': str(group.id),
            }
            # fwbuilder #971: the *cluster's* interface inherits what
            # describes the member - dynamic, unnumbered, unprotected, the
            # security level - and it does so on the cluster object, not
            # only on the copy, because a rule of the cluster names the
            # cluster's interface.  Without it a cluster whose external
            # interface gets its address by DHCP has an interface that is
            # neither dynamic nor addressed, so every rule translating to
            # it is dropped as naming nothing: the whole NAT of
            # `heartbeat_cluster_1_d`, where the reference writes the
            # run-time `$i_eth0`.
            cluster_iface.data = {
                **(cluster_iface.data or {}),
                'dyn': member_iface.is_dynamic(),
                'unnum': member_iface.is_unnumbered(),
                'unprotected': member_iface.is_unprotected(),
                'security_level': (member_iface.data or {}).get('security_level', '0'),
            }
            self._copy_cluster_interface(session, fw, cluster_iface, member_iface)

        return ''

    def _copy_cluster_interface(self, session, fw, cluster_iface, member_iface):
        """Add a copy of *cluster_iface* to *fw*, and return it.

        Ports ``CompilerDriver::copyFailoverInterface``.  The copy is what
        makes a cluster interface answerable on the member: it carries the
        address the cluster shares, so a rule naming that address belongs
        in INPUT and OUTPUT and not in FORWARD, and a rule that translates
        to the cluster interface resolves to that one address rather than
        to the member's own.  It gets an id of its own - with the
        cluster's, the C++ says in the same place, the interface would not
        be a child of the firewall and every rule element naming it would
        be rejected.

        It shares its *name* with the member's own interface, and on Linux
        it has to: the failover protocol runs on the member's NIC and the
        generated rule says ``-i <that name>``.  Which is why
        ``Interface.cluster_interface`` exists and the unique index on
        (device, interface name) makes an exception for it.

        The copy inherits what describes the member rather than the
        cluster - dynamic, unnumbered, unprotected, dedicated failover
        (fwbuilder #971) - so the expansion and the chain decisions ask
        the right questions about it.
        """
        copy_iface = Interface(
            id=uuid.uuid4(),
            name=cluster_iface.name,
            comment=cluster_iface.comment,
            device=fw,
        )
        copy_iface.cluster_interface = True
        copy_iface.keywords = set(cluster_iface.keywords or set())
        copy_iface.data = copy.deepcopy(cluster_iface.data or {})
        copy_iface.options = copy.deepcopy(cluster_iface.options or {})
        copy_iface.bcast_bits = cluster_iface.bcast_bits
        copy_iface.snmp_type = cluster_iface.snmp_type
        copy_iface.options['cluster_interface'] = True

        group = cluster_iface.get_failover_group()
        if member_iface is not None:
            copy_iface.options['base_device'] = member_iface.name
            copy_iface.options['base_interface_id'] = str(member_iface.id)
            if group is not None:
                # The C++ copies the failover group itself along with the
                # interface; here the copy points back at the one under
                # the cluster, which is what the automatic rules read, and
                # carries the protocol, which decides whether the script
                # configures the shared address or leaves it to the daemon
                # (`interfaceProperties::manageIpAddresses`).
                copy_iface.options['failover_group_id'] = str(group.id)
                copy_iface.options['failover_protocol'] = group.get_protocol()
            master = group.get_master_interface_id() if group is not None else None
            copy_iface.options['failover_master'] = bool(master) and str(master) == str(
                member_iface.id
            )
            copy_iface.data['dyn'] = member_iface.is_dynamic()
            copy_iface.data['unnum'] = member_iface.is_unnumbered()
            copy_iface.data['unprotected'] = member_iface.is_unprotected()
            copy_iface.data['dedicated_failover'] = member_iface.is_dedicated_failover()
        session.add(copy_iface)

        for addr in cluster_iface.addresses:
            copy_addr = type(addr)(
                id=uuid.uuid4(),
                name=addr.name,
                comment=addr.comment,
            )
            copy_addr.keywords = set(addr.keywords or set())
            copy_addr.data = copy.deepcopy(addr.data or {})
            for column in (
                'inet_addr_mask',
                'start_address',
                'end_address',
                'subst_type_name',
                'source_name',
                'run_time',
            ):
                setattr(copy_addr, column, copy.deepcopy(getattr(addr, column)))
            copy_addr.interface = copy_iface
            session.add(copy_addr)

        return copy_iface

    def merge_rule_sets(
        self, cluster: Cluster, fw: Firewall, rule_sets, rule_set_class
    ):
        """Return *rule_sets* with the cluster's merged in.

        Ports ``CompilerDriver::mergeRuleSets`` (CompilerDriver.cpp:909),
        fwbuilder ticket #372.  A cluster's rule set is what its members
        have in common; a member may override one by giving a rule set of
        its own the same name.  So: the member's rule set wins when it has
        rules of its own, and is said out loud; an empty one of the same
        name is replaced by the cluster's; everything else is added.

        Called once per rule set kind - policy, NAT and routing - the way
        ``populateClusterElements`` calls it (CompilerDriver.cpp:1095).
        The routing one is easy to forget and the most expensive to lose:
        a member compiled without the cluster's routes installs the new
        packet filter and no route at all, and says nothing about it.

        The C++ copies the cluster's rule sets into the member object.
        Here the answer is a list, because that is what the caller
        compiles from - the rule set keeps its owner and the database is
        not touched.
        """
        merged = list(rule_sets)
        by_name = {rs.name: rs for rs in merged}
        candidates = sorted(
            (rs for rs in cluster.rule_sets if isinstance(rs, rule_set_class)),
            key=lambda rs: rs.name,
        )
        for rule_set in candidates:
            own = by_name.get(rule_set.name)
            if own is None:
                merged.append(rule_set)
                continue
            if own.rules:
                self.warning(
                    f'{fw.name}: ignoring cluster rule set "{rule_set.name}" '
                    f'because the member firewall has a rule set with the '
                    f'same name'
                )
                continue
            merged[merged.index(own)] = rule_set
        return merged

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

    def find_imported_rule_sets(self, session, fw, rule_sets, rule_set_class) -> list:
        """Return the rule sets of *other* objects this firewall branches into.

        A Branch rule may point at a rule set that belongs to another
        firewall or cluster.  Firewall Builder compiles that rule set into
        the script of the firewall that jumps to it
        (``CompilerDriver::findImportedRuleSets``, called for the policies
        and for the NAT rule sets before anything else happens), because
        otherwise the jump lands in a chain nothing ever fills: the packet
        returns, the rule does nothing and the activation reports success.

        Two kinds of target are deliberately *not* imported.  One that
        belongs to this firewall is compiled anyway, and one that belongs
        to the cluster this firewall is a member of has been merged into it
        already.  Everything else is followed recursively, because a branch
        may branch on; a rule set reached twice from one rule is a loop and
        is said out loud rather than followed again.

        The imported rule sets are compiled as ordinary chains whatever
        their own "top" flag says.  The C++ clears that flag on the object
        and the comment above it spells out why: a top rule set goes into
        the built-in chains, so there would be no chain for the jump to
        name.  Here the answer is per compile run instead of a write into
        the database, see ``_is_top_ruleset``.
        """
        own = {rs.id for rs in rule_sets}
        cluster_id = getattr(fw, 'parent_cluster_id', None)

        imported: list = []
        seen: set = set()

        def follow(rule_set, reached: dict) -> None:
            count = reached.get(rule_set.id, 0) + 1
            reached[rule_set.id] = count
            if count > 1:
                return
            # Several rules of one rule set may branch to the same target;
            # that is not a loop, so it is followed once
            # (`local_branch_ruleset_counters` in the C++).
            followed: set = set()
            for rule in rule_set.rules:
                target = self._branch_target(session, rule)
                if target is None or target.id in followed:
                    continue
                followed.add(target.id)
                follow(target, reached)

        for rule_set in rule_sets:
            for rule in rule_set.rules:
                target = self._branch_target(session, rule)
                if target is None:
                    continue
                reached: dict = {}
                follow(target, reached)
                for target_id, count in reached.items():
                    candidate = session.get(RuleSet, target_id)
                    if candidate is None:
                        continue
                    if count > 1:
                        self.warning(
                            f'{fw.name}: rule {rule.position} of rule set '
                            f'"{rule_set.name}" branches to rule set '
                            f'"{candidate.name}", which branches back to it, '
                            f'creating a loop'
                        )
                    if target_id in own or target_id in seen:
                        continue
                    # A rule set of the cluster this firewall belongs to is
                    # already part of what is compiled.
                    if cluster_id and candidate.device_id == cluster_id:
                        continue
                    # The policies and the NAT rule sets are collected in
                    # two passes and a branch never crosses between them.
                    if not isinstance(candidate, rule_set_class):
                        continue
                    seen.add(target_id)
                    imported.append(candidate)

        return imported

    def _is_top_ruleset(self, ruleset) -> bool:
        """Whether *ruleset* fills the built-in chains of this script.

        A rule set imported from another firewall object is never the top
        one *here*, whatever it says about itself: the top rule set is
        compiled into the built-in chains, and then there would be no
        chain for a branching rule to jump to.  fwbuilder clears the flag
        on the object for the same reason
        (``CompilerDriver::findImportedRuleSets``); answering it per
        compile run keeps the firewall the rule set belongs to unchanged.
        """
        if ruleset.id in self._imported_rule_sets:
            return False
        return bool(ruleset.top)

    def find_branch_loop_edges(self, session, rule_sets) -> set[tuple[str, str]]:
        """Return the branch jumps that close a cycle, by rule set name.

        A chain that can reach itself through a jump is refused by the
        kernel, not by the tool: ``nft_chain_validate`` walks every jump
        from a base chain and answers ``-EMLINK`` once it has descended
        ``NFT_JUMP_STACK_SIZE`` levels (netfilter
        ``net/netfilter/nf_tables_api.c``), which both tools report as "Too
        many links".  ``nft --check`` never sees it, because it parses and
        evaluates without loading.

        What that costs differs by tool and is bad on both.  nftables
        loads a ruleset atomically, so the *whole* policy is refused and
        the firewall keeps the rules it had.  iptables installs command by
        command, so the jump into the looping chain fails from every
        built-in chain and everything else installs: the branch is
        silently absent from a script that otherwise activates.

        Only the jump that closes the cycle is named here, not every jump
        on it.  A depth-first walk starting at the top rule sets marks the
        edges pointing back at a rule set that is still on the stack, so
        breaking them leaves the rest of the branch tree reachable.  A
        target that is the top rule set is not followed at all: it is
        compiled into the built-in chains, so the chain the jump names
        stays empty and there is no cycle - the compilers report that case
        on its own.
        """
        by_state: dict = {}
        edges: set[tuple[str, str]] = set()
        # A branch rule may name its target by name alone, and a name means
        # a rule set of the same kind belonging to this firewall - which is
        # the set handed in here.
        by_name = {
            (type(rule_set).__name__, rule_set.name): rule_set
            for rule_set in reversed(rule_sets)
        }

        def visit(rule_set) -> None:
            by_state[rule_set.id] = False  # on the stack
            for rule in rule_set.rules:
                target = self._branch_target(session, rule, by_name)
                if target is None or self._is_top_ruleset(target):
                    continue
                state = by_state.get(target.id)
                if state is False:
                    edges.add((rule_set.name, target.name))
                elif state is None:
                    visit(target)
            by_state[rule_set.id] = True  # done

        ordered = [rs for rs in rule_sets if self._is_top_ruleset(rs)]
        ordered += [rs for rs in rule_sets if not self._is_top_ruleset(rs)]
        for rule_set in ordered:
            if rule_set.id not in by_state:
                visit(rule_set)
        return edges

    def order_branch_rule_sets(self, session, rule_sets, loop_edges=()):
        """Return *rule_sets* with every branch target before its branch.

        A NAT branch rule set becomes chains of its own, one per direction,
        because prerouting and postrouting are separate hooks - and the
        rule that jumps into it can only name the chains that rule set
        really filled.  The driver knows that once it has compiled the rule
        set, and hands it on as ``branch_ruleset_to_chain_mapping``, so a
        rule set compiled *before* the one it branches into reads an entry
        that is not there yet.

        What that costs differs by platform and is a hole on both.
        iptables does what Firewall Builder does with no answer at all
        (``NATCompiler_ipt::splitNATBranchRule``): it puts a copy in
        PREROUTING and one in POSTROUTING and says so, and the copy in the
        wrong chain carries a translation that chain cannot perform.
        nftables has no such fallback and leaves the rule out, so the
        translation is silently missing - and its rule set then installs
        nothing, which takes the rule branching into *it* with it.
        Compiling the targets first is what makes the map complete before
        it is read, and the answer exact on both.

        A jump that closes a cycle is left out by the compilers, so it is
        left out of the order as well - *loop_edges* is what
        `find_branch_loop_edges` answered.  A cycle it did not name is
        stopped by the visited set: the order is then arbitrary for that
        one edge, which is the state the pass was in for every edge.
        """
        members = {rule_set.id for rule_set in rule_sets}
        by_name = {
            (type(rule_set).__name__, rule_set.name): rule_set
            for rule_set in reversed(rule_sets)
        }
        ordered: list = []
        seen: set = set()

        def visit(rule_set) -> None:
            if rule_set.id in seen:
                return
            seen.add(rule_set.id)
            for rule in rule_set.rules:
                target = self._branch_target(session, rule, by_name)
                if target is None or target.id not in members:
                    continue
                if (rule_set.name, target.name) in loop_edges:
                    continue
                visit(target)
            ordered.append(rule_set)

        for rule_set in rule_sets:
            visit(rule_set)
        return ordered

    @staticmethod
    def _branch_target(session, rule, by_name=None):
        """Return the rule set a Branch rule points at, or ``None``.

        The action decides first: ``PolicyRule::getBranch`` and
        ``NATRule::getBranch`` (Rule.cpp:488 and :920) answer ``nullptr``
        for anything that is not a Branch rule, whatever the options say.
        An editor leaves a `branch_id` behind when the action is changed,
        and three firewalls of the reference corpus carry one on an
        ordinary Accept - following it would compile a rule set the
        firewall does not use.

        The id is the reference where there is one, and the name is the
        fallback, exactly the order both ``getBranch`` overloads read them
        in.  The name is looked up among the firewall's own rule sets of
        the same kind (``fw->findObjectByName(Policy::TYPENAME, ...)`` /
        ``NAT::TYPENAME``), which *by_name* holds.  Only the `.fwb` reader
        resolves an id, so without the fallback every branch rule of a
        `.fwf` - fwf's own format, and what the editor writes - answers
        "no target" and the walk above sees no jump at all.
        """
        if not (
            rule.policy_action == PolicyAction.Branch
            or rule.nat_action == NATAction.Branch
        ):
            return None
        options = getattr(rule, 'options', None) or {}
        ref = options.get('branch_id')
        if ref:
            try:
                target_id = uuid.UUID(str(ref))
            except (TypeError, ValueError):
                return None
            return session.get(RuleSet, target_id)
        name = options.get('branch_name')
        if not name or by_name is None:
            return None
        kind = 'NAT' if rule.nat_action == NATAction.Branch else 'Policy'
        return by_name.get((kind, str(name)))

    def collect_os_configurator_messages(self, oscnf) -> None:
        """Take over what the OS configurator has to say about the firewall.

        It is a ``BaseCompiler`` like the policy and NAT compilers and it
        reports the same way, but nothing collected from it - so "Can not
        add virtual address 192.0.2.1: no interface of the firewall is on
        that network" was raised and dropped, and the administrator was
        left with a NAT rule translating to an address the firewall never
        answers ARP for.

        The same sentence comes back more than once, because the
        configurator is asked once per address family and again while the
        script is assembled, so it is only taken over when it is new.  The
        two lists a driver keeps are short and read in full by everybody
        who reads the report.
        """
        if oscnf is None:
            return
        for msg in oscnf.get_errors():
            if msg not in self.all_errors:
                self.all_errors.append(msg)
        for msg in oscnf.get_warnings():
            if msg not in self.all_warnings:
                self.all_warnings.append(msg)

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

        Sub-interfaces are checked too, the way ``commonChecks2`` reads
        them (``fw->getByTypeDeep(Interface::TYPENAME)``): a VLAN
        interface carries the address of its tag, and a netmask of /0 on
        it makes every rule naming it match every address - which is the
        failure this check exists to stop, one level down.

        Returns a human-readable error string, or an empty string on
        success.
        """
        for iface in _every_interface(fw):
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
            'use_ULOG',
            'ULOG is deprecated and has been removed from modern Linux kernels; falling back to LOG',
        ),
    ]

    # The interface kinds Firewall Builder creates and this compiler does
    # not (#95), by the `type` its editor and Firewall Builder both store
    # (`res/os/linux24.xml`, and `iface_opts_dialog.py`).
    _UNCREATABLE_INTERFACE_TYPES: ClassVar[list[tuple[str, str]]] = [
        (
            'bonding',
            'the generated script does not create or remove bonding interfaces; '
            'they have to exist on the firewall before it runs',
        ),
        (
            '8021q',
            'the generated script does not create or remove VLAN interfaces; '
            'they have to exist on the firewall before it runs',
        ),
    ]

    def _warn_unsupported_options(self, options: dict, fw=None) -> None:
        """Emit warnings for recognised but unimplemented firewall options."""
        for opt, msg in self._UNSUPPORTED_BOOL_OPTIONS:
            if option_is_true(options.get(opt, False)):
                self.warning(msg)
        if fw is not None:
            self._warn_uncreatable_interfaces(fw)
            if option_is_true(options.get('configure_bridge_interfaces', False)):
                self._report_nested_bridges(fw)
            self._warn_misspelled_options(options, fw)

    def _report_nested_bridges(self, fw) -> None:
        """Report a bridge that hangs under another interface.

        The bridge block collects its bridges from the firewall's
        top-level interfaces, the way
        ``printBridgeInterfaceConfigurationCommands`` does, so a bridge
        that is a sub-interface of something is never built: no
        ``sync_bridge_interfaces``, no ``update_bridge``, and none of its
        own ports enslaved - and until now not a word either.
        ``OSConfigurator_linux24::validateInterfaces`` calls the same
        configuration unsupported and aborts on it, so this says so too.
        """

        def walk(iface, depth: int) -> None:
            if depth and iface.get_option('type', '') == 'bridge':
                self.error(
                    f'Interface "{iface.name}" is a bridge below the interface '
                    f'"{iface.parent_interface.name}". A bridge has to be an '
                    'interface of the firewall itself; below another one it is '
                    'not configured at all'
                )
            for child in iface.sub_interfaces:
                walk(child, depth + 1)

        for iface in fw.interfaces:
            walk(iface, 0)

    def _warn_uncreatable_interfaces(self, fw) -> None:
        """Warn about an interface the script names and cannot create.

        The question is what the firewall *has*, not what its options
        say.  Firewall Builder creates a bonding or VLAN interface when
        `configure_bonding_interfaces` / `configure_vlan_interfaces` is
        set, so there the option is the whole answer; this compiler
        creates neither, either way.  What it does do is name the
        interface in `verify_interfaces` and in
        `update_addresses_of_interface`, and the first of those ends the
        activation with `exit 1` on a machine where nothing has created
        it - before a single rule is installed.  Keying the warning on
        the option left three firewalls of the reference corpus silent
        about exactly that.
        """
        present = set()

        def walk(iface) -> None:
            present.add(str(iface.get_option('type', '') or ''))
            for child in iface.sub_interfaces:
                walk(child)

        for iface in fw.interfaces:
            walk(iface)

        for iface_type, msg in self._UNCREATABLE_INTERFACE_TYPES:
            if iface_type in present:
                self.warning(msg)

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
        # Compiling a cluster, the caller may name the file of each member
        # (`-O <member id>,<file name>,...`, which is what the Firewall
        # Builder GUI passes instead of `-o`); that answer takes the place
        # of the `-o` one for this member.
        option_name = str(fw.get_option('output_file') or '').strip()
        member_name = self.member_file_names.get(str(fw.id), '')
        if member_name:
            file_name = member_name
        elif self.file_name_setting:
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
