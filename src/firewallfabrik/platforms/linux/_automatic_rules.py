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

"""The rules a cluster member needs to see the other members.

A firewall that drops by default drops its own cluster traffic too, and
then both members consider themselves master and conntrackd replicates
nothing.  Firewall Builder therefore generates a handful of rules for
every cluster member before the policy is compiled
(``AutomaticRules_ipt::addConntrackRule`` and ``addFailoverRules``,
called from ``CompilerDriver_ipt::run``): the failover protocol on every
interface that has a failover group, and the state sync protocol on the
interface the state sync group names.

The rules go in front of the policy with negative positions, which is what
keeps them from being shadowed by a rule the administrator wrote and out
of the position numbering of the rules the editor shows
(``AutomaticRules::addMgmtRule``, fwbuilder ticket #16).

The defaults come from Firewall Builder's host OS resource file
(``res/os/linux24.xml``) and agree with the tools they are written for:
conntrackd's own sample configuration names 225.0.0.50 and group 3780 and
prints the very iptables rules this generates
(``conntrack-tools/doc/sync/*/conntrackd.conf``), heartbeat uses UDP 694
and OpenAIS UDP 5405.
"""

from __future__ import annotations

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import (
    Direction,
    Firewall,
    Interface,
    IPService,
    IPv4,
    PolicyAction,
    UDPService,
)

#: What each protocol sends to, and where, when the group says nothing.
#: `res/os/linux24.xml`, `/FWBuilderResources/Target/protocols`.
CONNTRACK_DEFAULT_ADDRESS = '225.0.0.50'
CONNTRACK_DEFAULT_PORT = 3780
HEARTBEAT_DEFAULT_ADDRESS = '224.0.10.100'
HEARTBEAT_DEFAULT_PORT = 694
OPENAIS_DEFAULT_ADDRESS = '226.94.1.1'
OPENAIS_DEFAULT_PORT = 5405
VRRP_ADDRESS = '224.0.0.18'
#: VRRP is IP protocol 112; RFC 2338 section 5.3.6.3 lets it run over
#: IPsec AH, which is protocol 51, and the failover group has a checkbox
#: for it.
VRRP_PROTOCOL = 112
AH_PROTOCOL = 51


def _address(name: str, address: str) -> IPv4:
    """A host address object that exists for this compile run only.

    Not added to the session: the rules hold the object itself, nothing
    ever looks it up by id, and the object tree the editor shows must not
    grow a "VRRP-Address" every time a cluster is compiled.
    """
    obj = IPv4(id=uuid.uuid4(), name=name)
    obj.data = {}
    obj.inet_addr_mask = {'address': address, 'netmask': '255.255.255.255'}
    return obj


def _udp_service(name: str, port: int) -> UDPService:
    """A UDP service matching one destination port, transient like above."""
    obj = UDPService(id=uuid.uuid4(), name=name)
    obj.data = {}
    obj.dst_range_start = port
    obj.dst_range_end = port
    return obj


def _ip_service(name: str, protocol: int) -> IPService:
    """An IP service matching one protocol number, transient like above."""
    obj = IPService(id=uuid.uuid4(), name=name)
    obj.data = {}
    obj.named_protocols = {'protocol_num': protocol}
    return obj


class AutomaticRules:
    """Builds the cluster rules of one member firewall.

    Ports ``AutomaticRules`` / ``AutomaticRules_ipt``.  The result is a
    list of :class:`CompRule` in the order the C++ produces them, which
    the policy compiler puts in front of the top rule set.  Nothing here
    is platform-specific: they are ordinary policy rules and both
    compilers turn them into their own syntax.
    """

    def __init__(self, fw: Firewall, session=None) -> None:
        self.fw = fw
        self.session = session
        self._rules: list[CompRule] = []

    def build(self) -> list[CompRule]:
        """Return the rules, in ascending position order (-n .. -1)."""
        self._rules = []
        self._add_conntrack_rules()
        self._add_failover_rules()
        # `insertRuleAtTop` puts each new rule above the previous one, so
        # the one created first ends up last and the whole block reads
        # -n .. -1 in the generated script.
        return list(reversed(self._rules))

    # -- rule construction ------------------------------------------------

    def _add_mgmt_rule(
        self,
        src,
        dst,
        service,
        iface,
        direction: Direction,
        label: str,
        *,
        related: bool = False,
    ) -> CompRule:
        """One rule, worded the way ``AutomaticRules_ipt::addMgmtRule`` does.

        Stateless unless the traffic is a connection the firewall itself
        starts, and always "the firewall is part of any and networks",
        because the rule is about the box and not about what it forwards.
        """
        position = -(len(self._rules) + 1)
        options = {'firewall_is_part_of_any_and_networks': True}
        if related:
            options['stateless'] = False
            options['accept_established'] = True
        else:
            options['stateless'] = True

        rule = CompRule(
            id=uuid.uuid4(),
            type='PolicyRule',
            position=position,
            label=f'{position} {label} (automatic)',
            comment='',
            options=options,
            negations={},
            src=[src] if src is not None else [],
            dst=[dst] if dst is not None else [],
            srv=[service] if service is not None else [],
            itf=[iface] if iface is not None else [],
            action=PolicyAction.Accept,
            direction=direction,
            hidden=True,
        )
        self._rules.append(rule)
        return rule

    # -- state sync -------------------------------------------------------

    def _compile_run_option(self, key: str) -> str:
        """A value the driver wrote onto the firewall for this run alone.

        `state_sync_group_id` and `state_sync_interface` are not settings
        an administrator makes and are in no `defaults.yaml`: the driver
        derives them from the cluster's state sync group while it prepares
        the member (`CompilerDriver::processStateSyncGroups`, which writes
        them into the firewall's options the same way).  They are
        therefore read off the options dict rather than through
        `get_option`, which exists to raise on a key the schema does not
        know.
        """
        return str((self.fw.options or {}).get(key) or '')

    def _state_sync_group(self):
        group_id = self._compile_run_option('state_sync_group_id')
        if not group_id or self.session is None:
            return None
        from firewallfabrik.core.objects import StateSyncClusterGroup

        try:
            return self.session.get(StateSyncClusterGroup, uuid.UUID(group_id))
        except (TypeError, ValueError):
            return None

    def _add_conntrack_rules(self) -> None:
        """Permit the state sync protocol on the link it runs over."""
        iface_name = self._compile_run_option('state_sync_interface')
        if not iface_name:
            return
        iface = next(
            (i for i in self.fw.interfaces if i.name == iface_name),
            None,
        )
        if iface is None:
            return

        group = self._state_sync_group()
        options = (group.options if group is not None else {}) or {}
        address = str(options.get('conntrack_address') or '') or (
            CONNTRACK_DEFAULT_ADDRESS
        )
        port = int(options.get('conntrack_port') or CONNTRACK_DEFAULT_PORT)
        service = _udp_service('CONNTRACK-UDP', port)

        if options.get('conntrack_unicast'):
            # No multicast group to name, so the rule names the other
            # members' interfaces directly.
            for other in _other_member_interfaces(group, self.fw):
                self._add_mgmt_rule(
                    other, self.fw, service, iface, Direction.Inbound, 'CONNTRACK'
                )
                self._add_mgmt_rule(
                    self.fw, other, service, iface, Direction.Outbound, 'CONNTRACK'
                )
            return

        destination = _address('CONNTRACK-Address', address)
        self._add_mgmt_rule(
            None, destination, service, iface, Direction.Inbound, 'CONNTRACK'
        )
        self._add_mgmt_rule(
            self.fw, destination, service, iface, Direction.Outbound, 'CONNTRACK'
        )

    # -- failover ---------------------------------------------------------

    def _add_failover_rules(self) -> None:
        """Permit the failover protocol on every interface that speaks it."""
        for iface in sorted(self.fw.interfaces, key=lambda i: i.name):
            if not iface.cluster_interface:
                continue
            group = _failover_group_of(iface, self.session)
            if group is None:
                continue
            member_iface = _base_interface(self.fw, iface)
            if member_iface is None:
                continue
            protocol = group.get_protocol()
            if protocol == 'vrrp':
                self._add_vrrp_rules(iface, member_iface, group)
            elif protocol == 'heartbeat':
                self._add_heartbeat_rules(iface, member_iface, group)
            elif protocol == 'openais':
                self._add_openais_rules(iface, member_iface, group)

    def _add_vrrp_rules(self, iface, member_iface, group) -> None:
        options = group.options or {}
        over_ah = bool(options.get('vrrp_over_ipsec_ah'))
        service = (
            _ip_service('IPSEC-AH', AH_PROTOCOL)
            if over_ah
            else _ip_service('VRRP service', VRRP_PROTOCOL)
        )
        label = 'VRRP (with IPSEC-AH)' if over_ah else 'VRRP'
        destination = _address('VRRP-Address', VRRP_ADDRESS)

        for other in _other_member_interfaces(group, self.fw, member_iface):
            self._add_mgmt_rule(
                other, destination, service, iface, Direction.Inbound, label
            )
        # One outbound rule for the interface, not one per other member:
        # it does not name the other side, so a cluster of three would
        # otherwise get the same rule twice.
        self._add_mgmt_rule(
            self.fw, destination, service, iface, Direction.Outbound, label
        )

    def _add_heartbeat_rules(self, iface, member_iface, group) -> None:
        options = group.options or {}
        address = str(options.get('heartbeat_address') or '') or (
            HEARTBEAT_DEFAULT_ADDRESS
        )
        port = int(options.get('heartbeat_port') or HEARTBEAT_DEFAULT_PORT)
        service = _udp_service('HEARTBEAT-UDP', port)
        destination = _address('HEARTBEAT-Address', address)
        unicast = bool(options.get('heartbeat_unicast'))

        # The C++ scopes these to the member's own interface rather than to
        # the copy of the cluster interface the VRRP rules use.
        for other in _other_member_interfaces(group, self.fw, member_iface):
            if unicast:
                self._add_mgmt_rule(
                    other,
                    self.fw,
                    service,
                    member_iface,
                    Direction.Inbound,
                    'heartbeat',
                )
                self._add_mgmt_rule(
                    self.fw,
                    other,
                    service,
                    member_iface,
                    Direction.Outbound,
                    'heartbeat',
                )
            else:
                self._add_mgmt_rule(
                    other,
                    destination,
                    service,
                    member_iface,
                    Direction.Inbound,
                    'heartbeat',
                )
                self._add_mgmt_rule(
                    self.fw,
                    destination,
                    service,
                    member_iface,
                    Direction.Outbound,
                    'heartbeat',
                )

    def _add_openais_rules(self, iface, member_iface, group) -> None:
        options = group.options or {}
        address = str(options.get('openais_address') or '') or OPENAIS_DEFAULT_ADDRESS
        port = int(options.get('openais_port') or OPENAIS_DEFAULT_PORT)
        service = _udp_service('OPENAIS-UDP', port)
        destination = _address('OPENAIS-Address', address)

        for other in _other_member_interfaces(group, self.fw, member_iface):
            self._add_mgmt_rule(
                other, destination, service, iface, Direction.Inbound, 'openais'
            )
            self._add_mgmt_rule(
                self.fw, destination, service, iface, Direction.Outbound, 'openais'
            )


def _failover_group_of(iface, session):
    """The failover group the copy of a cluster interface belongs to.

    The copy carries the group's id rather than the group itself: it is a
    copy of the cluster's interface made for this compile run, and the
    group stays where it is, under the cluster.
    """
    group_id = iface.get_option('failover_group_id', '')
    if not group_id or session is None:
        # The member interface carries the id; the copy carries the
        # cluster interface it was made from.
        return None
    from firewallfabrik.core.objects import FailoverClusterGroup

    try:
        return session.get(FailoverClusterGroup, uuid.UUID(str(group_id)))
    except (TypeError, ValueError):
        return None


def _base_interface(fw, copy_iface):
    """The member's own interface the copy stands for."""
    base = copy_iface.get_option('base_device', '')
    if not base:
        return None
    return next(
        (i for i in fw.interfaces if i.name == base and not i.cluster_interface),
        None,
    )


def _other_member_interfaces(group, fw, own_iface=None) -> list:
    """The interfaces of the *other* members in *group*.

    A dynamic one is left out of the rule entirely rather than written
    into it: it belongs to another machine, so its address is not
    something this script can look up, and "no source" is what the C++
    passes in that case.
    """
    if group is None:
        return []
    others = []
    for member in group.get_members():
        if not isinstance(member, Interface):
            continue
        if own_iface is not None and member.id == own_iface.id:
            continue
        if member.device_id == fw.id:
            continue
        others.append(None if member.is_dynamic() else member)
    return others
