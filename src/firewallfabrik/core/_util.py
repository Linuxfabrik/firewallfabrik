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

"""Shared code for the reader/writer modules.

Canonical type-to-class mappings, slot names, enum field definitions,
and the ParseResult dataclass used across XML reader, YAML reader,
and YAML writer.
"""

import dataclasses

from . import objects


@dataclasses.dataclass
class ParseResult:
    """Holds the parsed object graph and deferred association-table rows."""

    database: objects.FWObjectDatabase
    memberships: list[dict]
    rule_element_rows: list[dict]


ADDRESS_CLASSES = {
    'IPv4': objects.IPv4,
    'IPv6': objects.IPv6,
    'Network': objects.Network,
    'NetworkIPv6': objects.NetworkIPv6,
    'PhysAddress': objects.PhysAddress,
    'AddressRange': objects.AddressRange,
    'MultiAddressRunTime': objects.MultiAddressRunTime,
}

SERVICE_CLASSES = {
    'TCPService': objects.TCPService,
    'UDPService': objects.UDPService,
    'ICMPService': objects.ICMPService,
    'ICMP6Service': objects.ICMP6Service,
    'IPService': objects.IPService,
    'CustomService': objects.CustomService,
    'UserService': objects.UserService,
    'TagService': objects.TagService,
}

DEVICE_CLASSES = {
    'Host': objects.Host,
    'Firewall': objects.Firewall,
    'Cluster': objects.Cluster,
}

GROUP_CLASSES = {
    'ObjectGroup': objects.ObjectGroup,
    'ServiceGroup': objects.ServiceGroup,
    'IntervalGroup': objects.IntervalGroup,
    'ClusterGroup': objects.ClusterGroup,
    'FailoverClusterGroup': objects.FailoverClusterGroup,
    'StateSyncClusterGroup': objects.StateSyncClusterGroup,
    'DNSName': objects.DNSName,
    'AddressTable': objects.AddressTable,
    'AttachedNetworks': objects.AttachedNetworks,
    'DynamicGroup': objects.DynamicGroup,
    'MultiAddress': objects.MultiAddress,
}

RULESET_CLASSES = {
    'Policy': objects.Policy,
    'NAT': objects.NAT,
    'Routing': objects.Routing,
}

RULE_CLASSES = {
    'PolicyRule': objects.PolicyRule,
    'NATRule': objects.NATRule,
    'RoutingRule': objects.RoutingRule,
}

SLOT_NAMES = {
    'Src': 'src',
    'Dst': 'dst',
    'Srv': 'srv',
    'Itf': 'itf',
    'When': 'when',
    'OSrc': 'osrc',
    'ODst': 'odst',
    'OSrv': 'osrv',
    'TSrc': 'tsrc',
    'TDst': 'tdst',
    'TSrv': 'tsrv',
    'ItfInb': 'itf_inb',
    'ItfOutb': 'itf_outb',
    'RDst': 'rdst',
    'RGtw': 'rgtw',
    'RItf': 'ritf',
}

SLOT_VALUES = frozenset(SLOT_NAMES.values())

ENUM_FIELDS = {
    'policy_action': ('action', objects.PolicyAction),
    'policy_direction': ('direction', objects.Direction),
    'nat_action': ('action', objects.NATAction),
    'nat_rule_type': ('rule_type', objects.NATRuleType),
    'routing_rule_type': ('rule_type', objects.RoutingRuleType),
}
