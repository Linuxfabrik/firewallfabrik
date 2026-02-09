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

# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.

# SPDX-License-Identifier: GPL-2.0-or-later

"""
SQLAlchemy 2.0 ORM models for libfwbuilder data structures.

Association tables replace the old FWReference / RuleElement class trees.
"""

# Import all submodules so every ORM class registers on the shared Base.metadata.
from ._addresses import (
    Address,
    AddressRange,
    IPv4,
    IPv6,
    MultiAddressRunTime,
    Network,
    NetworkIPv6,
    PhysAddress,
)
from ._base import (
    Base,
    enable_sqlite_fks,
)
from ._database import (
    FWObjectDatabase,
    Library,
)
from ._devices import (
    Cluster,
    Firewall,
    Host,
    Interface,
)
from ._groups import (
    AddressTable,
    AttachedNetworks,
    ClusterGroup,
    DNSName,
    DynamicGroup,
    FailoverClusterGroup,
    Group,
    IntervalGroup,
    MultiAddress,
    ObjectGroup,
    ServiceGroup,
    StateSyncClusterGroup,
    group_membership,
)
from ._rules import (
    NAT,
    NATRule,
    Policy,
    PolicyRule,
    Routing,
    RoutingRule,
    Rule,
    RuleSet,
    rule_elements,
)
from ._services import (
    CustomService,
    ICMP6Service,
    ICMPService,
    Interval,
    IPService,
    Service,
    TagService,
    TCPService,
    TCPUDPService,
    UDPService,
    UserService,
)
from ._types import (
    Direction,
    Inet6AddrMask,
    InetAddr,
    InetAddrMask,
    JSONEncodedSet,
    NATAction,
    NATRuleType,
    PolicyAction,
    RoutingRuleType,
    StandardId,
    TCPFlag,
)

__all__ = [
    'NAT',
    'Address',
    'AddressRange',
    'AddressTable',
    'AttachedNetworks',
    'Base',
    'Cluster',
    'ClusterGroup',
    'CustomService',
    'DNSName',
    'Direction',
    'DynamicGroup',
    'FWObjectDatabase',
    'FailoverClusterGroup',
    'Firewall',
    'Group',
    'Host',
    'ICMP6Service',
    'ICMPService',
    'IPService',
    'IPv4',
    'IPv6',
    'Inet6AddrMask',
    'InetAddr',
    'InetAddrMask',
    'Interface',
    'Interval',
    'IntervalGroup',
    'JSONEncodedSet',
    'Library',
    'MultiAddress',
    'MultiAddressRunTime',
    'NATAction',
    'NATRule',
    'NATRuleType',
    'Network',
    'NetworkIPv6',
    'ObjectGroup',
    'PhysAddress',
    'Policy',
    'PolicyAction',
    'PolicyRule',
    'Routing',
    'RoutingRule',
    'RoutingRuleType',
    'Rule',
    'RuleSet',
    'Service',
    'ServiceGroup',
    'StandardId',
    'StateSyncClusterGroup',
    'TCPFlag',
    'TCPService',
    'TCPUDPService',
    'TagService',
    'UDPService',
    'UserService',
    'enable_sqlite_fks',
    'group_membership',
    'rule_elements',
]
