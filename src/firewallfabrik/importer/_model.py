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

"""The neutral model both parsers produce and the builder reads.

An iptables-save file and an ``nft -j list ruleset`` listing say the same
things in different words.  Each parser translates its input into these
classes, and one builder turns them into FirewallFabrik objects, so the
two packet filters are mapped by the same code and end up alike.

The model holds what a rule *matches* and what it *does*, in the terms of
netfilter, not of FirewallFabrik: a chain is still a chain, a hook is
still a hook.  Whatever a parser understands but the model has no field
for goes into :attr:`Rule.unsupported`, with the reason, and the builder
imports the rule disabled.
"""

import dataclasses


@dataclasses.dataclass
class Address:
    """One address match: a host, a network or a range.

    *text* is what the builder puts into the object: ``192.0.2.1``,
    ``192.0.2.0/24``, ``192.0.2.1-192.0.2.9``, or the IPv6 counterparts.
    """

    family: int  # 4 or 6
    text: str


@dataclasses.dataclass
class PortRange:
    low: int
    high: int


@dataclasses.dataclass
class Service:
    """One protocol match and what it says about the protocol.

    A rule matches the union of its services, the way a FirewallFabrik
    rule matches the union of the objects in its service element.
    """

    protocol: str  # 'tcp', 'udp', 'icmp', 'icmpv6', or a protocol number
    src_ports: list[PortRange] = dataclasses.field(default_factory=list)
    dst_ports: list[PortRange] = dataclasses.field(default_factory=list)
    icmp_type: int | None = None
    icmp_code: int | None = None
    # TCP flags as two sets of names (fin, syn, rst, psh, ack, urg): the
    # flags inspected and the ones of them that have to be set.
    tcp_flags_mask: frozenset[str] = frozenset()
    tcp_flags_set: frozenset[str] = frozenset()


@dataclasses.dataclass
class Rule:
    """One rule of one chain, in the order of the chain."""

    raw: str  # the rule as the input wrote it, for comments and messages
    line: int = 0  # line number in the input, 0 where it has none
    family: int | None = None  # 4, 6, or None for both (an inet table)
    src: list[Address] = dataclasses.field(default_factory=list)
    src_negated: bool = False
    src_set: str = ''  # name of a set the source address is matched against
    dst: list[Address] = dataclasses.field(default_factory=list)
    dst_negated: bool = False
    dst_set: str = ''
    in_interface: str = ''
    in_interface_negated: bool = False
    out_interface: str = ''
    out_interface_negated: bool = False
    services: list[Service] = dataclasses.field(default_factory=list)
    services_negated: bool = False
    # Connection tracking states, lower case; None when the rule asks for
    # none, which is "every state".
    states: frozenset[str] | None = None
    user: str = ''  # the owner of a locally generated packet, uid or name
    limit_rate: int = 0
    limit_unit: str = ''  # 'second', 'minute', 'hour', 'day'
    limit_burst: int = 0
    limit_over: bool = False  # the rule matches above the rate, not up to it
    log: bool = False
    log_prefix: str = ''
    log_level: str = ''
    comment: str = ''
    # What the rule does: 'accept', 'drop', 'reject', 'return', 'jump',
    # 'continue' (no verdict), 'snat', 'dnat', 'masquerade', 'redirect',
    # 'log' (a rule whose only target is LOG).
    action: str = 'continue'
    jump_target: str = ''
    # A goto: the jump does not come back to this chain but to the one that
    # called it, or to the policy of a base chain.
    goto: bool = False
    reject_with: str = ''  # the icmp type name, or 'tcp-reset'
    nat_addresses: list[Address] = dataclasses.field(default_factory=list)
    nat_ports: PortRange | None = None
    unsupported: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Chain:
    name: str
    # The hook a base chain is attached to ('input', 'forward', 'output',
    # 'prerouting', 'postrouting'), or '' for a chain reached by a jump.
    hook: str = ''
    policy: str = ''  # 'accept' or 'drop' on a base chain
    rules: list[Rule] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Table:
    """One table: an iptables table of one address family, or an nft table.

    *kind* is what the table does - 'filter', 'nat', 'mangle', 'raw' - which
    for nftables comes from the type of its base chains rather than from
    its name.
    """

    name: str
    kind: str
    family: int | None  # 4, 6, or None for an inet table
    chains: dict[str, Chain] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class AddressSet:
    """A named nftables set of addresses."""

    name: str
    family: int
    addresses: list[Address] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Ruleset:
    """Everything one input said, and what the parser had to say about it."""

    source: str  # 'iptables' or 'nftables'
    tables: list[Table] = dataclasses.field(default_factory=list)
    sets: dict[str, AddressSet] = dataclasses.field(default_factory=dict)
    # Messages about the input as a whole, as (severity, text) with
    # severity 'error' or 'warning'.
    messages: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    version: str = ''  # the release that wrote the input, where it says


@dataclasses.dataclass
class NextHop:
    """Where a route sends a packet: a gateway, an interface, or both."""

    gateway: Address | None = None
    dev: str = ''
    weight: int = 1


@dataclasses.dataclass
class Route:
    """One route of the main routing table, as ``ip -j route`` lists it."""

    raw: str  # the route as the listing wrote it, for comments and messages
    family: int  # 4 or 6
    dst: Address | None = None  # None for the default route
    # One next hop, or several for an equal-cost multi path route.
    next_hops: list[NextHop] = dataclasses.field(default_factory=list)
    metric: int = 0  # 0 where the route names none
    unsupported: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Routes:
    """The routes one ``ip -j route`` listing holds, and what was left out."""

    routes: list[Route] = dataclasses.field(default_factory=list)
    messages: list[tuple[str, str]] = dataclasses.field(default_factory=list)
