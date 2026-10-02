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

"""Read the routes of ``ip -j route show table all`` and its IPv6 twin.

The generated script manages the main table and nothing else: on
activation it deletes every route of that table but the kernel's - and the
default route, when it installs none of its own - and adds its routing
rules (the ``routing_functions`` configlet).  So the routes worth importing
are the ones an administrator configured in that table, which the kernel
marks ``proto boot`` (``ip route add``, ifupdown) or ``proto static``
(NetworkManager, systemd-networkd).  A route the kernel made for an
address is put back by the kernel; one from DHCP, router advertisements or
a routing daemon belongs to that program, which an imported copy would
pin down; one of another table is none of the script's business.  Those
are reported instead.  A blackhole, unreachable or prohibit route stops
what it matches, which no routing rule can do and the script would undo;
the builder turns it into policy rules.

``print_route`` in iproute2's ``ip/iproute.c`` leaves out what is the
default: ``type`` for unicast, ``protocol`` for boot, ``table`` for main
and ``scope`` for universe.  Everything else it may print beyond the
destination, the gateway, the device and the metric is something a
FirewallFabrik routing rule cannot say.  Verified against iproute2 6.x on
Fedora 44 in a network namespace.
"""

import collections
import json

from firewallfabrik.importer._model import NextHop, Route, Routes
from firewallfabrik.importer._nftables import _address

# The routes an administrator configured (rtnetlink.h: RTPROT_BOOT is what
# "ip route add" sets, RTPROT_STATIC what NetworkManager and
# systemd-networkd set for a configured route).
_CONFIGURED = {'boot', 'static'}

# Keys of a route that are no part of what a routing rule says, and need
# not be: who made it, its scope, IPv6's router preference, and the cache
# information iproute2 adds.
_IGNORED = {'dst', 'gateway', 'dev', 'metric', 'protocol', 'scope', 'flags'}
_IGNORED_V6 = {'pref', 'expires', 'error', 'used', 'age', 'users', 'cache'}

# The route types that stop a packet instead of sending it on, which the
# kernel answers with nothing, "host unreachable" (IPv6: "no route") and
# "communication administratively prohibited" (fib_props in
# net/ipv4/fib_semantics.c, ip_error in net/ipv4/route.c,
# ip6_pkt_discard and ip6_pkt_prohibit in net/ipv6/route.c).
_BLOCKING = {'blackhole', 'unreachable', 'prohibit'}

# The metric the kernel gives an IPv6 route that names none
# (IP6_RT_PRIO_USER in include/net/ip6_route.h); writing it out would only
# say the same twice.
_IPV6_DEFAULT_METRIC = 1024


def parse_ip_route_json(text, family=None):
    """Parse the JSON of ``ip -4|-6 -j route show table all``.

    Without ``-4`` or ``-6``, ``table all`` lists both families, so the
    family is read off each route; given *family*, the routes of the other
    one are skipped.
    """
    result = Routes()
    text = text.strip()
    if not text:
        return result
    try:
        entries = json.loads(text)
    except ValueError as exc:
        result.messages.append(('error', f'The route listing is no JSON: {exc}'))
        return result
    left_out = collections.Counter()
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        entry_family = _family(entry) or family or 4
        if family is not None and entry_family != family:
            continue
        table = entry.get('table', 'main')
        protocol = entry.get('protocol', 'boot')
        kind = entry.get('type', 'unicast')
        if table == 'main' and kind == 'unicast':
            prefix = _address(entry.get('dst', 'default'))
            if prefix is not None:
                result.prefixes.append(prefix)
        if table == 'local' or protocol == 'kernel':
            continue  # the kernel's own, which it puts back by itself
        if table == 'main' and kind in _BLOCKING:
            # Whoever made it: the script deletes it either way.
            route = _route(entry, entry_family)
            route.kind = kind
            result.blocking.append(route)
            continue
        if table != 'main':
            left_out[entry_family, f'table {table}'] += 1
            continue
        if protocol not in _CONFIGURED:
            left_out[entry_family, f'proto {protocol}'] += 1
            continue
        if kind != 'unicast':
            left_out[entry_family, f'type {kind}'] += 1
            continue
        result.routes.append(_route(entry, entry_family))
    for (version, what), count in sorted(left_out.items()):
        if what.startswith('table '):
            # The script never touches another table.
            result.messages.append(
                (
                    'info',
                    f'IPv{version} routes not imported: {count} of {what}. The '
                    'firewall script manages the main table only and leaves '
                    'this one alone.',
                )
            )
            continue
        result.messages.append(
            (
                'warning',
                f'IPv{version} routes not imported: {count} of {what}. A '
                'firewall script with routing rules deletes every route of '
                'the main table it does not install, except those of the '
                'kernel and, while it installs none, the default route.',
            )
        )
    return result


def _family(entry):
    """The address family of a route, from its destination or gateway."""
    hops = entry.get('nexthops') or [entry]
    for value in (entry.get('dst'), *(hop.get('gateway') for hop in hops)):
        if value and value != 'default':
            return 6 if ':' in str(value) else 4
    return None


def _route(entry, family):
    raw = json.dumps(entry, separators=(',', ':'))
    route = Route(raw=raw, family=family)
    dst = entry.get('dst', 'default')
    if dst != 'default':
        route.dst = _address(dst)
        if route.dst is None:
            route.unsupported.append(f'destination {dst}')
    metric = int(entry.get('metric', 0) or 0)
    if family == 6 and metric == _IPV6_DEFAULT_METRIC:
        metric = 0
    route.metric = metric
    hops = entry.get('nexthops')
    if hops:
        for hop in hops:
            route.next_hops.append(_next_hop(hop, route, of_several=True))
    else:
        route.next_hops.append(_next_hop(entry, route))
    ignored = _IGNORED | (_IGNORED_V6 if family == 6 else set())
    for key in sorted(set(entry) - ignored - {'nexthops', 'type', 'table'}):
        route.unsupported.append(_describe(key, entry[key]))
    if entry.get('scope') not in (None, 'link', 'global', 'universe'):
        route.unsupported.append(f'scope {entry["scope"]}')
    route.unsupported.extend(f'flag {flag}' for flag in entry.get('flags') or [])
    return route


def _next_hop(entry, route, of_several=False):
    gateway = None
    if entry.get('gateway'):
        gateway = _address(entry['gateway'])
        if gateway is None:
            route.unsupported.append(f'gateway {entry["gateway"]}')
    weight = int(entry.get('weight', 1) or 1)
    if of_several:
        # A rule per next hop is one equal-cost leg each; a weight has no
        # place there, and a flag of the hop none either.
        if weight != 1:
            route.unsupported.append(f'weight {weight}')
        route.unsupported.extend(
            f'next hop flag {flag}' for flag in entry.get('flags') or []
        )
        for key in sorted(set(entry) - {'gateway', 'dev', 'weight', 'flags'}):
            route.unsupported.append(f'next hop {_describe(key, entry[key])}')
    return NextHop(gateway=gateway, dev=entry.get('dev', ''), weight=weight)


def _describe(key, value):
    if key == 'prefsrc':
        return f'source address {value}'
    if key == 'metrics':
        parts = []
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, dict):
                parts.extend(f'{k} {v}' for k, v in item.items())
        return ', '.join(parts) or 'route metrics'
    if isinstance(value, (str, int)):
        return f'{key} {value}'
    return key
