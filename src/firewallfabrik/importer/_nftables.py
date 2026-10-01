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

"""Read the output of ``nft -j list ruleset``.

The JSON listing needs no grammar of its own: tables, chains, sets and
rules arrive as objects, and a rule is a list of statements - matches,
then counters, logs and limits, then the verdict - in the order nft
evaluates them (``doc/libnftables-json.adoc``; the writer is
``src/json.c``).  Schema version 1 is the only one there is
(``JSON_SCHEMA_VERSION`` in ``include/json.h``), and the listing carries
it since nftables 0.9.1.

A table written by iptables-nft keeps every match it has no native
expression for as an ``xt`` object without its parameters (``xt_json``
in ``src/json.c``), so such a rule cannot be read back from here; the
parser says so and points at iptables-save, which can.

The forms below were measured with nftables 1.1.6: a port as a number, a
prefix as ``{"prefix": {"addr", "len"}}``, an anonymous set inline as
``{"set": [...]}``, a named one as ``"@name"``, and ``ct state`` compared
with ``in``.
"""

import ipaddress
import json
import socket

from firewallfabrik.importer._model import (
    Address,
    AddressSet,
    Chain,
    PortRange,
    Rule,
    Ruleset,
    Service,
    Table,
)

SUPPORTED_SCHEMA_VERSION = 1

# NF_IP_PRI_MANGLE, the priority nft calls "mangle"
# (include/uapi/linux/netfilter_ipv4.h).
_MANGLE_PRIORITY = -150

# The type names nft prints (src/proto.c, icmp_type_tbl and
# icmp6_type_tbl) and the numbers they stand for.
_ICMP_TYPES = {
    'echo-reply': 0,
    'destination-unreachable': 3,
    'source-quench': 4,
    'redirect': 5,
    'echo-request': 8,
    'router-advertisement': 9,
    'router-solicitation': 10,
    'time-exceeded': 11,
    'parameter-problem': 12,
    'timestamp-request': 13,
    'timestamp-reply': 14,
    'info-request': 15,
    'info-reply': 16,
    'address-mask-request': 17,
    'address-mask-reply': 18,
}
_ICMP6_TYPES = {
    'destination-unreachable': 1,
    'packet-too-big': 2,
    'time-exceeded': 3,
    'parameter-problem': 4,
    'echo-request': 128,
    'echo-reply': 129,
    'mld-listener-query': 130,
    'mld-listener-report': 131,
    'mld-listener-done': 132,
    'mld-listener-reduction': 132,
    'nd-router-solicit': 133,
    'nd-router-advert': 134,
    'nd-neighbor-solicit': 135,
    'nd-neighbor-advert': 136,
    'nd-redirect': 137,
    'router-renumbering': 138,
    'ind-neighbor-solicit': 141,
    'ind-neighbor-advert': 142,
    'mld2-listener-report': 143,
}

_FAMILIES = {'ip': 4, 'ip6': 6, 'inet': None}

_ADDRESS_FIELDS = {
    ('ip', 'saddr'): ('src', 4),
    ('ip', 'daddr'): ('dst', 4),
    ('ip6', 'saddr'): ('src', 6),
    ('ip6', 'daddr'): ('dst', 6),
}

_SET_FAMILIES = {'ipv4_addr': 4, 'ipv6_addr': 6}


def parse_nft_json(text):
    """Parse *text*, the output of ``nft -j list ruleset``."""
    ruleset = Ruleset(source='nftables')
    try:
        data = json.loads(text)
    except ValueError as exc:
        ruleset.messages.append(('error', f'Not a JSON document: {exc}'))
        return ruleset
    items = data.get('nftables') if isinstance(data, dict) else None
    if not isinstance(items, list):
        ruleset.messages.append(
            ('error', 'Not the output of "nft -j list ruleset": no "nftables" list.')
        )
        return ruleset

    tables = {}
    # Named limit objects, which a rule references by name.  fwf writes a
    # rule's own rate limit as one, so every line of the rule counts in the
    # same bucket.
    ruleset.named_limits = {}
    for item in items:
        if not isinstance(item, dict) or len(item) != 1:
            continue
        kind, body = next(iter(item.items()))
        if not isinstance(body, dict):
            continue
        try:
            _add_item(ruleset, tables, kind, body)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            # One object of a shape this parser does not expect costs that
            # object, not the import.
            ruleset.messages.append(
                ('warning', f'A {kind} of the listing could not be read ({exc}).')
            )
    # A table holds the kind of its base chains: a table with a nat base
    # chain is a nat table, whatever it is called.  One table may hold
    # both - firewalld since 1.0 keeps filtering and NAT in "inet
    # firewalld" - and is then read as two.
    split = []
    for table in ruleset.tables:
        split.extend(_split_by_kind(table))
    ruleset.tables = split
    for table in ruleset.tables:
        table.kind = _table_kind(table) or table.kind
    return ruleset


def _split_by_kind(table):
    """*table*, or a filter and a nat table when it has base chains of both.

    A chain of its own goes with the base chains it is reached from by
    jump or goto; one reached from neither stays with the filter part.
    """
    kinds = set(table.chain_types.values())
    if 'nat' not in kinds or not kinds - {'nat'}:
        return [table]
    reach = {}
    for name, chain_type in table.chain_types.items():
        side = 'nat' if chain_type == 'nat' else 'filter'
        stack = [name]
        while stack:
            current = stack.pop()
            if current in reach.get(side, set()):
                continue
            reach.setdefault(side, set()).add(current)
            chain = table.chains.get(current)
            if chain is not None:
                stack.extend(r.jump_target for r in chain.rules if r.jump_target)
    nat_names = reach.get('nat', set()) - reach.get('filter', set())
    parts = []
    for side, wanted in (
        ('filter', lambda name: name not in nat_names),
        ('nat', lambda name: name in nat_names),
    ):
        part = Table(name=table.name, kind=side, family=table.family)
        part.nft_family = table.nft_family
        part.chain_types = {
            name: kind for name, kind in table.chain_types.items() if wanted(name)
        }
        part.chains = {name: c for name, c in table.chains.items() if wanted(name)}
        parts.append(part)
    return parts


def _add_item(ruleset, tables, kind, body):
    if kind == 'metainfo':
        _check_metainfo(ruleset, body)
    elif kind == 'table':
        _add_table(ruleset, tables, body)
    elif kind == 'chain':
        _add_chain(tables, body)
    elif kind == 'set':
        _add_set(ruleset, tables, body)
    elif kind == 'limit':
        ruleset.named_limits[
            (body.get('family'), body.get('table'), body.get('name'))
        ] = body
    elif kind == 'rule':
        _add_rule(ruleset, tables, body)


def _check_metainfo(ruleset, body):
    ruleset.version = str(body.get('version', ''))
    schema = body.get('json_schema_version')
    if schema is not None and schema > SUPPORTED_SCHEMA_VERSION:
        ruleset.messages.append(
            (
                'warning',
                f'The listing uses JSON schema version {schema}; this importer '
                f'knows version {SUPPORTED_SCHEMA_VERSION}.',
            )
        )


def _key(body):
    return (body.get('family'), body.get('table'))


def _add_table(ruleset, tables, body):
    family_name = body.get('family')
    if family_name not in _FAMILIES:
        ruleset.messages.append(
            (
                'warning',
                f'Table {family_name} {body.get("name")} is not imported: '
                f'FirewallFabrik filters ip, ip6 and inet.',
            )
        )
        return
    table = Table(
        name=body.get('name', ''),
        kind='filter',
        family=_FAMILIES[family_name],
    )
    table.nft_family = family_name
    table.chain_types = {}
    tables[(family_name, table.name)] = table
    ruleset.tables.append(table)


def _add_chain(tables, body):
    table = tables.get(_key(body))
    if table is None:
        return
    chain = Chain(
        name=body.get('name', ''),
        hook=body.get('hook', '') if body.get('type') else '',
        policy=body.get('policy', '') if body.get('type') else '',
    )
    chain.priority = body.get('prio', 0)
    table.chains[chain.name] = chain
    if body.get('type'):
        table.chain_types[chain.name] = body['type']


def _table_kind(table):
    types = set(table.chain_types.values())
    if 'nat' in types:
        return 'nat'
    if 'route' in types:
        return 'mangle'
    hooks = {table.chains[name].hook for name, kind in table.chain_types.items()}
    priorities = [
        getattr(table.chains[name], 'priority', 0) for name in table.chain_types
    ]
    if types and all(isinstance(p, int) and p <= _MANGLE_PRIORITY for p in priorities):
        # The priority of the iptables mangle table (NF_IP_PRI_MANGLE) or
        # below: chains that run before filtering, for marks and the like.
        # A packet goes through them and through the filter chains of the
        # same hook, so their accept is not the firewall's.
        return 'mangle'
    if types and not hooks & {'input', 'forward', 'output'}:
        # Filter chains on prerouting and postrouting only are where marks
        # and priorities are set - the mangle table FirewallFabrik writes.
        return 'mangle'
    return 'filter' if types else ''


def _add_set(ruleset, tables, body):
    if _key(body) not in tables:
        return
    set_type = body.get('type')
    family = _SET_FAMILIES.get(set_type) if isinstance(set_type, str) else None
    name = body.get('name', '')
    flags = set(body.get('flags', []))
    if family is None or flags & {'dynamic', 'timeout'}:
        # A set of ports, or one the ruleset fills itself while it runs,
        # is not a list of addresses an object could stand for.
        return
    addresses = []
    for element in body.get('elem', []):
        address = _address(element, family)
        if address is not None:
            addresses.append(address)
    ruleset.sets[name] = AddressSet(name=name, family=family, addresses=addresses)


def _add_rule(ruleset, tables, body):
    table = tables.get(_key(body))
    if table is None:
        return
    chain = table.chains.setdefault(
        body.get('chain', ''), Chain(name=body.get('chain', ''))
    )
    rule = Rule(
        raw=_raw_text(body),
        family=table.family,
        comment=body.get('comment', ''),
    )
    parser = _ExprParser(rule, ruleset)
    parser.table_key = _key(body)
    try:
        parser.parse(body.get('expr', []))
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        # A statement of a shape this parser does not expect costs the
        # rule, not the import.
        rule.unsupported.append(f'a statement this importer cannot read ({exc})')
    chain.rules.append(rule)


def _raw_text(body):
    # The JSON of the rule is the closest thing to its original text the
    # listing offers; the handle lets the administrator find it with
    # "nft -a list ruleset".
    return (
        f'nft handle {body.get("handle", "?")} in {body.get("family")} '
        f'{body.get("table")} {body.get("chain")}: '
        f'{json.dumps(body.get("expr", []), separators=(",", ":"))}'
    )


def _address(value, family=None):
    """Turn one address element into an :class:`Address`, or None."""
    if isinstance(value, dict):
        if 'prefix' in value:
            prefix = value['prefix']
            text = f'{prefix.get("addr")}/{prefix.get("len")}'
        elif 'range' in value:
            low, high = value['range']
            text = f'{low}-{high}'
        elif 'elem' in value:
            return _address(value['elem'].get('val'), family)
        else:
            return None
    else:
        text = str(value)
    try:
        if '-' in text:
            low, high = text.split('-', 1)
            version = ipaddress.ip_address(low).version
            ipaddress.ip_address(high)
            return Address(family=version, text=text)
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if net.prefixlen == net.max_prefixlen:
        return Address(family=net.version, text=str(net.network_address))
    return Address(family=net.version, text=str(net))


def _values(right):
    """The values a match compares against, as a list."""
    if isinstance(right, dict) and 'set' in right:
        return list(right['set'])
    if isinstance(right, list):
        return list(right)
    return [right]


def _protocol_name(value):
    if isinstance(value, int):
        return {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6'}.get(value, str(value))
    value = str(value).lower()
    if value == 'ipv6-icmp':
        return 'icmpv6'
    return value


def _protocol_number(name):
    if name.isdigit():
        return int(name)
    try:
        return socket.getprotobyname(name)
    except OSError:
        return None


class _ExprParser:
    """Walk the statements of one rule and fill a :class:`Rule`."""

    def __init__(self, rule, ruleset):
        self.rule = rule
        self.ruleset = ruleset
        self.protocols = []  # from meta l4proto, ip protocol, ip6 nexthdr
        self.protocols_negated = False
        self.src_ports = None
        self.dst_ports = None
        self.port_protocol = ''  # tcp, udp, or th for "either"
        self.icmp = []  # (protocol, type)
        self.icmp_code = None
        self.tcp_flags = None
        self.table_key = (None, None)

    def parse(self, expressions):
        for expression in expressions:
            if not isinstance(expression, dict) or len(expression) != 1:
                self._unsupported(f'statement {expression!r}')
                continue
            kind, body = next(iter(expression.items()))
            handler = getattr(self, f'stmt_{kind}', None)
            if handler is None:
                self._unsupported(f'statement {kind}')
                continue
            handler(body)
        self._finish()

    def _unsupported(self, what):
        if what not in self.rule.unsupported:
            self.rule.unsupported.append(what)

    # -- matches --

    def stmt_match(self, body):
        op = body.get('op', '==')
        left = body.get('left')
        right = body.get('right')
        negated = op == '!='
        if op not in ('==', '!=', 'in'):
            self._unsupported(f'comparison {op}')
            return
        if not isinstance(left, dict) or len(left) != 1:
            self._unsupported(f'match on {left!r}')
            return
        kind, what = next(iter(left.items()))
        if kind == 'payload':
            self._payload(what, right, negated)
        elif kind == 'meta':
            self._meta(what.get('key'), right, negated)
        elif kind == 'ct':
            self._ct(what, right, negated)
        elif kind == '&':
            self._bitmask(what, right, negated)
        else:
            self._unsupported(f'match on {kind}')

    def _payload(self, what, right, negated):
        protocol = what.get('protocol')
        field = what.get('field')
        target = _ADDRESS_FIELDS.get((protocol, field))
        if target is not None:
            self._addresses(target[0], right, negated)
            return
        if field in ('sport', 'dport') and protocol in ('tcp', 'udp', 'th'):
            ports = self._ports(right)
            if ports is None or negated:
                self._unsupported(f'{"negated " if negated else ""}{protocol} {field}')
                return
            self.port_protocol = protocol
            if field == 'sport':
                self.src_ports = ports
            else:
                self.dst_ports = ports
            return
        if field in ('protocol', 'nexthdr') and protocol in ('ip', 'ip6'):
            self._protocols(right, negated)
            return
        if protocol in ('icmp', 'icmpv6') and field in ('type', 'code'):
            if negated:
                self._unsupported(f'negated {protocol} {field}')
                return
            table = _ICMP_TYPES if protocol == 'icmp' else _ICMP6_TYPES
            if field == 'type':
                for value in _values(right):
                    number = value if isinstance(value, int) else table.get(value)
                    if number is None:
                        self._unsupported(f'{protocol} type {value}')
                        continue
                    self.icmp.append((protocol, number))
            else:
                values = _values(right)
                if len(values) != 1 or not isinstance(values[0], int):
                    self._unsupported(f'{protocol} code {right!r}')
                    return
                self.icmp_code = values[0]
            return
        self._unsupported(f'{protocol} {field}')

    def _addresses(self, side, right, negated):
        if isinstance(right, str) and right.startswith('@'):
            name = right[1:]
            if name not in self.ruleset.sets:
                self._unsupported(f'set @{name}')
                return
            setattr(self.rule, f'{side}_set', name)
            setattr(self.rule, f'{side}_negated', negated)
            return
        addresses = []
        for value in _values(right):
            address = _address(value)
            if address is None:
                self._unsupported(f'address {value!r}')
                return
            addresses.append(address)
        getattr(self.rule, side).extend(addresses)
        setattr(self.rule, f'{side}_negated', negated)

    def _ports(self, right):
        ranges = []
        for value in _values(right):
            if isinstance(value, int):
                ranges.append(PortRange(value, value))
            elif isinstance(value, dict) and 'range' in value:
                low, high = value['range']
                if not (isinstance(low, int) and isinstance(high, int)):
                    return None
                ranges.append(PortRange(low, high))
            else:
                # A service name ("nft -S") or a named set of ports.
                return None
        return ranges

    def _protocols(self, right, negated):
        self.protocols = [_protocol_name(v) for v in _values(right)]
        self.protocols_negated = negated

    def _meta(self, key, right, negated):
        if key in ('iifname', 'iif', 'oifname', 'oif'):
            values = _values(right)
            if len(values) != 1 or not isinstance(values[0], str):
                self._unsupported(f'meta {key} {right!r}')
                return
            if key.startswith('i'):
                self.rule.in_interface = values[0]
                self.rule.in_interface_negated = negated
            else:
                self.rule.out_interface = values[0]
                self.rule.out_interface_negated = negated
            return
        if key == 'l4proto':
            self._protocols(right, negated)
            return
        if key == 'skuid':
            values = _values(right)
            if negated or len(values) != 1:
                self._unsupported(f'meta skuid {right!r}')
                return
            self.rule.user = str(values[0])
            return
        if key == 'nfproto':
            values = _values(right)
            if negated or len(values) != 1 or values[0] not in ('ipv4', 'ipv6'):
                self._unsupported(f'meta nfproto {right!r}')
                return
            self.rule.family = 4 if values[0] == 'ipv4' else 6
            return
        self._unsupported(f'meta {key}')

    def _ct(self, what, right, negated):
        if what.get('key') != 'state' or what.get('dir'):
            self._unsupported(f'ct {what.get("key")}')
            return
        if negated:
            self._unsupported('negated ct state')
            return
        self.rule.states = frozenset(str(v) for v in _values(right))

    def _bitmask(self, what, right, negated):
        # tcp flags & (fin|syn|rst|ack) == syn
        try:
            payload, mask = what
        except ValueError:
            self._unsupported('bitwise match')
            return
        if payload != {'payload': {'protocol': 'tcp', 'field': 'flags'}} or negated:
            self._unsupported('bitwise match')
            return
        mask_flags = mask.get('|') if isinstance(mask, dict) else [mask]
        set_flags = right.get('|') if isinstance(right, dict) else [right]
        if not isinstance(mask_flags, list) or not isinstance(set_flags, list):
            self._unsupported('tcp flags')
            return
        self.tcp_flags = (
            frozenset(str(f) for f in mask_flags),
            frozenset(str(f) for f in set_flags if f),
        )

    # -- statements --

    def stmt_counter(self, _body):
        pass  # counts, decides nothing

    def stmt_log(self, body):
        body = body or {}
        self.rule.log = True
        self.rule.log_prefix = body.get('prefix', '')
        self.rule.log_level = body.get('level', '')
        if set(body) - {'prefix', 'level'}:
            self._unsupported(
                'log ' + ', '.join(sorted(set(body) - {'prefix', 'level'}))
            )

    def stmt_limit(self, body):
        if isinstance(body, str):
            named = self.ruleset.named_limits.get((*self.table_key, body))
            if named is None:
                self._unsupported(f'limit object {body}')
                return
            body = named
        if body.get('rate_unit', 'packets') != 'packets':
            self._unsupported('limit over a byte rate')
            return
        self.rule.limit_over = bool(body.get('inv'))
        self.rule.limit_rate = int(body.get('rate', 0))
        self.rule.limit_unit = body.get('per', 'second')
        self.rule.limit_burst = int(body.get('burst', 0))

    def stmt_accept(self, _body):
        self.rule.action = 'accept'

    def stmt_drop(self, _body):
        self.rule.action = 'drop'

    def stmt_queue(self, body):
        # FirewallFabrik's Pipe action is a plain "queue", which nft lists
        # as queue 0 without flags (queue_stmt_json in nftables' json.c).
        self.rule.action = 'queue'
        body = body or {}
        if body.get('num', 0) != 0:
            self._unsupported(f'queue to {body["num"]!r}')
        if body.get('flags'):
            self._unsupported(f'queue flags {body["flags"]!r}')

    def stmt_return(self, _body):
        self.rule.action = 'return'

    def stmt_jump(self, body):
        self.rule.action = 'jump'
        self.rule.jump_target = body.get('target', '')

    def stmt_goto(self, body):
        self.rule.action = 'jump'
        self.rule.jump_target = body.get('target', '')
        self.rule.goto = True

    def stmt_reject(self, body):
        self.rule.action = 'reject'
        body = body or {}
        if body.get('type') == 'tcp reset':
            self.rule.reject_with = 'tcp-reset'
        elif body.get('expr'):
            self.rule.reject_with = str(body['expr'])

    def _nat(self, action, body):
        self.rule.action = action
        body = body or {}
        if body.get('addr') is not None:
            address = _address(body['addr'])
            if address is None:
                self._unsupported(f'{action} to {body["addr"]!r}')
            else:
                self.rule.nat_addresses.append(address)
        port = body.get('port')
        if isinstance(port, int):
            self.rule.nat_ports = PortRange(port, port)
        elif isinstance(port, dict) and 'range' in port:
            self.rule.nat_ports = PortRange(*port['range'])
        elif port is not None:
            self._unsupported(f'{action} port {port!r}')
        if body.get('flags') or body.get('type_flags'):
            self._unsupported(f'{action} flags')

    def stmt_snat(self, body):
        self._nat('snat', body)

    def stmt_dnat(self, body):
        self._nat('dnat', body)

    def stmt_masquerade(self, body):
        self._nat('masquerade', body)

    def stmt_redirect(self, body):
        self._nat('redirect', body)

    def stmt_xt(self, body):
        name = (body or {}).get('name', '?')
        self._unsupported(
            f'iptables-nft match or target {name}; import this table from '
            f'iptables-save instead'
        )

    # -- assembly --

    def _finish(self):
        rule = self.rule
        services = []
        if self.icmp:
            for protocol, number in self.icmp:
                services.append(
                    Service(
                        protocol=protocol, icmp_type=number, icmp_code=self.icmp_code
                    )
                )
        elif self.src_ports is not None or self.dst_ports is not None:
            if self.port_protocol == 'th':
                protocols = [p for p in self.protocols if p in ('tcp', 'udp')]
                if not protocols:
                    self._unsupported('th port without tcp or udp')
            else:
                protocols = [self.port_protocol]
            for protocol in protocols:
                services.append(
                    Service(
                        protocol=protocol,
                        src_ports=list(self.src_ports or []),
                        dst_ports=list(self.dst_ports or []),
                    )
                )
        elif self.tcp_flags is not None:
            services.append(
                Service(
                    protocol='tcp',
                    tcp_flags_mask=self.tcp_flags[0],
                    tcp_flags_set=self.tcp_flags[1],
                )
            )
        else:
            for protocol in self.protocols:
                if protocol not in ('tcp', 'udp', 'icmp', 'icmpv6') and (
                    _protocol_number(protocol) is None
                ):
                    self._unsupported(f'protocol {protocol}')
                    continue
                services.append(Service(protocol=protocol))
        if self.tcp_flags is not None and services and services[0].protocol == 'tcp':
            services[0].tcp_flags_mask, services[0].tcp_flags_set = self.tcp_flags
        rule.services = services
        rule.services_negated = self.protocols_negated and bool(services)
        if rule.action == 'continue' and rule.log:
            rule.action = 'log'
