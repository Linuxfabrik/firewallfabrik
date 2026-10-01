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

"""Turn the neutral model into FirewallFabrik objects.

The result is a list of object descriptions in the shape of the ``.fwf``
data file - the same dictionaries the YAML reader reads - so that
:mod:`firewallfabrik.importer._apply` can hand them to that reader and
every object arrives exactly as if it had been loaded from a file.

The mapping follows Firewall Builder's importer (``IPTImporter.cpp``),
which decided most of the questions an import raises:

* the built-in chains of the filter table become one top Policy rule set,
  each chain of its own a rule set that a Branch rule jumps to, and the
  nat table the same for NAT;
* an input rule gets the firewall as its destination and an output rule
  as its source, and "firewall is part of any" is switched off, so a rule
  of the forward chain stays in the forward chain;
* a rule naming both an incoming and an outgoing interface becomes a rule
  on the incoming one that branches into a rule set holding the rule on
  the outgoing one, since a FirewallFabrik policy rule has one interface
  and one direction;
* an address or service the data file already has - the Standard library
  included - is used instead of a copy (Firewall Builder's "Find and use
  existing objects");
* a rule whose meaning cannot be carried over is imported anyway, but
  disabled, coloured, and with the original text and the reason in its
  comment.

Where Firewall Builder stops short this goes further: IPv6, ``conntrack``
states and nftables are read, a LOG rule followed by the rule it logs for
becomes one logged rule, and a built-in chain whose policy is ACCEPT ends
with a rule that says so.
"""

import copy
import dataclasses
import ipaddress
import socket

from firewallfabrik.core._util import escape_obj_name
from firewallfabrik.importer._model import Address, Rule, Service

# Firewall Builder's colour for a rule it could not import
# (Importer::markCurrentRuleBad).
UNSUPPORTED_COLOR = '#C86E6E'

_REJECT_TYPES = {
    'adm-prohibited': 'ICMP admin prohibited',
    'admin-prohib': 'ICMP admin prohibited',
    'admin-prohibited': 'ICMP admin prohibited',
    'addr-unreach': 'ICMP host unreachable',
    'addr-unreachable': 'ICMP host unreachable',
    'host-prohib': 'ICMP host prohibited',
    'host-unreach': 'ICMP host unreachable',
    'net-prohib': 'ICMP net prohibited',
    'net-unreach': 'ICMP net unreachable',
    'port-unreach': 'ICMP port unreachable',
    'proto-unreach': 'ICMP protocol unreachable',
    'tcp-rst': 'TCP RST',
    'host-prohibited': 'ICMP host prohibited',
    'host-unreachable': 'ICMP host unreachable',
    'icmp-admin-prohibited': 'ICMP admin prohibited',
    'icmp-host-prohibited': 'ICMP host prohibited',
    'icmp-host-unreachable': 'ICMP host unreachable',
    'icmp-net-prohibited': 'ICMP net prohibited',
    'icmp-net-unreachable': 'ICMP net unreachable',
    'icmp-port-unreachable': 'ICMP port unreachable',
    'icmp-proto-unreachable': 'ICMP protocol unreachable',
    'icmp6-addr-unreachable': 'ICMP host unreachable',
    'icmp6-adm-prohibited': 'ICMP admin prohibited',
    'icmp6-port-unreachable': 'ICMP port unreachable',
    'net-prohibited': 'ICMP net prohibited',
    'net-unreachable': 'ICMP net unreachable',
    'port-unreachable': 'ICMP port unreachable',
    'prot-unreachable': 'ICMP protocol unreachable',
    'tcp-reset': 'TCP RST',
}

_TERMINAL_ACTIONS = {'accept', 'drop', 'queue', 'reject', 'return'}
_POLICY_ACTIONS = {
    'accept': 'Accept',
    'drop': 'Deny',
    'queue': 'Pipe',
    'reject': 'Reject',
    'return': 'Return',
    'continue': 'Continue',
    'log': 'Continue',
    'jump': 'Branch',
}

_FLAG_NAMES = ('urg', 'ack', 'psh', 'rst', 'syn', 'fin')

# Options of the imported firewall.  Each of these, left at its default,
# makes the compiler add rules of its own that the imported ruleset did
# not have: an imported firewall has to do what the old one did.
_NEUTRAL_OPTIONS = {
    'accept_established': False,
    'check_shading': False,
    'configure_interfaces': False,
    'drop_invalid': False,
    'firewall_is_part_of_any_and_networks': False,
    # A log line without a prefix of its own takes the firewall's, and
    # every log line is capped at the firewall's logging limit; the
    # imported rules had neither unless the input says so.
    'limit_value': '0',
    'log_invalid': False,
    'log_prefix': '',
    'manage_virtual_addr': False,
    'verify_interfaces': False,
}


@dataclasses.dataclass
class ExistingObjects:
    """Addresses and services the data file already has, by what they mean.

    *by_signature* maps the signature :func:`address_signature` or
    :func:`service_signature` computes to the reference path of an object
    that means exactly that.  *established* holds the paths of the
    Standard library's "ESTABLISHED" services, per address family.
    """

    by_signature: dict = dataclasses.field(default_factory=dict)
    established: dict = dataclasses.field(default_factory=dict)
    taken_names: set = dataclasses.field(default_factory=set)


@dataclasses.dataclass
class ImportPlan:
    """What the builder produced: objects to create and what it had to say."""

    firewall: dict
    objects: list[dict]
    messages: list[tuple[str, str]]
    unsupported_rules: int = 0  # imported disabled
    widened_rules: int = 0  # blocking rules imported without a condition
    imported_rules: int = 0
    imported_routes: int = 0
    marked_routes: int = 0  # routes imported without part of what they said


def address_signature(address):
    """The signature of an :class:`Address`, or of an object's fields."""
    text = address.text
    if '-' in text:
        low, high = text.split('-', 1)
        return (
            'range',
            str(ipaddress.ip_address(low)),
            str(ipaddress.ip_address(high)),
        )
    net = ipaddress.ip_network(text, strict=False)
    if net.prefixlen == net.max_prefixlen:
        return ('host', str(net.network_address))
    return ('net', str(net))


def service_signature(protocol, src=(0, 0), dst=(0, 0), flags=(), mask=(), icmp=None):
    """The signature of one service, independent of how it was written."""
    if protocol in ('tcp', 'udp'):
        return (protocol, tuple(src), tuple(dst), frozenset(mask), frozenset(flags))
    if protocol in ('icmp', 'icmpv6'):
        return (protocol, icmp)
    return ('ip', protocol)


class Builder:
    """Build the plan for one firewall out of one or more parsed inputs."""

    def __init__(
        self,
        fw_name,
        platform,
        version,
        library_path,
        path_for,
        existing,
        interface_addresses=None,
    ):
        """*path_for(type_name, name)* returns the reference path an object
        of that type and name will have once it is in the library.

        *interface_addresses* maps an interface name to its addresses, as
        :func:`parse_ip_addr_json` reads them from the machine; without
        it every interface but the loopback is dynamic.
        """
        self.fw_name = fw_name
        self.platform = platform
        self.version = version
        self.library_path = library_path
        self.path_for = path_for
        self.existing = existing
        self.fw_path = path_for('Firewall', fw_name)
        self.objects = {}  # signature -> (path, dict)
        self.names = set(existing.taken_names)
        self.interfaces = {}  # name -> dict
        self.interface_addresses = interface_addresses or {}
        for name in self.interface_addresses:
            self._interface_ref(name)
        self.rule_sets = []  # dicts, in order
        self.rule_set_names = set()
        self.messages = []
        self.options = dict(_NEUTRAL_OPTIONS)
        self.unsupported_rules = 0
        self.imported_routes = 0
        self.imported_routes_marked = 0
        self.fw_hosts = []
        self.widened_rules = 0
        self.imported_rules = 0
        self._current_sets = {}
        self._nested_count = 0
        self.original_names = {}

    # -- entry point --

    def build(self, rulesets, table_filter=None, routes=None):
        """Build from *rulesets*; *table_filter(table)* picks the tables.

        *routes* are the :class:`Routes` of ``ip -j route``, one per
        address family, for the Routing rule set.
        """
        selected = [
            (ruleset, table)
            for ruleset in rulesets
            for table in ruleset.tables
            if table_filter is None or table_filter(table)
        ]
        # What follows trims and rewrites chains; a copy keeps the parsed
        # input as it was for a second plan from it, for another platform.
        # One deepcopy of both keeps the tables in *selected* those of the
        # copied rule sets.
        rulesets, selected = copy.deepcopy((rulesets, selected))
        for ruleset in rulesets:
            self.messages.extend(ruleset.messages)
        self._automatic_rules([table for _rs, table in selected])
        self._most_common_log_limit([table for _rs, table in selected])
        self._local_addresses([table for _rs, table in selected])
        for ruleset, table in selected:
            self._table(ruleset, table)
        self._routing(routes or [])
        self._empty_top_rule_sets()
        firewall = {
            'type': 'Firewall',
            'name': self.fw_name,
            'data': {
                'platform': self.platform,
                'host_OS': 'linux24',
                'version': self.version,
            },
            'options': self.options,
            'interfaces': list(self.interfaces.values()),
            'rule_sets': self.rule_sets,
        }
        return ImportPlan(
            firewall=firewall,
            objects=[obj for _path, obj in self.objects.values() if obj is not None],
            messages=self.messages,
            unsupported_rules=self.unsupported_rules,
            widened_rules=self.widened_rules,
            imported_rules=self.imported_rules,
            imported_routes=self.imported_routes,
            marked_routes=self.imported_routes_marked,
        )

    # -- routing --

    def _routing(self, route_lists):
        """Turn the routes into the rules of the Routing rule set.

        A route of several next hops becomes one rule per hop, with the
        destination and the metric they share; the compiler writes such
        rules as one equal-cost multi path route.  A route with something
        a routing rule cannot hold is imported all the same, colored and
        with the original in its comment: the route without it still
        reaches its destination.  Only a gateway the interface cannot
        reach by itself ("onlink") is imported disabled, because the
        compiler refuses it and the activation would stop.
        """
        rules = []
        for routes in route_lists:
            self.messages.extend(routes.messages)
            for route in routes.routes:
                rules.extend(self._routing_rules(route))
        if rules:
            self._add_routing_rule_set(rules)

    def _routing_rules(self, route):
        problems = list(route.unsupported)
        rdst = []
        if route.dst is not None:
            try:
                rdst = [self._address_ref(route.dst)]
            except ValueError:
                problems.append(f'destination {route.dst.text}')
        elif route.family == 6:
            # An empty destination is the default route, and iproute2 takes
            # the family of such a route from the gateway; one out of a
            # device alone would come out as IPv4.
            rdst = [self._address_ref(Address(family=6, text='::/0'))]
        rules = []
        for hop in route.next_hops:
            rule = {'type': 'RoutingRule', 'options': {}}
            if rdst:
                rule['rdst'] = rdst
            if hop.gateway is not None:
                try:
                    rule['rgtw'] = [self._address_ref(hop.gateway)]
                except ValueError:
                    problems.append(f'gateway {hop.gateway.text}')
            if hop.dev:
                rule['ritf'] = [self._interface_ref(hop.dev)]
            if route.metric:
                rule['options']['metric'] = route.metric
            rules.append(rule)
        comment = []
        if problems:
            comment.append('Imported without: ' + '; '.join(problems) + '.')
            comment.append(f'Original: {route.raw}')
        disabled = any(p.endswith('onlink') for p in problems)
        for rule in rules:
            if problems:
                rule['options']['color'] = UNSUPPORTED_COLOR
                rule['comment'] = '\n'.join(comment)
            if disabled:
                rule['options']['disabled'] = True
        where = f'IPv{route.family} route {route.dst.text if route.dst else "default"}'
        if disabled:
            self.unsupported_rules += 1
            self.messages.append(
                ('warning', f'{where}: imported disabled: ' + '; '.join(problems))
            )
        elif problems:
            self.imported_routes_marked += 1
            self.messages.append(
                ('warning', f'{where}: imported without ' + '; '.join(problems))
            )
        self.imported_routes += 1
        return rules

    def _add_routing_rule_set(self, rules):
        rule_set = {'type': 'Routing', 'name': 'Routing', 'top': True, 'rules': []}
        for position, rule in enumerate(rules):
            rule['position'] = position
            rule_set['rules'].append(rule)
        self.rule_sets.append(rule_set)

    def _empty_top_rule_sets(self):
        """Give the firewall the rule sets a new one starts with."""
        present = {rs['type'] for rs in self.rule_sets if rs.get('top')}
        for rs_type in ('Policy', 'NAT', 'Routing'):
            if rs_type not in present:
                self.rule_sets.append(
                    {'type': rs_type, 'name': rs_type, 'top': True, 'rules': []}
                )

    # -- the rules FirewallFabrik writes by itself --

    def _automatic_rules(self, tables):
        """Turn the leading state rules of every filter chain into options.

        FirewallFabrik puts the same rules at the start of every built-in
        chain: accept established and related packets, log and drop the
        invalid ones - three firewall options say whether it does.  A hand
        written ruleset usually starts the same way.  Where *every*
        built-in chain of the filter tables starts with the same of these
        rules, they are the options and the rules are dropped; otherwise
        the options would add them to a chain that did not have them, and
        they are imported as rules.
        """
        chains = [
            chain
            for table in tables
            if table.kind == 'filter'
            for chain in table.chains.values()
            if chain.hook in ('input', 'forward', 'output')
        ]
        if not chains:
            return
        prefixes = [_automatic_prefix(chain.rules) for chain in chains]
        kinds = {tuple(kind for kind, _rule in prefix) for prefix in prefixes}
        if len(kinds) != 1 or not next(iter(kinds)):
            return
        found = next(iter(kinds))
        log_rules = [
            rule for prefix in prefixes for kind, rule in prefix if kind == 'log'
        ]
        if log_rules and not self._log_limit_from(log_rules[0]):
            return
        if any(not self._log_limit_matches(rule) for rule in log_rules):
            return
        for chain, prefix in zip(chains, prefixes, strict=True):
            chain.rules = chain.rules[len(prefix) :]
        self.options['accept_established'] = 'established' in found
        self.options['drop_invalid'] = 'drop' in found
        self.options['log_invalid'] = 'log' in found
        self.messages.append(
            (
                'info',
                'The rules every built-in chain starts with - '
                + ', '.join(_AUTOMATIC_LABELS[kind] for kind in found)
                + ' - are the firewall options of the same name.',
            )
        )

    def _local_addresses(self, tables):
        """Give the firewall the addresses its input and output rules name.

        A packet in the input chain is addressed to this machine and one in
        the output chain comes from it, so an address an input rule
        matches as destination, or an output rule as source, is one of the
        firewall's own.  A ruleset does not list the addresses of the
        interfaces; without these the rule would name an address the
        firewall object does not have, and compile into the forward chain.
        Where the interfaces are not known, the addresses go on an
        interface of their own, marked unprotected so that no rule is made
        for it.
        """
        known = {
            str(ipaddress.ip_interface(address).ip)
            for addresses in self.interface_addresses.values()
            for address in addresses
        }
        found = []
        for table in tables:
            if table.kind != 'filter':
                continue
            for chain in table.chains.values():
                side = {'input': 'dst', 'output': 'src'}.get(chain.hook)
                if side is None:
                    continue
                for rule in chain.rules:
                    if getattr(rule, f'{side}_negated'):
                        continue
                    for address in getattr(rule, side):
                        host = _local_host(address)
                        if host and host not in known and host not in found:
                            found.append(host)
        self.fw_hosts = [ipaddress.ip_address(h) for h in (*known, *found)]
        if not found:
            return
        self.interfaces['imported'] = {
            'name': 'imported',
            'comment': (
                'The addresses the imported input and output rules address the '
                'firewall with. The ruleset does not say which interface each '
                'of them is on; move them to the right interface.'
            ),
            'data': {'unprotected': True},
            'addresses': [
                _interface_address(
                    'imported', index, host + ('/128' if ':' in host else '/32')
                )
                for index, host in enumerate(found)
            ],
        }
        self.messages.append(
            (
                'info',
                'Addresses of the firewall the rules name, on the interface '
                '"imported": ' + ', '.join(found),
            )
        )

    def _most_common_log_limit(self, tables):
        """Make the most common rate limit of the LOG rules the firewall's.

        FirewallFabrik has one logging limit for the whole firewall; a LOG
        rule with a different one cannot keep it, and choosing the most
        common one leaves the fewest of them behind.
        """
        if self.options.get('limit_value', '0') != '0':
            return
        counts = {}
        for table in tables:
            for chain in table.chains.values():
                for rule in chain.rules:
                    if rule.action == 'log' and rule.limit_rate:
                        key = (rule.limit_rate, rule.limit_unit)
                        counts[key] = counts.get(key, 0) + 1
        if counts:
            rate, unit = max(counts, key=lambda key: (counts[key], key))
            self.options['limit_value'] = str(rate)
            self.options['limit_suffix'] = f'/{unit}'

    def _log_limit_from(self, rule):
        """Take the logging limit of the firewall from a log rule."""
        if not rule.limit_rate:
            return True
        if self.options.get('limit_value', '0') != '0':
            return self._log_limit_matches(rule)
        self.options['limit_value'] = str(rule.limit_rate)
        self.options['limit_suffix'] = f'/{rule.limit_unit}'
        return True

    def _log_limit_matches(self, rule):
        if not rule.limit_rate:
            return self.options.get('limit_value', '0') == '0'
        return self.options.get('limit_value') == str(rule.limit_rate) and (
            self.options.get('limit_suffix') == f'/{rule.limit_unit}'
        )

    # -- tables and chains --

    def _table(self, ruleset, table):
        self._current_sets = ruleset.sets
        if table.kind not in ('filter', 'nat'):
            self.messages.append(
                (
                    'warning',
                    f'Table {table.name}: a {table.kind} table is not imported.',
                )
            )
            return
        rs_type = 'Policy' if table.kind == 'filter' else 'NAT'
        family_suffix = (
            ' IPv6' if table.family == 6 else ''
        )  # a top rule set is no chain
        top_name = self._unique_rule_set_name(
            rs_type, f'{rs_type}{family_suffix}', table, top=True
        )
        # firewalld gives every zone NAT chains it leaves empty and jumps
        # into each of them.  A jump into an empty chain comes straight
        # back, and a NAT rule set without rules is one the compilers
        # refuse to branch into, so such jumps and chains are left out.
        empty = _empty_chains(table) if rs_type == 'NAT' else set()
        chain_names = {}
        for chain in table.chains.values():
            if not chain.hook and chain.name not in empty:
                chain_names[chain.name] = self._unique_rule_set_name(
                    rs_type, chain.name, table
                )
        context = _TableContext(
            ruleset=ruleset,
            table=table,
            rs_type=rs_type,
            chain_names=chain_names,
            ipv4=table.family in (4, None),
            ipv6=table.family in (6, None),
            empty_chains=empty,
        )

        top_rules = []
        hooks = _POLICY_HOOKS if rs_type == 'Policy' else _NAT_HOOKS
        for chain in table.chains.values():
            if chain.hook and chain.hook not in hooks:
                self.messages.append(
                    (
                        'warning',
                        f'Table {table.name}: chain {chain.name} on {chain.hook} is '
                        f'not imported; a {rs_type} rule set has no place for it.',
                    )
                )
        base_chains = sorted(
            (c for c in table.chains.values() if c.hook in hooks),
            key=lambda c: _HOOK_ORDER.get(c.hook, 99),
        )
        hooks_seen = {}
        for chain in base_chains:
            if chain.hook in hooks_seen:
                self.messages.append(
                    (
                        'warning',
                        f'Table {table.name}: chains {hooks_seen[chain.hook]} and '
                        f'{chain.name} both hook into {chain.hook}; their rules are '
                        f'imported one after the other, but in the kernel a packet '
                        f'accepted by one of them is still seen by the other.',
                    )
                )
            hooks_seen[chain.hook] = chain.name
            top_rules.extend(self._chain_rules(context, chain))
            if rs_type == 'Policy' and chain.policy == 'accept':
                top_rules.append(self._policy_rule(chain))
        self._add_rule_set(rs_type, top_name, context, top_rules, top=True)
        for chain in table.chains.values():
            if chain.hook or chain.name in empty:
                continue
            rules = self._chain_rules(context, chain)
            self._add_rule_set(rs_type, chain_names[chain.name], context, rules)
        context_rule_sets = context.extra_rule_sets
        for name, rules, family in context_rule_sets:
            self._add_rule_set(rs_type, name, context, rules, family=family)

    def _unique_rule_set_name(self, rs_type, name, table, top=False):
        """A rule set name no other one has, and a valid chain name.

        A rule set other than the top one becomes a chain of its own, and
        iptables refuses a chain name with whitespace in it or longer than
        28 characters (XT_EXTENSION_MAXNAMELEN).  The iptables compiler
        writes a NAT rule set as one chain per direction, named after it
        with "_PREROUTING" or "_POSTROUTING" behind, which leaves 16.  A
        longer name - firewalld names its chains like
        "filter_IN_policy_allow-host-ipv6" - is cut, and the rule set's
        comment keeps the original.
        """
        candidate = name
        if not top:
            limit = _NAT_NAME_LIMIT if rs_type == 'NAT' else _CHAIN_NAME_LIMIT
            if len(candidate) > limit:
                candidate = candidate[: limit - 3]
        if (rs_type, candidate) in self.rule_set_names and table.family == 6:
            candidate = f'{candidate}_v6' if top else f'{candidate[:-3]}_v6'
        n = 2
        base = candidate
        while (rs_type, candidate) in self.rule_set_names:
            candidate = f'{base}_{n}' if top else f'{base[: -1 - len(str(n))]}_{n}'
            n += 1
        self.rule_set_names.add((rs_type, candidate))
        if candidate != name:
            self.original_names[(rs_type, candidate)] = name
        return candidate

    def _add_rule_set(self, rs_type, name, context, rules, top=False, family=None):
        rule_set = {
            'type': rs_type,
            'name': name,
            'ipv4': context.ipv4 if family is None else family == 4,
            'ipv6': context.ipv6 if family is None else family == 6,
            'top': top,
            'rules': [],
        }
        original = self.original_names.get((rs_type, name))
        if original and not top:
            rule_set['comment'] = f'Chain {original} of the imported ruleset.'
        for position, rule in enumerate(rules):
            rule['position'] = position
            rule_set['rules'].append(rule)
        self.rule_sets.append(rule_set)

    def _rule_set_path(self, rs_type, name):
        return f'{self.fw_path}/{rs_type}:{escape_obj_name(name)}'

    def _chain_rules(self, context, chain):
        rules = []
        model_rules = list(chain.rules)
        index = 0
        while index < len(model_rules):
            rule = model_rules[index]
            following = model_rules[index + 1] if index + 1 < len(model_rules) else None
            if (
                rule.action == 'log'
                and following is not None
                and _same_match(rule, following)
                and following.action in _TERMINAL_ACTIONS
                and not following.log
                and not rule.unsupported
            ):
                # LOG and the rule it logs for are one rule in
                # FirewallFabrik, which compiles a logged rule back into
                # exactly this pair.
                merged = dataclasses.replace(
                    following,
                    log=True,
                    log_prefix=rule.log_prefix,
                    log_level=rule.log_level,
                    raw=f'{rule.raw}\n{following.raw}',
                    comment=following.comment or rule.comment,
                )
                if rule.limit_rate and not self._log_limit_from(rule):
                    merged.unsupported = [
                        *merged.unsupported,
                        'a log rate limit other than the one of the other log rules',
                    ]
                rule = merged
                index += 1
            index += 1
            if _jumps_into(rule, context.empty_chains):
                continue
            if _jumps_into(rule, context.empty_chains, goto=True):
                # A goto into an empty chain is a return.
                rule = dataclasses.replace(
                    rule, action='return', goto=False, jump_target=''
                )
            if context.rs_type == 'Policy':
                built = self._policy_rule_from(context, chain, rule)
            else:
                built = self._nat_rule_from(context, chain, rule)
            if (
                rule.goto
                and built
                and built[0].get('action') == 'Branch'
                and 'rule set this rule branches into'
                not in built[0].get('comment', '')
            ):
                built.append(_goto_return(built[0]))
            rules.extend(built)
        return rules

    # -- policy rules --

    def _policy_rule(self, chain):
        """The rule a built-in chain with policy ACCEPT ends with."""
        rule = {
            'type': 'PolicyRule',
            'action': 'Accept',
            'comment': f'Policy of chain {chain.name}.',
            'options': {'stateless': True},
        }
        if chain.hook == 'input':
            rule['direction'] = 'Inbound'
            rule['dst'] = [self.fw_path]
        elif chain.hook == 'output':
            rule['direction'] = 'Outbound'
            rule['src'] = [self.fw_path]
        else:
            rule['direction'] = 'Both'
        self.imported_rules += 1
        return rule

    def _policy_rule_from(self, context, chain, rule):
        problems = list(rule.unsupported)
        options = {}  # what the rule does: logging, limits, reject type
        main = {}  # the elements of the rule that carries the match
        main_neg = {}
        # Conditions a FirewallFabrik policy rule cannot hold next to the
        # main ones, each as (elements, negations, direction): a second
        # interface, a connection state next to a service, a user next to
        # a service.  Each goes into a rule set of its own that the rule
        # before it branches into, the way Firewall Builder's importer
        # does it, and the last one holds the action.
        nested = []

        action = _POLICY_ACTIONS.get(rule.action)
        if action is None:
            problems.append(f'action {rule.action}')
            action = 'Continue'
        if rule.action == 'jump':
            target = context.chain_names.get(rule.jump_target)
            if target is None:
                problems.append(f'jump to the unknown chain {rule.jump_target}')
                action = 'Continue'
            else:
                options['branch_id'] = self._rule_set_path('Policy', target)
        if rule.action == 'reject' and rule.reject_with:
            reject = _REJECT_TYPES.get(rule.reject_with)
            if reject is None:
                problems.append(f'reject with {rule.reject_with}')
            else:
                options['action_on_reject'] = reject

        # Addresses.  The chain a rule is in becomes its direction, and the
        # firewall object stands for "this machine" where the chain says so.
        src = self._address_refs(rule.src, rule.src_set, problems)
        dst = self._address_refs(rule.dst, rule.dst_set, problems)
        if rule.src_negated and src:
            main_neg['src'] = True
        if rule.dst_negated and dst:
            main_neg['dst'] = True
        direction = 'Both'
        local_side = {'input': 'dst', 'output': 'src'}.get(chain.hook)
        if local_side is not None:
            direction = 'Inbound' if chain.hook == 'input' else 'Outbound'
            refs = dst if local_side == 'dst' else src
            model = rule.dst if local_side == 'dst' else rule.src
            local_set = rule.dst_set if local_side == 'dst' else rule.src_set
            negated_local = (
                rule.dst_negated if local_side == 'dst' else rule.src_negated
            )
            if refs and (
                local_set or negated_local or any(not _single_host(a) for a in model)
            ):
                # A network on the local side is "an address of this machine
                # within that network", which one rule element cannot say:
                # the rule names the firewall, and the rule set it branches
                # into the network.
                negated = main_neg.pop(local_side, False)
                nested.append(
                    ({local_side: refs}, {local_side: True} if negated else {}, None)
                )
                refs = []
            if not refs:
                refs = [self.fw_path]
            if local_side == 'dst':
                dst = refs
            else:
                src = refs
        elif chain.hook == 'forward':
            # An address range around one of the firewall's addresses,
            # negated or not, makes the compiler add the rule to the output
            # or input chain as well, ahead of the rules imported there
            # (splitIfSrcMatchesFw and splitIfSrcNegAndFw in Firewall
            # Builder; a network does not, the firewall option
            # firewall_is_part_of_any_and_networks is off).  In the rule set
            # a rule branches into, the chain is that rule set's own.
            for side in ('src', 'dst'):
                model = rule.src if side == 'src' else rule.dst
                set_name = rule.src_set if side == 'src' else rule.dst_set
                if set_name and set_name in self._current_sets:
                    model = [*model, *self._current_sets[set_name].addresses]
                if self._covers_firewall(model):
                    refs = src if side == 'src' else dst
                    if not refs:
                        continue
                    negated = main_neg.pop(side, False)
                    nested.append(({side: refs}, {side: True} if negated else {}, None))
                    if side == 'src':
                        src = []
                    else:
                        dst = []
        # In an inet table, "meta nfproto ipv4" restricts a rule that names
        # no address to one family.  The rule set the action goes into is
        # then compiled for that family alone; the branch into it does
        # nothing for the other one.  An "all IPv4" network would say the
        # same, but the compiler reads 0.0.0.0/0 as a network the firewall
        # is on and moves a forward rule into the output chain.
        family_only = None
        if (
            rule.family in (4, 6)
            and context.table.family is None
            and not any(a.family == rule.family for a in [*rule.src, *rule.dst])
            and not any(s.protocol in ('icmp', 'icmpv6') for s in rule.services)
        ):
            family_only = rule.family
        main['src'], main['dst'] = src, dst

        # Interfaces.
        if rule.in_interface:
            main['itf'] = [self._interface_ref(rule.in_interface)]
            direction = 'Inbound'
            if rule.in_interface_negated:
                main_neg['itf'] = True
            if rule.out_interface:
                neg = {'itf': True} if rule.out_interface_negated else {}
                nested.append(
                    (
                        {'itf': [self._interface_ref(rule.out_interface)]},
                        neg,
                        'Outbound',
                    )
                )
        elif rule.out_interface:
            main['itf'] = [self._interface_ref(rule.out_interface)]
            direction = 'Outbound'
            if rule.out_interface_negated:
                main_neg['itf'] = True

        # Services, the connection state and the user, all of which
        # FirewallFabrik keeps in the service element.
        services = self._service_refs(rule.services, rule.family, problems)
        if rule.services_negated and services:
            main_neg['srv'] = True
        extra_services = []
        states = rule.states
        if states is None:
            options['stateless'] = True
        elif states == {'new'}:
            options['stateless'] = False
        else:
            options['stateless'] = True
            if states == {'established', 'related'}:
                extra_services.append(self._established(rule))
            else:
                extra_services.append(self._state_service(states))
        if rule.user:
            # The compiler takes a user match only in the output chain and
            # drops it from a chain a rule branches into, so the user stays
            # in the rule itself and the ports go into the rule set behind it.
            user = self._user_service(rule.user)
            if services or main_neg.get('srv'):
                srv_neg = {'srv': True} if main_neg.pop('srv', False) else {}
                nested.insert(0, ({'srv': services}, srv_neg, None))
            services = [user]
        for service in extra_services:
            if services or main_neg.get('srv'):
                nested.append(({'srv': [service]}, {}, None))
            else:
                services = [service]
        main['srv'] = services

        # Logging and limits.  A LOG rule's limit caps its log lines, which
        # is the firewall's logging limit in FirewallFabrik.
        limit_rate = rule.limit_rate
        if rule.action == 'log' and limit_rate:
            if self._log_limit_from(rule):
                limit_rate = 0
            else:
                problems.append(
                    'a log rate limit other than the one of the other log rules'
                )
        if rule.log:
            options['log'] = True
            options['log_prefix'] = rule.log_prefix
            # iptables-save leaves out the default level, which is
            # "warning" (LOG_save, libxt_LOG.c), and so does nft (warn).
            options['log_level'] = rule.log_level or 'warning'
        if limit_rate:
            options['limit_value'] = str(limit_rate)
            options['limit_suffix'] = f'/{rule.limit_unit}'
            if rule.limit_over:
                options['limit_value_not'] = True
            if rule.limit_burst:
                options['limit_burst'] = str(rule.limit_burst)

        # The rule carrying the main match, and the chain of rule sets
        # behind it.  Every rule but the last only branches; the last one
        # does what the imported rule did.
        if family_only and not nested:
            nested.append(({}, {}, None))
        out = self._policy_rule_dict(main, main_neg, direction)
        current = out
        for index, (elements, negations, nested_direction) in enumerate(nested):
            self._nested_count += 1
            name = self._unique_rule_set_name(
                'Policy', f'{chain.name[:20]}_b{self._nested_count}', context.table
            )
            current['action'] = 'Branch'
            current['options'] = {
                'stateless': True,
                'branch_id': self._rule_set_path('Policy', name),
            }
            # The rule that branches already matches only what the chain it
            # is in sees; the firewall object in the rule inside would not be
            # taken out there, but turned into the addresses of every
            # interface.
            inner_elements = dict(elements)
            # Inside the rule set it branches into, a direction without an
            # interface would only add an "any interface" match the chain of
            # the branching rule does not need.
            inner = self._policy_rule_dict(
                inner_elements,
                negations,
                nested_direction
                or ('Both' if 'itf' not in inner_elements else direction),
            )
            last = index == len(nested) - 1
            context.extra_rule_sets.append(
                (name, [inner], family_only if last else None)
            )
            current = inner
        current['action'] = action
        current['options'] = options
        self._finish(out, rule, problems, blocking=action in ('Deny', 'Reject'))
        if current is not out:
            note = 'The rest of the match is in the rule set this rule branches into.'
            out['comment'] = f'{out.get("comment", "")}\n{note}'.strip()
            if out['options'].get('disabled'):
                current['options']['disabled'] = True
            if out['options'].get('color'):
                current['options']['color'] = UNSUPPORTED_COLOR
        return [out]

    def _policy_rule_dict(self, elements, negations, direction):
        rule = {'type': 'PolicyRule', 'direction': direction, 'options': {}}
        for slot in ('src', 'dst', 'srv', 'itf'):
            if elements.get(slot):
                rule[slot] = elements[slot]
        negations = {k: v for k, v in negations.items() if v and elements.get(k)}
        if negations:
            rule['negations'] = negations
        return rule

    # -- NAT rules --

    def _nat_rule_from(self, context, chain, rule):
        problems = list(rule.unsupported)
        out = {'type': 'NATRule', 'action': 'Translate', 'options': {}}
        osrc = self._address_refs(rule.src, rule.src_set, problems)
        odst = self._address_refs(rule.dst, rule.dst_set, problems)
        osrv = self._service_refs(rule.services, rule.family, problems)
        negations = {}
        if rule.src_negated and osrc:
            negations['osrc'] = True
        if rule.dst_negated and odst:
            negations['odst'] = True
        if rule.services_negated and osrv:
            negations['osrv'] = True
        tsrc, tdst, tsrv = [], [], []
        itf_inb = [self._interface_ref(rule.in_interface)] if rule.in_interface else []
        itf_outb = (
            [self._interface_ref(rule.out_interface)] if rule.out_interface else []
        )
        if rule.in_interface_negated and itf_inb:
            negations['itf_inb'] = True
        if rule.out_interface_negated and itf_outb:
            negations['itf_outb'] = True

        translated = self._address_refs(rule.nat_addresses, '', problems)
        action = rule.action
        if action == 'snat':
            tsrc = translated
            if rule.nat_ports:
                tsrv = self._nat_port(rule, problems, source=True)
        elif action == 'masquerade':
            # The address of the interface the packet leaves through; a
            # negated interface ("oifname != lo", firewalld) names none.
            if itf_outb and not negations.get('itf_outb'):
                tsrc = list(itf_outb)
            else:
                tsrc = [self.fw_path]
            # MASQUERADE rather than SNAT to the address the interface has
            # when the script runs, as the original did.
            out['options']['ipt_use_masq'] = True
            if rule.nat_ports:
                problems.append('masquerade to ports')
        elif action == 'dnat':
            tdst = translated
            if rule.nat_ports:
                tsrv = self._nat_port(rule, problems, source=False)
            if chain.hook == 'output' and not osrc:
                osrc = [self.fw_path]
        elif action == 'redirect':
            tdst = [self.fw_path]
            if rule.nat_ports:
                tsrv = self._nat_port(rule, problems, source=False)
        elif action in ('accept', 'return'):
            pass  # no translation
        elif action == 'jump':
            target = context.chain_names.get(rule.jump_target)
            if target is None:
                problems.append(f'jump to the unknown chain {rule.jump_target}')
            else:
                out['action'] = 'Branch'
                out['options']['branch_id'] = self._rule_set_path('NAT', target)
        else:
            problems.append(f'NAT action {action}')

        for slot, refs in (
            ('osrc', osrc),
            ('odst', odst),
            ('osrv', osrv),
            ('tsrc', tsrc),
            ('tdst', tdst),
            ('tsrv', tsrv),
            ('itf_inb', itf_inb),
            ('itf_outb', itf_outb),
        ):
            if refs:
                out[slot] = refs
        if negations:
            out['negations'] = negations
        self._finish(out, rule, problems)
        return [out]

    def _nat_port(self, rule, problems, source):
        protocols = [s.protocol for s in rule.services if s.protocol in ('tcp', 'udp')]
        if len(protocols) != 1:
            problems.append('a translated port without exactly one of tcp or udp')
            return []
        service = Service(protocol=protocols[0])
        if source:
            service.src_ports = [rule.nat_ports]
        else:
            service.dst_ports = [rule.nat_ports]
        return [self._service_ref(service, rule.family)]

    # -- shared --

    def _finish(self, out, rule, problems, blocking=False):
        """Count the rule, and mark it where it could not be carried over.

        A rule that is not carried over exactly fails closed.  One that
        lets traffic through is imported disabled: without it less passes.
        One that blocks is imported active without what could not be
        carried over: with fewer conditions it matches more, so it blocks
        more, never less.  Disabling it instead would let through what
        the original stopped.  Both are colored and say so.
        """
        comment_lines = []
        if rule.comment:
            comment_lines.append(rule.comment)
        where = f'line {rule.line}' if rule.line else rule.raw.split(':', 1)[0]
        if problems and blocking:
            self.widened_rules += 1
            out['options']['color'] = UNSUPPORTED_COLOR
            comment_lines.append(
                'Imported without: ' + '; '.join(problems) + '. It blocks more '
                'than the original rule did.'
            )
            comment_lines.append(f'Original: {rule.raw}')
            self.messages.append(
                (
                    'warning',
                    f'{where}: imported without '
                    + '; '.join(problems)
                    + ', so it blocks more than the original',
                )
            )
        elif problems:
            self.unsupported_rules += 1
            out['options']['disabled'] = True
            out['options']['color'] = UNSUPPORTED_COLOR
            comment_lines.append('Not imported: ' + '; '.join(problems) + '.')
            comment_lines.append(f'Original: {rule.raw}')
            self.messages.append(
                ('warning', f'{where}: imported disabled: ' + '; '.join(problems))
            )
        else:
            self.imported_rules += 1
        if comment_lines:
            out['comment'] = '\n'.join(comment_lines)

    def _established(self, rule):
        family = 6 if rule.family == 6 else 4
        path = self.existing.established.get(family)
        if path is not None:
            return path
        if ('established', family) in self.objects:
            return self.objects[('established', family)][0]
        service = {
            'type': 'CustomService',
            'name': 'ESTABLISHED',
            'codes': {
                'iptables': '-m state --state ESTABLISHED,RELATED',
                'nftables': 'ct state established,related',
            },
        }
        return self._add_object(('established', family), service)

    def _state_service(self, states):
        signature = ('state', frozenset(states))
        if signature in self.objects:
            return self.objects[signature][0]
        names = sorted(states)
        service = {
            'type': 'CustomService',
            'name': self._unique_name('state ' + ','.join(n.upper() for n in names)),
            'codes': {
                'iptables': '-m conntrack --ctstate '
                + ','.join(n.upper() for n in names),
                'nftables': 'ct state ' + ','.join(names),
            },
        }
        return self._add_object(('state', frozenset(states)), service)

    def _user_service(self, user):
        signature = ('user', user)
        if signature in self.objects:
            return self.objects[signature][0]
        existing = self.existing.by_signature.get(signature)
        if existing is not None:
            return existing
        service = {
            'type': 'UserService',
            'name': self._unique_name(f'user {user}'),
            'userid': user,
        }
        return self._add_object(signature, service)

    def _covers_firewall(self, addresses):
        """Whether one of *addresses* takes in an address of the firewall."""
        for address in addresses:
            low, sep, high = address.text.partition('-')
            try:
                if sep:
                    first = ipaddress.ip_address(low)
                    last = ipaddress.ip_address(high)
                    covers = [
                        h
                        for h in self.fw_hosts
                        if h.version == first.version and first <= h <= last
                    ]
                else:
                    network = ipaddress.ip_network(address.text, strict=False)
                    covers = [
                        h
                        for h in self.fw_hosts
                        if h.version == network.version and h in network
                    ]
            except ValueError:
                continue
            if covers:
                return True
        return False

    def _address_refs(self, addresses, set_name, problems):
        refs = []
        if set_name:
            refs.append(self._set_ref(set_name, problems))
        for address in addresses:
            try:
                refs.append(self._address_ref(address))
            except ValueError:
                problems.append(f'address {address.text}')
        return [r for r in refs if r]

    def _set_ref(self, name, problems):
        ruleset_sets = self._current_sets
        address_set = ruleset_sets.get(name)
        if address_set is None:
            problems.append(f'set @{name}')
            return ''
        if not address_set.addresses:
            # An empty set in a listing is usually one the script fills
            # while it runs - an address table, a DNS name, the address of
            # a dynamic interface.  As an empty group it would match
            # nothing, which is not what the rule did.
            problems.append(f'set @{name} is empty in the listing')
            return ''
        signature = ('set', name)
        if signature in self.objects:
            return self.objects[signature][0]
        members = [self._address_ref(a) for a in address_set.addresses]
        group = {
            'type': 'ObjectGroup',
            'name': self._unique_name(name),
            'comment': f'nftables set @{name}',
            'members': sorted(members),
        }
        return self._add_object(signature, group)

    def _address_ref(self, address):
        signature = address_signature(address)
        existing = self.existing.by_signature.get(signature)
        if existing is not None:
            return existing
        if signature in self.objects:
            return self.objects[signature][0]
        kind = signature[0]
        if kind == 'range':
            obj = {
                'type': 'AddressRange',
                'name': self._unique_name(f'range-{signature[1]}-{signature[2]}'),
                'start_address': {'address': signature[1]},
                'end_address': {'address': signature[2]},
            }
        else:
            net = ipaddress.ip_network(signature[1], strict=False)
            v6 = net.version == 6
            if kind == 'host':
                type_name = 'IPv6' if v6 else 'IPv4'
                name = f'h-{net.network_address}'
            else:
                type_name = 'NetworkIPv6' if v6 else 'Network'
                name = f'net-{net}'
            netmask = str(net.prefixlen) if v6 else str(net.netmask)
            obj = {
                'type': type_name,
                'name': self._unique_name(name),
                'inet_addr_mask': {
                    'address': str(net.network_address),
                    'netmask': netmask,
                },
            }
        return self._add_object(signature, obj)

    def _service_refs(self, services, family, problems):
        refs = []
        for service in services:
            for single in _split_service(service):
                try:
                    refs.append(self._service_ref(single, family))
                except ValueError as exc:
                    problems.append(str(exc))
        return refs

    def _service_ref(self, service, family):
        protocol = service.protocol
        if protocol in ('tcp', 'udp'):
            src = (
                (service.src_ports[0].low, service.src_ports[0].high)
                if service.src_ports
                else (0, 0)
            )
            dst = (
                (service.dst_ports[0].low, service.dst_ports[0].high)
                if service.dst_ports
                else (0, 0)
            )
            signature = service_signature(
                protocol,
                src,
                dst,
                service.tcp_flags_set,
                service.tcp_flags_mask,
            )
        elif protocol in ('icmp', 'icmpv6'):
            code = -1 if service.icmp_code is None else service.icmp_code
            icmp_type = -1 if service.icmp_type is None else service.icmp_type
            signature = service_signature(protocol, icmp=(icmp_type, code))
        else:
            number = _protocol_number(protocol)
            if number is None:
                raise ValueError(f'protocol {protocol}')
            signature = service_signature(str(number))
        existing = self.existing.by_signature.get(signature)
        if existing is not None:
            return existing
        if signature in self.objects:
            return self.objects[signature][0]
        return self._add_object(
            signature, _service_object(signature, self._unique_name)
        )

    def _interface_ref(self, name):
        if name not in self.interfaces and self.interface_addresses.get(name):
            self.interfaces[name] = {
                'name': name,
                'data': {},
                'addresses': [
                    _interface_address(name, index, address)
                    for index, address in enumerate(self.interface_addresses[name])
                ],
            }
        elif name not in self.interfaces:
            # A ruleset does not say which addresses the machine has.  A
            # dynamic interface is the one that matches whatever address it
            # carries when the script runs, the way the imported rule
            # matched it; an unnumbered one would contribute no address
            # to a rule naming the firewall, and the rule would be left
            # out.
            self.interfaces[name] = {
                'name': name,
                'data': {'dyn': name != 'lo'},
            }
            if name == 'lo':
                self.interfaces[name]['addresses'] = [
                    {
                        'type': 'IPv4',
                        'name': 'lo-ip',
                        'inet_addr_mask': {
                            'address': '127.0.0.1',
                            'netmask': '255.0.0.0',
                        },
                    }
                ]
        return f'{self.fw_path}/Interface:{escape_obj_name(name)}'

    def _add_object(self, signature, obj):
        if signature in self.objects:
            # A second object for one signature would leave the rules that
            # name the first one pointing at nothing.
            raise RuntimeError(f'object {signature} created twice')
        path = self.path_for(obj['type'], obj['name'])
        self.objects[signature] = (path, obj)
        return path

    def _unique_name(self, name):
        candidate = name
        n = 2
        while candidate in self.names:
            candidate = f'{name} ({n})'
            n += 1
        self.names.add(candidate)
        return candidate


class _TableContext:
    def __init__(
        self, ruleset, table, rs_type, chain_names, ipv4, ipv6, empty_chains=()
    ):
        self.ruleset = ruleset
        self.table = table
        self.rs_type = rs_type
        self.chain_names = chain_names
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.empty_chains = set(empty_chains)
        self.extra_rule_sets = []


_AUTOMATIC_LABELS = {
    'established': 'accept established and related packets',
    'log': 'log invalid packets',
    'drop': 'drop invalid packets',
}


def _is_plain(rule: Rule, allow_limit=False):
    """Whether *rule* matches on its connection state and nothing else."""
    return (
        not rule.src
        and not rule.dst
        and not rule.src_set
        and not rule.dst_set
        and not rule.in_interface
        and not rule.out_interface
        and not rule.services
        and not rule.user
        and not rule.unsupported
        and (allow_limit or not rule.limit_rate)
    )


def _automatic_prefix(rules):
    """The automatic rules a chain starts with, as (kind, rule) pairs."""
    prefix = []
    index = 0
    if (
        index < len(rules)
        and _is_plain(rules[index])
        and rules[index].states == {'established', 'related'}
        and rules[index].action == 'accept'
        and not rules[index].log
    ):
        prefix.append(('established', rules[index]))
        index += 1
    if (
        index < len(rules)
        and _is_plain(rules[index], allow_limit=True)
        and rules[index].states == {'invalid'}
        and rules[index].action == 'log'
    ):
        prefix.append(('log', rules[index]))
        index += 1
    if (
        index < len(rules)
        and _is_plain(rules[index])
        and rules[index].states == {'invalid'}
        and rules[index].action == 'drop'
        and not rules[index].log
    ):
        prefix.append(('drop', rules[index]))
    elif prefix and prefix[-1][0] == 'log':
        # A log without the drop behind it is not the option.
        prefix.pop()
    return prefix


_POLICY_HOOKS = ('input', 'forward', 'output')

# The longest chain name iptables takes, and what is left of it for a NAT
# rule set once the iptables compiler has put "_POSTROUTING" behind it.
_CHAIN_NAME_LIMIT = 28
_NAT_NAME_LIMIT = 16
_NAT_HOOKS = ('prerouting', 'input', 'output', 'postrouting')

_HOOK_ORDER = {
    'prerouting': 0,
    'input': 1,
    'forward': 2,
    'output': 3,
    'postrouting': 4,
}


def _jumps_into(rule: Rule, chains, goto=False):
    # A jump that logs on its way does something; a goto into an empty
    # chain returns from the calling one, which counts only where every
    # rule of that chain does nothing either.
    return (
        rule.action == 'jump'
        and (goto or not rule.goto)
        and not rule.log
        and rule.jump_target in chains
    )


def _empty_chains(table):
    """The regular chains of *table* that hold nothing but jumps into such.

    A goto counts here as well: a chain whose rules all go to empty chains
    returns whatever a packet matches.
    """
    empty: set = set()
    changed = True
    while changed:
        changed = False
        for chain in table.chains.values():
            if chain.hook or chain.name in empty:
                continue
            if all(_jumps_into(rule, empty, goto=True) for rule in chain.rules):
                empty.add(chain.name)
                changed = True
    return empty


def _goto_return(branch):
    """The rule after a branch that makes it a goto.

    A goto jumps without coming back: when the chain it went to runs out,
    the packet continues in the chain that called this one, or meets the
    policy of a base chain.  A rule set FirewallFabrik branches into comes
    back, so the same match returns at once - which is where a goto would
    have gone.  In a NAT rule set the end of the match is "no translation".
    """
    rule = {
        key: value
        for key, value in branch.items()
        if key not in ('action', 'options', 'comment', 'position')
    }
    options = {'stateless': True}
    if branch.get('options', {}).get('disabled'):
        options['disabled'] = True
        options['color'] = UNSUPPORTED_COLOR
    rule['options'] = options
    if branch['type'] == 'PolicyRule':
        rule['action'] = 'Return'
    else:
        rule['action'] = 'Translate'
    rule['comment'] = 'Returns after the branch above, which was a goto.'
    return rule


def _single_host(address):
    """Whether *address* is one address rather than a network or a range.

    A broadcast or multicast address stays in the rule that names it:
    FirewallFabrik counts it as the firewall's, and in a rule set a rule
    branches into it would be taken out of the rule as "the firewall".
    """
    return '-' not in address.text and '/' not in address.text


def _local_host(address):
    """The address, if *address* is one host a machine can have."""
    if '-' in address.text or '/' in address.text:
        return ''
    ip = ipaddress.ip_address(address.text)
    if ip.is_multicast or ip.is_unspecified or str(ip) == '255.255.255.255':
        return ''
    return str(ip)


def _interface_address(interface, index, address):
    """The address object of an interface, from "192.0.2.1/24"."""
    iface = ipaddress.ip_interface(address)
    v6 = iface.version == 6
    suffix = f'-{index}' if index else ''
    return {
        'type': 'IPv6' if v6 else 'IPv4',
        'name': f'{interface}-ip{"6" if v6 else ""}{suffix}',
        'inet_addr_mask': {
            'address': str(iface.ip),
            'netmask': str(iface.network.prefixlen) if v6 else str(iface.netmask),
        },
    }


def parse_ip_addr_json(text):
    """Read ``ip -j addr``: interface name -> ["192.0.2.1/24", ...].

    Link-local IPv6 addresses are left out: every interface has one, and
    a rule naming the firewall would match each of them.
    """
    import json

    result = {}
    for link in json.loads(text or '[]'):
        name = link.get('ifname')
        if not name:
            continue
        addresses = []
        for info in link.get('addr_info', []):
            if info.get('family') not in ('inet', 'inet6'):
                continue
            if info.get('scope') == 'link':
                continue
            addresses.append(f'{info.get("local")}/{info.get("prefixlen")}')
        result[name] = addresses
    return result


def _same_match(a: Rule, b: Rule):
    """Whether two rules match the same packets, leaving their actions aside."""
    fields = (
        'family',
        'src',
        'src_negated',
        'src_set',
        'dst',
        'dst_negated',
        'dst_set',
        'in_interface',
        'in_interface_negated',
        'out_interface',
        'out_interface_negated',
        'services',
        'services_negated',
        'states',
    )
    return all(getattr(a, f) == getattr(b, f) for f in fields)


def _split_service(service):
    """One :class:`Service` per object: a list of port ranges is a union."""
    if service.protocol not in ('tcp', 'udp'):
        yield service
        return
    sources = service.src_ports or [None]
    destinations = service.dst_ports or [None]
    for src in sources:
        for dst in destinations:
            yield Service(
                protocol=service.protocol,
                src_ports=[src] if src else [],
                dst_ports=[dst] if dst else [],
                tcp_flags_mask=service.tcp_flags_mask,
                tcp_flags_set=service.tcp_flags_set,
            )


def _protocol_number(protocol):
    if protocol.isdigit():
        return int(protocol)
    try:
        return socket.getprotobyname(protocol)
    except OSError:
        return None


def _range_text(low, high):
    return str(low) if low == high else f'{low}-{high}'


def _service_object(signature, unique_name):
    protocol = signature[0]
    if protocol in ('tcp', 'udp'):
        _proto, src, dst, mask, flags = signature
        parts = [protocol]
        if src != (0, 0):
            parts.append(f'sport {_range_text(*src)}')
        if dst != (0, 0):
            parts.append(f'dport {_range_text(*dst)}')
        if mask:
            parts.append(
                'flags '
                + ','.join(f for f in _FLAG_NAMES if f in flags)
                + '/'
                + ','.join(f for f in _FLAG_NAMES if f in mask)
            )
        obj = {
            'type': 'TCPService' if protocol == 'tcp' else 'UDPService',
            'name': unique_name(
                ' '.join(parts) if len(parts) > 1 else f'all {protocol}'
            ),
        }
        if src != (0, 0):
            obj['src_range_start'], obj['src_range_end'] = src
        if dst != (0, 0):
            obj['dst_range_start'], obj['dst_range_end'] = dst
        if protocol == 'tcp' and mask:
            obj['tcp_flags'] = {f: f in flags for f in _FLAG_NAMES}
            obj['tcp_flags_masks'] = {f: f in mask for f in _FLAG_NAMES}
        return obj
    if protocol in ('icmp', 'icmpv6'):
        icmp_type, code = signature[1]
        label = 'any' if icmp_type == -1 else str(icmp_type)
        if code != -1:
            label += f'/{code}'
        return {
            'type': 'ICMPService' if protocol == 'icmp' else 'ICMP6Service',
            'name': unique_name(f'{protocol} {label}'),
            'data': {'type': str(icmp_type), 'code': str(code)},
        }
    number = signature[1]
    return {
        'type': 'IPService',
        'name': unique_name(f'ip proto {number}'),
        'named_protocols': {'protocol_num': str(number)},
    }


def address_from_object(obj):
    """The :class:`Address` an address object of the data file stands for."""
    from firewallfabrik.core import objects

    if isinstance(obj, objects.AddressRange):
        start = (obj.start_address or {}).get('address')
        end = (obj.end_address or {}).get('address')
        if not start or not end:
            return None
        return Address(family=0, text=f'{start}-{end}')
    mask = obj.inet_addr_mask or {}
    address = mask.get('address')
    netmask = mask.get('netmask')
    if not address:
        return None
    if isinstance(obj, (objects.IPv4, objects.IPv6)):
        return Address(family=0, text=address)
    if netmask is None:
        return None
    return Address(family=0, text=f'{address}/{netmask}')
