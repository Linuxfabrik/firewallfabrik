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

"""Read the output of ``iptables-save`` and ``ip6tables-save``.

The format is line based: ``*table`` opens a table, ``:CHAIN POLICY
[packets:bytes]`` declares a chain, ``-A CHAIN ...`` appends a rule and
``COMMIT`` closes the table.  Each rule is the command line that would
have created it, which ``shlex`` splits the way the shell would - the
extensions quote a string that holds a space or a quote with
``xtables_save_string``, which writes the shell's own escapes.

The options are the ones the extensions' ``save`` functions write, not
everything ``iptables`` accepts on its command line: ``iptables-save``
prints an ICMP type as a number (``icmp_save`` in
``extensions/libipt_icmp.c``), a rate as ``N/sec``, ``/min``, ``/hour`` or
``/day`` (``print_rate`` in ``libxt_limit.c``) and a log level as a
number (``LOG_save`` in ``libxt_LOG.c``).  Verified against the iptables
sources of the netfilter tree.  An option this module does not know is
not guessed at: the rule is kept and marked, which is what Firewall
Builder's importer does, and unlike ferm's ``import-ferm``, which stops
at the first one.
"""

import ipaddress
import re
import shlex
import socket

from firewallfabrik.importer._model import (
    Address,
    Chain,
    PortRange,
    Rule,
    Ruleset,
    Service,
    Table,
)

# The tables a FirewallFabrik firewall says something about.  mangle,
# raw and security hold marks, notrack and SELinux contexts, which the
# importer does not model; they are reported rather than half imported.
_IMPORTED_TABLES = ('filter', 'nat')

_SKIPPED_TABLES = {
    'mangle': 'FirewallFabrik builds it from the marking and classification '
    'options of policy rules.',
    'raw': 'FirewallFabrik writes no rules of its own there.',
    'security': 'FirewallFabrik writes no rules of its own there.',
}

_BUILTIN_HOOKS = {
    'INPUT': 'input',
    'FORWARD': 'forward',
    'OUTPUT': 'output',
    'PREROUTING': 'prerouting',
    'POSTROUTING': 'postrouting',
}

_RATE_UNITS = {
    'sec': 'second',
    'second': 'second',
    'min': 'minute',
    'minute': 'minute',
    'hour': 'hour',
    'day': 'day',
}

# syslog levels, the numbers LOG_save writes (sys/syslog.h).
_LOG_LEVELS = {
    '0': 'emerg',
    '1': 'alert',
    '2': 'crit',
    '3': 'error',
    '4': 'warning',
    '5': 'notice',
    '6': 'info',
    '7': 'debug',
}

_TCP_FLAGS = ('fin', 'syn', 'rst', 'psh', 'ack', 'urg')

# The ICMP type names iptables accepts on its command line
# (extensions/libxt_icmp.h), for a file written by hand; iptables-save
# itself writes numbers.  A name without a code matches every code.
_ICMP_NAMES = {
    'any': (None, None),
    'echo-reply': (0, None),
    'pong': (0, None),
    'destination-unreachable': (3, None),
    'network-unreachable': (3, 0),
    'host-unreachable': (3, 1),
    'protocol-unreachable': (3, 2),
    'port-unreachable': (3, 3),
    'fragmentation-needed': (3, 4),
    'source-route-failed': (3, 5),
    'network-unknown': (3, 6),
    'host-unknown': (3, 7),
    'network-prohibited': (3, 9),
    'host-prohibited': (3, 10),
    'TOS-network-unreachable': (3, 11),
    'TOS-host-unreachable': (3, 12),
    'communication-prohibited': (3, 13),
    'host-precedence-violation': (3, 14),
    'precedence-cutoff': (3, 15),
    'source-quench': (4, None),
    'redirect': (5, None),
    'network-redirect': (5, 0),
    'host-redirect': (5, 1),
    'TOS-network-redirect': (5, 2),
    'TOS-host-redirect': (5, 3),
    'echo-request': (8, None),
    'ping': (8, None),
    'router-advertisement': (9, None),
    'router-solicitation': (10, None),
    'time-exceeded': (11, None),
    'ttl-exceeded': (11, None),
    'ttl-zero-during-transit': (11, 0),
    'ttl-zero-during-reassembly': (11, 1),
    'parameter-problem': (12, None),
    'ip-header-bad': (12, 0),
    'required-option-missing': (12, 1),
    'timestamp-request': (13, None),
    'timestamp-reply': (14, None),
    'info-request': (15, None),
    'info-reply': (16, None),
    'address-mask-request': (17, None),
    'address-mask-reply': (18, None),
}
_ICMP6_NAMES = {
    'destination-unreachable': (1, None),
    'no-route': (1, 0),
    'communication-prohibited': (1, 1),
    'beyond-scope': (1, 2),
    'address-unreachable': (1, 3),
    'port-unreachable': (1, 4),
    'failed-policy': (1, 5),
    'reject-route': (1, 6),
    'packet-too-big': (2, None),
    'time-exceeded': (3, None),
    'ttl-exceeded': (3, None),
    'ttl-zero-during-transit': (3, 0),
    'ttl-zero-during-reassembly': (3, 1),
    'parameter-problem': (4, None),
    'bad-header': (4, 0),
    'unknown-header-type': (4, 1),
    'unknown-option': (4, 2),
    'echo-request': (128, None),
    'ping': (128, None),
    'echo-reply': (129, None),
    'pong': (129, None),
    'mld-listener-query': (130, None),
    'mld-listener-report': (131, None),
    'mld-listener-done': (132, None),
    'mld-listener-reduction': (132, None),
    'router-solicitation': (133, None),
    'router-advertisement': (134, None),
    'neighbour-solicitation': (135, None),
    'neighbor-solicitation': (135, None),
    'neighbour-advertisement': (136, None),
    'neighbor-advertisement': (136, None),
    'redirect': (137, None),
}

# The spellings of a protocol the tools write, mapped to the one the
# model uses.  iptables-save writes the name /etc/protocols gives it, which
# for ICMPv6 is "ipv6-icmp", and a number where it has none.
_PROTOCOL_NAMES = {
    '1': 'icmp',
    '6': 'tcp',
    '17': 'udp',
    '58': 'icmpv6',
    'icmp6': 'icmpv6',
    'ipv6-icmp': 'icmpv6',
}

_HEADER_RE = re.compile(r'^#\s*Generated by (ip6?tables)(?:-\w+)?-save v(\S+)')


def parse_iptables_save(text, family=None):
    """Parse *text*, the output of iptables-save or ip6tables-save.

    *family* is 4 or 6; without it the header line written by the tool
    decides, and an input without one is read as IPv4.
    """
    ruleset = Ruleset(source='iptables')
    family = family or _family_from_header(text) or 4

    for match in _HEADER_RE.finditer(text):
        ruleset.version = match.group(2)
        break

    table = None
    skipped_rules = 0
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('*'):
            table = Table(name=line[1:], kind=line[1:], family=family)
            skipped_rules = 0
            if table.name in _IMPORTED_TABLES:
                ruleset.tables.append(table)
            continue
        if line == 'COMMIT':
            if (
                table is not None
                and table.name not in _IMPORTED_TABLES
                and skipped_rules
            ):
                ruleset.messages.append(
                    (
                        'warning',
                        f'The {table.name} table is not imported '
                        f'({skipped_rules} rules): {_SKIPPED_TABLES.get(table.name, "")}',
                    )
                )
            table = None
            continue
        if table is None:
            ruleset.messages.append(
                ('error', f'Line {number}: outside of a table: {line}')
            )
            continue
        if table.name not in _IMPORTED_TABLES:
            skipped_rules += line.startswith(('-A ', '['))
            continue
        if line.startswith(':'):
            _parse_chain_line(table, line)
            continue
        # iptables-save -c writes the counters in front of the rule.
        line = re.sub(r'^\[\d+:\d+\]\s+', '', line)
        if line.startswith('-A '):
            _parse_rule_line(ruleset, table, line, number)
            continue
        ruleset.messages.append(
            ('error', f'Line {number}: not understood, ignored: {line}')
        )
    return ruleset


def _family_from_header(text):
    match = _HEADER_RE.search(text)
    if match is None:
        return None
    return 6 if match.group(1) == 'ip6tables' else 4


def _parse_chain_line(table, line):
    # ":INPUT ACCEPT [0:0]" or ":user-chain - [0:0]"
    parts = line[1:].split()
    name = parts[0]
    policy = parts[1].lower() if len(parts) > 1 and parts[1] != '-' else ''
    hook = _BUILTIN_HOOKS.get(name, '') if policy else ''
    table.chains.setdefault(name, Chain(name=name, hook=hook, policy=policy))


def _parse_rule_line(ruleset, table, line, number):
    try:
        tokens = shlex.split(line)
    except ValueError as exc:
        ruleset.messages.append(
            ('error', f'Line {number}: cannot be split into words ({exc}): {line}')
        )
        return
    chain_name = tokens[1]
    chain = table.chains.setdefault(chain_name, Chain(name=chain_name))
    rule = Rule(raw=line, line=number, family=table.family)
    _RuleParser(rule, table, tokens[2:]).parse()
    chain.rules.append(rule)


class _RuleParser:
    """Walk the options of one rule and fill a :class:`Rule`."""

    def __init__(self, rule, table, tokens):
        self.rule = rule
        self.table = table
        self.tokens = tokens
        self.pos = 0
        self.negate = False
        self.protocol = ''
        self.protocol_negated = False
        self.service = None  # the Service the port and flag options fill
        self.target = ''
        self.module = ''  # the last -m, to name an option nobody knows
        self.extra_services = []  # the source half of multiport --ports

    def parse(self):
        while self.pos < len(self.tokens):
            word = self._next()
            if word == '!':
                self.negate = True
                continue
            handler = _OPTION_HANDLERS.get(word)
            if handler is None:
                prefix = f'-m {self.module} ' if self.module else ''
                self._unsupported(f'{prefix}{word}')
                self._skip_values()
            else:
                handler(self)
            self.negate = False
        self._finish()

    # -- token helpers --

    def _next(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _value(self):
        if self.pos >= len(self.tokens):
            return ''
        value = self._next()
        if value == '!' and self.pos < len(self.tokens):
            # The form before iptables 1.4.3, "-s ! 192.0.2.1", which a
            # hand-kept file may still have; Firewall Builder's importer
            # rewrites the new form into it (IPTImporterRun.cpp).
            self.negate = True
            value = self._next()
        return value

    def _skip_values(self):
        # The values of an option nobody understood run up to the next
        # word that starts an option of its own.
        while self.pos < len(self.tokens) and not (
            self.tokens[self.pos].startswith('-') or self.tokens[self.pos] == '!'
        ):
            self.pos += 1

    def _unsupported(self, what):
        reason = f'{"negated " if self.negate else ""}{what}'
        if reason not in self.rule.unsupported:
            self.rule.unsupported.append(reason)

    # -- matches --

    def _address(self, value):
        try:
            if '-' in value:
                low, high = value.split('-', 1)
                ipaddress.ip_address(low)
                ipaddress.ip_address(high)
                return Address(family=self.table.family or 4, text=value)
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            self._unsupported(f'address {value}')
            return None
        if net.prefixlen == net.max_prefixlen:
            text = str(net.network_address)
        else:
            text = str(net)
        return Address(family=net.version, text=text)

    def opt_source(self):
        address = self._address(self._value())
        if address is not None:
            self.rule.src.append(address)
            self.rule.src_negated = self.negate

    def opt_destination(self):
        address = self._address(self._value())
        if address is not None:
            self.rule.dst.append(address)
            self.rule.dst_negated = self.negate

    def opt_src_range(self):
        address = self._address(self._value())
        if address is not None:
            self.rule.src.append(address)
            self.rule.src_negated = self.negate

    def opt_dst_range(self):
        address = self._address(self._value())
        if address is not None:
            self.rule.dst.append(address)
            self.rule.dst_negated = self.negate

    def opt_in_interface(self):
        self.rule.in_interface = _interface_name(self._value())
        self.rule.in_interface_negated = self.negate

    def opt_out_interface(self):
        self.rule.out_interface = _interface_name(self._value())
        self.rule.out_interface_negated = self.negate

    def opt_protocol(self):
        value = self._value().lower()
        self.protocol = _PROTOCOL_NAMES.get(value, value)
        self.protocol_negated = self.negate

    def opt_fragment(self):
        self._unsupported('-f (fragments)')

    def opt_module(self):
        # A module load says nothing by itself; its options do.
        self.module = self._value()

    def _service(self):
        if self.service is None:
            self.service = Service(protocol=self.protocol or 'tcp')
        return self.service

    def opt_sport(self):
        ports = _port_ranges(self._value(), self.protocol)
        if self.negate or ports is None:
            self._unsupported('source port')
            return
        self._service().src_ports.extend(ports)

    def opt_dport(self):
        ports = _port_ranges(self._value(), self.protocol)
        if self.negate or ports is None:
            self._unsupported('destination port')
            return
        self._service().dst_ports.extend(ports)

    def opt_ports(self):
        # multiport --ports: the source port or the destination port is in
        # the list, which is two services where a rule takes their union.
        ports = _port_ranges(self._value(), self.protocol)
        if self.negate or ports is None:
            self._unsupported('--ports')
            return
        self._service().dst_ports.extend(ports)
        self.extra_services.append(
            Service(protocol=self.protocol or 'tcp', src_ports=list(ports))
        )

    def opt_tcp_flags(self):
        mask = self._value()
        comp = self._value()
        if self.negate:
            self._unsupported('--tcp-flags')
            return
        service = self._service()
        service.tcp_flags_mask = _tcp_flag_set(mask)
        service.tcp_flags_set = _tcp_flag_set(comp)

    def opt_syn(self):
        if self.negate:
            self._unsupported('--syn')
            return
        service = self._service()
        service.tcp_flags_mask = frozenset({'syn', 'rst', 'ack', 'fin'})
        service.tcp_flags_set = frozenset({'syn'})

    def opt_icmp_type(self):
        value = self._value()
        if self.negate:
            self._unsupported('ICMP type')
            return
        names = _ICMP6_NAMES if self.protocol == 'icmpv6' else _ICMP_NAMES
        if value in names:
            icmp_type, icmp_code = names[value]
        else:
            type_, _, code = value.partition('/')
            if not type_.isdigit() or (code and not code.isdigit()):
                self._unsupported(f'ICMP type {value}')
                return
            icmp_type, icmp_code = int(type_), int(code) if code else None
        if icmp_type is None:
            return
        service = self._service()
        service.icmp_type = icmp_type
        service.icmp_code = icmp_code

    def opt_state(self):
        value = self._value()
        if self.negate:
            self._unsupported('connection state')
            return
        self.rule.states = frozenset(s.lower() for s in value.split(','))

    def opt_limit(self):
        value = self._value()
        rate, _, unit = value.partition('/')
        unit = _RATE_UNITS.get(unit or 'hour')
        if self.negate or not rate.isdigit() or unit is None:
            self._unsupported(f'--limit {value}')
            return
        self.rule.limit_rate = int(rate)
        self.rule.limit_unit = unit

    def opt_hashlimit(self):
        # FirewallFabrik writes a rule's own rate limit as a hashlimit
        # without a mode: one bucket for the rule.  With a mode the bucket
        # is per address or port, which is not a rule option here.
        option = self.tokens[self.pos - 1]
        value = self._value()
        rate, _, unit = value.partition('/')
        unit = _RATE_UNITS.get(unit or 'second')
        if self.negate or not rate.isdigit() or unit is None:
            self._unsupported(f'{option} {value}')
            return
        self.rule.limit_rate = int(rate)
        self.rule.limit_unit = unit
        self.rule.limit_over = option == '--hashlimit-above'

    def opt_hashlimit_name(self):
        self._value()  # names the bucket, which FirewallFabrik names itself

    def opt_limit_burst(self):
        value = self._value()
        if value.isdigit():
            self.rule.limit_burst = int(value)

    def opt_uid_owner(self):
        value = self._value()
        if self.negate:
            self._unsupported('negated --uid-owner')
            return
        self.rule.user = value

    def opt_comment(self):
        self.rule.comment = self._value()

    # -- targets --

    def opt_jump(self):
        self.target = self._value()

    def opt_goto(self):
        self.target = self._value()
        self.rule.goto = True

    def opt_reject_with(self):
        self.rule.reject_with = self._value()

    def opt_queue_num(self):
        # NFQUEUE_save always writes the queue number; FirewallFabrik's
        # Pipe action is queue 0, any other is a condition it cannot hold.
        value = self._value()
        if value != '0':
            self._unsupported(f'--queue-num {value}')

    def opt_log_prefix(self):
        self.rule.log_prefix = self._value()

    def opt_log_level(self):
        value = self._value()
        self.rule.log_level = _LOG_LEVELS.get(value, value)

    def opt_log_flag(self):
        # --log-tcp-sequence and the like are firewall-wide settings in
        # FirewallFabrik, not rule options.
        self._unsupported(f'{self.tokens[self.pos - 1]}')

    def opt_to_source(self):
        self._nat_spec(self._value())

    def opt_to_destination(self):
        self._nat_spec(self._value())

    def opt_to_ports(self):
        ports = _port_ranges(self._value().replace('-', ':'))
        if ports is None or len(ports) != 1:
            self._unsupported('--to-ports')
            return
        self.rule.nat_ports = ports[0]

    def _nat_spec(self, value):
        # "198.51.100.1", "198.51.100.1-198.51.100.9", ":1024-2048",
        # "198.51.100.1:80", "[2001:db8::1]:80" (libxt_NAT.c).
        address, port = value, ''
        if value.startswith('['):
            address, _, rest = value[1:].partition(']')
            port = rest.lstrip(':')
        elif value.count(':') == 1:
            address, port = value.split(':')
        if address:
            parsed = self._address(address)
            if parsed is None:
                return
            self.rule.nat_addresses.append(parsed)
        if port:
            ports = _port_ranges(port.replace('-', ':'))
            if ports is None or len(ports) != 1:
                self._unsupported(f'NAT port {port}')
                return
            self.rule.nat_ports = ports[0]

    def _finish(self):
        rule = self.rule
        if self.service is not None:
            rule.services.append(self.service)
            rule.services.extend(self.extra_services)
        elif self.protocol and self.protocol != 'all':
            rule.services.append(Service(protocol=self.protocol))
        if self.protocol_negated:
            if self.service is not None and (
                self.service.src_ports
                or self.service.dst_ports
                or self.service.icmp_type is not None
            ):
                rule.unsupported.append('negated protocol with ports or types')
            rule.services_negated = True
        target = self.target
        if target in ('ACCEPT', 'DROP', 'RETURN', 'REJECT'):
            rule.action = target.lower()
        elif target in ('NFQUEUE', 'QUEUE'):
            rule.action = 'queue'
        elif target == 'LOG':
            rule.action = 'log'
            rule.log = True
        elif target in ('SNAT', 'DNAT', 'MASQUERADE', 'REDIRECT'):
            rule.action = target.lower()
        elif target == '':
            rule.action = 'continue'
        elif target in self.table.chains or _looks_like_chain(target):
            rule.action = 'jump'
            rule.jump_target = target
        else:
            rule.action = 'continue'
            rule.unsupported.append(f'target {target}')


def _looks_like_chain(name):
    # Targets are upper case by convention (ACCEPT, MASQUERADE, CT);
    # a chain the table has not declared yet is anything else.
    return not name.isupper()


def _interface_name(value):
    # iptables spells a wildcard "eth+", FirewallFabrik stores "eth*".
    return value[:-1] + '*' if value.endswith('+') else value


def _tcp_flag_set(value):
    if value.upper() == 'ALL':
        return frozenset(_TCP_FLAGS)
    if value.upper() == 'NONE':
        return frozenset()
    return frozenset(flag.lower() for flag in value.split(','))


def _port_ranges(value, protocol=''):
    """Turn "22", "1024:65535", ":1023" or "22,80,8000:8080" into ranges.

    A name is looked up in the services database ("smtp"), which is what
    iptables does with one (xtables_parse_port).
    """
    ranges = []
    for part in value.split(','):
        low, sep, high = part.partition(':')
        low_port = _port_number(low, protocol) if low else 0
        high_port = _port_number(high, protocol) if high else None
        if low_port is None or (high and high_port is None):
            return None
        if high_port is None:
            high_port = 65535 if sep else low_port
        ranges.append(PortRange(low_port, high_port))
    return ranges


def _port_number(text, protocol):
    if text.isdigit():
        return int(text)
    try:
        return socket.getservbyname(
            text, protocol if protocol in ('tcp', 'udp') else None
        )
    except OSError:
        return None


_OPTION_HANDLERS = {
    '-s': _RuleParser.opt_source,
    '--source': _RuleParser.opt_source,
    '-d': _RuleParser.opt_destination,
    '--destination': _RuleParser.opt_destination,
    '--src-range': _RuleParser.opt_src_range,
    '--dst-range': _RuleParser.opt_dst_range,
    '-i': _RuleParser.opt_in_interface,
    '--in-interface': _RuleParser.opt_in_interface,
    '-o': _RuleParser.opt_out_interface,
    '--out-interface': _RuleParser.opt_out_interface,
    '-p': _RuleParser.opt_protocol,
    '--protocol': _RuleParser.opt_protocol,
    '-f': _RuleParser.opt_fragment,
    '--fragment': _RuleParser.opt_fragment,
    '-m': _RuleParser.opt_module,
    '--match': _RuleParser.opt_module,
    '--sport': _RuleParser.opt_sport,
    '--source-port': _RuleParser.opt_sport,
    '--sports': _RuleParser.opt_sport,
    '--source-ports': _RuleParser.opt_sport,
    '--dport': _RuleParser.opt_dport,
    '--destination-port': _RuleParser.opt_dport,
    '--dports': _RuleParser.opt_dport,
    '--destination-ports': _RuleParser.opt_dport,
    '--ports': _RuleParser.opt_ports,
    '--tcp-flags': _RuleParser.opt_tcp_flags,
    '--syn': _RuleParser.opt_syn,
    '--icmp-type': _RuleParser.opt_icmp_type,
    '--icmpv6-type': _RuleParser.opt_icmp_type,
    '--state': _RuleParser.opt_state,
    '--ctstate': _RuleParser.opt_state,
    '--limit': _RuleParser.opt_limit,
    '--limit-burst': _RuleParser.opt_limit_burst,
    '--hashlimit-upto': _RuleParser.opt_hashlimit,
    '--hashlimit-above': _RuleParser.opt_hashlimit,
    '--hashlimit-burst': _RuleParser.opt_limit_burst,
    '--hashlimit-name': _RuleParser.opt_hashlimit_name,
    '--comment': _RuleParser.opt_comment,
    '--uid-owner': _RuleParser.opt_uid_owner,
    '-j': _RuleParser.opt_jump,
    '--jump': _RuleParser.opt_jump,
    '-g': _RuleParser.opt_goto,
    '--goto': _RuleParser.opt_goto,
    '--reject-with': _RuleParser.opt_reject_with,
    '--log-prefix': _RuleParser.opt_log_prefix,
    '--queue-num': _RuleParser.opt_queue_num,
    '--log-level': _RuleParser.opt_log_level,
    '--log-tcp-sequence': _RuleParser.opt_log_flag,
    '--log-tcp-options': _RuleParser.opt_log_flag,
    '--log-ip-options': _RuleParser.opt_log_flag,
    '--log-uid': _RuleParser.opt_log_flag,
    '--log-macdecode': _RuleParser.opt_log_flag,
    '--to-source': _RuleParser.opt_to_source,
    '--to-destination': _RuleParser.opt_to_destination,
    '--to-ports': _RuleParser.opt_to_ports,
}
