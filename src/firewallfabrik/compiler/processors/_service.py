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

"""Service rule processors shared across platforms.

Corresponds to fwbuilder's ServiceRuleProcessors.cpp.
Provides the SeparateServiceObject base class and concrete subclasses
for splitting rules by service type, as well as service validation.
"""

from __future__ import annotations

from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import (
    CustomService,
    ICMPService,
    TagService,
    TCPService,
    UDPService,
    UserService,
)


class SeparateServiceObject(BasicRuleProcessor):
    """Base class for separating service objects that match a condition.

    For each service in the rule's service element that satisfies
    ``condition()``, creates a new rule with just that service.
    Remaining (non-matching) services stay in the original rule.

    Corresponds to C++ ``Compiler::separateServiceObject``.
    """

    def condition(self, srv) -> bool:
        """Return True if this service should be separated."""
        raise NotImplementedError

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        # Use srv for policy rules, osrv for NAT rules
        slot = 'srv' if rule.type == 'PolicyRule' else 'osrv'
        services = getattr(rule, slot)

        if len(services) <= 1:
            self.tmp_queue.append(rule)
            return True

        # Separate matching services into individual rules
        separated = []
        for srv in services:
            if self.condition(srv):
                r = rule.clone()
                setattr(r, slot, [srv])
                self.tmp_queue.append(r)
                separated.append(srv)

        # Remove separated services from the original
        remaining = [s for s in services if s not in separated]
        setattr(rule, slot, remaining)

        if remaining:
            self.tmp_queue.append(rule)

        return True


class SeparateSrcPort(SeparateServiceObject):
    """Separate TCP/UDP services that specify source ports.

    Services with source ports cannot be combined with destination-only
    services in multiport matching.

    Corresponds to C++ ``Compiler::separateSrcPort``.
    """

    def condition(self, srv) -> bool:
        if not isinstance(srv, (TCPService, UDPService)):
            return False
        srs = srv.src_range_start or 0
        sre = srv.src_range_end or 0
        if srs != 0 and sre == 0:
            sre = srs
        return srs != 0 or sre != 0


class SeparateSrcAndDstPort(SeparateServiceObject):
    """Separate TCP/UDP services that specify both source and destination ports.

    Corresponds to C++ ``Compiler::separateSrcAndDstPort``.
    """

    def condition(self, srv) -> bool:
        if not isinstance(srv, (TCPService, UDPService)):
            return False
        srs = srv.src_range_start or 0
        sre = srv.src_range_end or 0
        drs = srv.dst_range_start or 0
        dre = srv.dst_range_end or 0
        if srs != 0 and sre == 0:
            sre = srs
        if drs != 0 and dre == 0:
            dre = drs
        return (srs != 0 or sre != 0) and (drs != 0 or dre != 0)


class SeparateTCPWithFlags(SeparateServiceObject):
    """Separate TCP services with flag inspection.

    TCP services with flags (SYN, ACK, etc.) cannot be combined with
    other services in multiport matching.

    Corresponds to C++ ``Compiler::separateTCPWithFlags``.
    """

    def condition(self, srv) -> bool:
        if not isinstance(srv, TCPService):
            return False
        # Match fwbuilder's TCPService::inspectFlags() which returns true
        # only when actual TCP flag masks are set (not just all-false dicts
        # from the standard library).
        masks = srv.tcp_flags_masks
        if not masks:
            return False
        return any(masks.values())


class SeparateUserServices(SeparateServiceObject):
    """Separate UserService objects into individual rules.

    Corresponds to C++ ``Compiler::separateUserServices``.
    """

    def condition(self, srv) -> bool:
        return isinstance(srv, UserService)


class SeparateCustom(SeparateServiceObject):
    """Separate CustomService objects into individual rules.

    Corresponds to C++ ``Compiler::separateCustom``.
    """

    def condition(self, srv) -> bool:
        return isinstance(srv, CustomService)


class SeparateTagged(SeparateServiceObject):
    """Separate TagService objects into individual rules.

    Corresponds to C++ ``Compiler::separateTagged``.
    """

    def condition(self, srv) -> bool:
        return isinstance(srv, TagService)


class VerifyCustomServices(BasicRuleProcessor):
    """Verify that CustomService objects have code for the current platform.

    Corresponds to C++ ``Compiler::verifyCustomServices``.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        self.tmp_queue.append(rule)

        slot = 'srv' if rule.type == 'PolicyRule' else 'osrv'
        services = getattr(rule, slot)
        platform = self.compiler.my_platform_name()

        for srv in services:
            if isinstance(srv, CustomService):
                code = (srv.codes or {}).get(platform, '')
                if not code:
                    self.compiler.abort(
                        rule,
                        f"Custom service '{srv.name}' is not configured "
                        f"for the platform '{platform}'",
                    )

        return True


# The slots of a rule that hold services, per rule type.  A NAT rule names
# the service it matches on in ``osrv`` and the one it translates to in
# ``tsrv``; both reach a command line.
_SERVICE_SLOTS = {
    'PolicyRule': ('srv',),
    'NATRule': ('osrv', 'tsrv'),
}

# A port number is 16 bits.  iptables bounds it in `xtables_parse_port`
# (netfilter iptables libxtables/xtables.c) and nftables answers
# "Service out of range"; both editors bound the field, so only a
# hand-edited or corrupt data file can carry more.
MAX_PORT_NUMBER = 65535


def port_range_problem(srv) -> str:
    """Return why *srv* names a port range neither tool takes, or ``''``.

    A range whose end is below its start is refused outright.  iptables
    answers ``invalid portrange (min > max)`` for ``--dport`` and
    ``invalid portrange specified`` for ``-m multiport``, which stops the
    activation script with the built-in policies already at DROP;
    nftables answers ``Range negative size`` and refuses the **whole**
    ruleset, so the firewall never gets the new policy at all.  Both
    verified against iptables 1.8.11 and nft 1.1.6.

    Firewall Builder corrects the value in its editor instead
    (``TCPServiceDialog::applyChanges``, its bug #1695481, and the same
    in ``UDPServiceDialog``), so its compiler never has to ask.  A data
    file written by an older release, by another tool or by hand carries
    whatever it carries, which is why the question is asked here.
    """
    if not isinstance(srv, (TCPService, UDPService)):
        return ''
    for what, start, end in (
        ('source', srv.src_range_start or 0, srv.src_range_end or 0),
        ('destination', srv.dst_range_start or 0, srv.dst_range_end or 0),
    ):
        for port in (start, end):
            # A port number is 16 bits: `xtables_parse_port` bounds it at
            # UINT16_MAX ("invalid port/service `%s' specified") and
            # nftables answers "Service out of range".
            if not 0 <= port <= MAX_PORT_NUMBER:
                return f'names the {what} port {port}, which is not a port number'
        # An end of 0 is "no range", not "port 0": the printers write the
        # start alone for it.
        if end and start > end:
            return f'names the {what} port range {start}-{end}, which runs backwards'
    return ''


# An ICMP type and an ICMP code are one byte each in the header, and both
# tools bound them there: iptables reads the pair with
# `xtables_strtoui(str, ..., 0, 255)` and answers "Unknown ICMP type" or
# "Unknown ICMP code" (netfilter iptables extensions/libxt_icmp.h), which
# stops the activation script with the built-in policies already at DROP,
# and nftables answers "Value 300 exceeds valid range 0-255" and refuses
# the whole ruleset.  Both editors bound the field to -1..255, so only a
# hand-edited or foreign data file can carry more.
MAX_ICMP_TYPE = 255


def icmp_type_problem(srv) -> str:
    """Return why *srv* names an ICMP type or code neither tool takes.

    ``-1`` is the model's "any", which is what the print rules read the
    absence of the attribute as, so only a value above the byte the
    header has - or one that is no number at all - is a problem.
    """
    if not isinstance(srv, ICMPService):
        return ''
    codes = getattr(srv, 'codes', None) or srv.data or {}
    for what in ('type', 'code'):
        raw = codes.get(what, -1)
        if raw is None or raw == '':
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return f'names the ICMP {what} "{raw}", which is not a number'
        if value > MAX_ICMP_TYPE:
            return f'names the ICMP {what} {value}, and the header has one byte for it'
    return ''


class VerifyPortRanges(BasicRuleProcessor):
    """Leave out a rule whose service names a port range that runs backwards.

    The condition has no place in the generated command: writing the range
    the other way round would match traffic the administrator did not name,
    and leaving the ports off altogether would widen the rule to the whole
    protocol.  So the rule goes and the service is named, once per service.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in _SERVICE_SLOTS.get(rule.type, ('srv',)):
            for srv in getattr(rule, slot, None) or []:
                problem = port_range_problem(srv)
                if not problem:
                    continue
                self.compiler.error(
                    rule,
                    f'Service "{srv.name}" {problem}; iptables and nftables '
                    'both refuse it, so the rule is left out. Correct the '
                    'port range in the service object.',
                )
                return True

        self.tmp_queue.append(rule)
        return True


class VerifyIcmpTypes(BasicRuleProcessor):
    """Leave out a rule whose ICMP service names a type or code there is not.

    Dropping the type instead would widen the rule from one ICMP message
    to every one of them, so the rule goes and the service is named.  See
    ``icmp_type_problem`` for what each tool answers.
    """

    def process_next(self) -> bool:
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return False

        for slot in _SERVICE_SLOTS.get(rule.type, ('srv',)):
            for srv in getattr(rule, slot, None) or []:
                problem = icmp_type_problem(srv)
                if not problem:
                    continue
                self.compiler.error(
                    rule,
                    f'Service "{srv.name}" {problem}; iptables stops the '
                    'activation over it and nftables refuses the whole '
                    'ruleset, so the rule is left out. Correct the service '
                    'object.',
                )
                return True

        self.tmp_queue.append(rule)
        return True
