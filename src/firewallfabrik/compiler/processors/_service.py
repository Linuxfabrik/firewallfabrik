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
