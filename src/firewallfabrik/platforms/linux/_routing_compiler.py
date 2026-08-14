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

"""Linux routing compiler: generates 'ip route' commands.

Corresponds to fwbuilder's iptlib/routing_compiler_ipt.py.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._routing_compiler import RoutingCompiler
from firewallfabrik.compiler._rule_processor import RoutingRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    Begin,
    DropRuleWithEmptyRE,
    EmptyGroupsInRE,
    ExpandGroups,
    PrintTotalNumberOfRules,
    RecursiveGroupsInRE,
)
from firewallfabrik.core.objects import (
    Address,
    Cluster,
    Firewall,
    Host,
    Interface,
    IPv4,
    IPv6,
    MultiAddress,
    Network,
    NetworkIPv6,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


class RoutingCompilerLinux(RoutingCompiler):
    """Compiles routing rules into 'ip route' commands for Linux."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
    ) -> None:
        super().__init__(session, fw, ipv6_policy)
        self.ecmp_rules_buffer: dict[str, str] = {}
        self.ecmp_comments_buffer: dict[str, str] = {}

    def compile(self) -> None:
        banner = f" Compiling routing rules for '{self.fw.name}'"
        self.info(banner)

        self.add(Begin())
        self.add(PrintTotalNumberOfRules())

        # Same order as RoutingCompiler_ipt::compile(): validate what the
        # rule names, then expand it, then check what the expansion left.
        self.add(RecursiveGroupsInRE('check for recursive groups in RDst', 'rdst'))
        self.add(EmptyGroupsInRE('check for empty groups in RDst', 'rdst'))
        self.add(EmptyRGtwAndRItf('check if RGtw and RItf are both empty'))
        self.add(SingleAddressInRGtw('check that the gateway has one address'))
        self.add(RItfChildOfFw('check that RItf is an interface of this firewall'))

        self.add(ExpandGroups('expand groups'))
        self.add(ExpandMultipleAddressesInRouting('expand objects with addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        self.add(ValidateRoutingDestination('validate destination addresses'))
        self.add(ExpandAddressRangesInRDst('process address ranges'))
        self.add(EliminateDuplicatesInRDst('eliminate duplicates in RDst'))
        self.add(ConvertToAtomicForRDst('convert to atomic rules by destination'))

        self.add(RoutingPrintRule('generate ip route commands'))
        self.run_rule_processors()

    def epilog(self) -> None:
        """Output ECMP routing rules if any exist."""
        if self.ecmp_rules_buffer:
            for key, comment in self.ecmp_comments_buffer.items():
                self.output.write(comment)
                rule_cmd = self.ecmp_rules_buffer.get(key, '')
                if rule_cmd:
                    self.output.write(rule_cmd)
                    self.output.write('\n')


class EmptyRGtwAndRItf(RoutingRuleProcessor):
    """Report a rule that names neither a gateway nor an interface.

    ``ip route add <dst>`` without either is not a route the kernel can
    install.  Corresponds to ``RoutingCompiler::emptyRDstAndRItf``, which
    despite its name looks at RGtw and RItf.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.rgtw and not rule.ritf:
            self.compiler.error(
                rule,
                'The rule names neither a gateway nor an interface, so there '
                'is no route to install; the rule is left out',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class SingleAddressInRGtw(RoutingRuleProcessor):
    """Report a gateway object that carries more than one address.

    ``via`` takes exactly one next hop.  Corresponds to
    ``RoutingCompiler::singleAdressInRGtw``, which asks
    ``RuleElement::checkSingleIPAdress``.  Runs before the expansion, so
    the message can name the object the administrator picked rather than
    one of the addresses behind it.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        for obj in rule.rgtw:
            if _count_addresses(obj) > 1:
                self.compiler.error(
                    rule,
                    f'Object "{obj.name}" is used as the gateway but carries '
                    f'more than one address; the rule is left out',
                )
                return True

        self.tmp_queue.append(rule)
        return True


class RItfChildOfFw(RoutingRuleProcessor):
    """Report an interface that does not belong to this firewall.

    ``dev`` names a device on the box the script runs on.  An interface of
    another object compiles into a command that fails at activation.
    Corresponds to ``RoutingCompiler::rItfChildOfFw``, including its
    cluster case: an interface of a cluster the firewall is a member of
    counts as its own.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        for obj in rule.ritf:
            if not isinstance(obj, Interface):
                continue
            if self._belongs_to_firewall(obj):
                continue
            self.compiler.error(
                rule,
                f'Object "{obj.name}" is used as the interface but is not an '
                f'interface of this firewall; the rule is left out',
            )
            return True

        self.tmp_queue.append(rule)
        return True

    def _belongs_to_firewall(self, iface: Interface) -> bool:
        parent = _parent_host(iface)
        if parent is None:
            return False
        if parent.id == self.compiler.fw.id:
            return True
        # A cluster interface is the member's own interface once the cluster
        # is resolved, which this port does not do yet (#84).  Reporting it
        # would turn an unfinished feature into a compile error.
        return isinstance(parent, Cluster)


class ExpandMultipleAddressesInRouting(RoutingRuleProcessor):
    """Replace a host or firewall in RDst and RGtw with its addresses.

    The counterpart of ``ExpandMultipleAddresses`` in the policy pipeline.
    Without it the print rule sees an object it cannot render.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.compiler.expand_addr(rule, 'rdst')
        self.compiler.expand_addr(rule, 'rgtw')
        self.tmp_queue.append(rule)
        return True


class ValidateRoutingDestination(RoutingRuleProcessor):
    """Report a destination the generated script cannot write out.

    fwbuilder refuses a run-time ``AddressTable`` or ``DNSName`` here
    (``RoutingCompiler::validateNetwork``) because the address is not known
    when the route is installed, and it refuses a network whose address is
    not the network address of its own netmask.  Both leave the rule
    saying something other than what the editor shows.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        for obj in rule.rdst:
            if isinstance(obj, MultiAddress) and (obj.data or {}).get('run_time'):
                self.compiler.error(
                    rule,
                    f'Object "{obj.name}" resolves only on the firewall, which '
                    f'is too late for a route; the rule is left out',
                )
                return True
            if not _is_valid_network(obj):
                self.compiler.error(
                    rule,
                    f'Object "{obj.name}" is used as the destination but its '
                    f'address is not the network address of its own netmask, '
                    f'so the route would go somewhere else; the rule is left '
                    f'out',
                )
                return True

        self.tmp_queue.append(rule)
        return True


class ExpandAddressRangesInRDst(RoutingRuleProcessor):
    """Write an address range in RDst out as the networks covering it.

    ``ip route add`` takes one prefix, never a range.  Corresponds to
    ``RoutingCompiler_ipt::addressRangesInDst``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.compiler.expand_address_ranges(rule, 'rdst')
        self.tmp_queue.append(rule)
        return True


class EliminateDuplicatesInRDst(RoutingRuleProcessor):
    """Remove duplicate objects from the destination element."""

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        self.compiler.eliminate_duplicates_in_element(rule, 'rdst')
        self.tmp_queue.append(rule)
        return True


class ConvertToAtomicForRDst(RoutingRuleProcessor):
    """Give every destination its own ``ip route add`` command.

    The objects of a rule element are alternatives and a route names one
    destination, so a rule listing several needs one command each.
    Corresponds to ``RoutingCompiler::ConvertToAtomicForDST``.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if len(rule.rdst) <= 1:
            self.tmp_queue.append(rule)
            return True

        for obj in rule.rdst:
            r = rule.clone()
            r.rdst = [obj]
            self.tmp_queue.append(r)
        return True


def _parent_host(iface: Interface):
    """Return the Host, Firewall or Cluster an interface belongs to.

    A sub-interface carries no device of its own, so the chain of parent
    interfaces has to be walked first.
    """
    current = iface
    seen = set()
    while current is not None and current.id not in seen:
        seen.add(current.id)
        if current.device is not None:
            return current.device
        current = current.parent_interface
    return None


# The address types that are one address a route can go via.  The C++
# asks ``getByType("IPv4")`` for this (fwbuilder
# libfwbuilder/src/fwbuilder/RuleElement.cpp,
# RuleElementRGtw::checkSingleIPAdress), i.e. it counts inet addresses and
# nothing else.  A PhysAddress answers ``get_address()`` with a MAC, so
# counting whatever has an address makes an interface that carries an
# address *and* a MAC - which is what a host with "MAC address matching"
# turned on expands to - look like two next hops and costs the rule.
_INET_ADDRESS_TYPES = (IPv4, IPv6, Network, NetworkIPv6)


def _count_addresses(obj) -> int:
    """Return how many next hops an object offers.

    Mirrors ``Address::countInetAddresses``: only an object that *is* one
    inet address answers 1; a host or an interface answers however many it
    carries.
    """
    if isinstance(obj, Interface):
        return sum(1 for addr in obj.addresses if _count_addresses(addr))
    if isinstance(obj, Host):
        return sum(
            1
            for iface in obj.interfaces
            for addr in iface.addresses
            if _count_addresses(addr)
        )
    if isinstance(obj, _INET_ADDRESS_TYPES):
        return 1 if obj.get_address() else 0
    return 0


def _is_valid_network(obj) -> bool:
    """Return whether a network object can name a route.

    Only a network is checked, the way ``validateNetwork::checkValidNetwork``
    does it: ``Network::isValidRoutingNet`` asks whether the address is the
    network address of its own mask, because ``ip route add 192.168.1.7/24``
    installs a route to 192.168.1.0/24 and the rule then says something
    other than what the editor shows.  Anything else passes here and is
    answered for by the print rule.
    """
    if not isinstance(obj, (Network, NetworkIPv6)):
        return True
    addr = obj.get_address()
    mask = obj.get_netmask()
    if not addr or not mask:
        return False
    try:
        net = ipaddress.ip_network(f'{addr}/{mask}', strict=False)
    except ValueError:
        return False
    return str(net.network_address) == addr


class RoutingPrintRule(RoutingRuleProcessor):
    """Generates 'ip route' commands from routing CompRules."""

    def __init__(self, name: str = 'generate ip route commands') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        output = self._routing_rule_to_string(rule)
        if output:
            self.compiler.output.write(output)
            self.compiler.output.write('\n')

        self.tmp_queue.append(rule)
        return True

    @staticmethod
    def _is_ipv6_route(rule: CompRule) -> bool:
        """Return whether this route belongs to the IPv6 routing table.

        iproute2 takes the family from the destination or the gateway and
        only falls back to IPv4 when it can read it from neither, which is
        exactly the case of a route to "default" out of an interface.  Such
        a rule would install an IPv4 default route, so the family is stated
        rather than inferred.
        """
        for slot in ('rdst', 'rgtw'):
            for obj in getattr(rule, slot, None) or []:
                if getattr(obj, 'is_v6', None) and obj.is_v6():
                    return True
        return False

    def _routing_rule_to_string(self, rule: CompRule) -> str:
        """Convert a routing CompRule to an 'ip route' command string.

        Returns an empty string when the rule cannot be written out; the
        reason has been reported by then.  A route whose destination the
        compiler cannot render must never be written out as anything else:
        the only thing "ip route add" accepts in that place is ``default``,
        and installing a default route out of the gateway meant for one
        subnet sends every packet the wrong way.
        """
        # The script defines IP from the firewall's "path to ip" setting,
        # the same way it defines IPTABLES; writing the bare name here ran
        # whatever the PATH happened to find instead.
        family = ' -6' if self._is_ipv6_route(rule) else ''
        parts = [f'$IP{family} route add']

        dst = self._print_rdst(rule)
        if dst is None:
            return ''
        gtw = self._print_rgtw(rule)
        if gtw is None:
            return ''
        itf = self._print_ritf(rule)
        if itf is None:
            return ''
        metric = rule.get_option('metric', 0)

        parts.append(dst)
        # fwbuilder writes the metric right behind the destination
        # (RoutingCompiler_ipt_writers.cpp RoutingRuleToString).
        if metric and int(metric) > 0:
            parts.append(f'metric {metric}')
        if gtw:
            parts.append(f'via {gtw}')
        if itf:
            parts.append(f'dev {itf}')

        return ' '.join(parts)

    def _print_rdst(self, rule: CompRule) -> str | None:
        """Print the routing destination, or None when there is none to print.

        An empty element is "any", which is what a default route says.  An
        element holding an object nobody can turn into an address is a
        different thing entirely and is reported instead.
        """
        if not rule.rdst:
            return 'default'
        obj = rule.rdst[0]
        addr = self._print_addr(obj)
        if addr:
            return addr
        self.compiler.error(
            rule,
            f'Object "{getattr(obj, "name", obj)}" is used as the destination '
            f'but names no address the route command can use; the rule is '
            f'left out',
        )
        return None

    def _print_rgtw(self, rule: CompRule) -> str | None:
        """Print the routing gateway, or None when it cannot be printed."""
        if not rule.rgtw:
            return ''
        obj = rule.rgtw[0]
        addr = self._print_addr(obj)
        if addr and addr != 'default':
            return addr
        if addr == 'default':
            # fwbuilder leaves the "via" out for an "any" gateway rather
            # than writing "via default", which iproute2 does not take.
            return ''
        self.compiler.error(
            rule,
            f'Object "{getattr(obj, "name", obj)}" is used as the gateway but '
            f'names no address the route command can use; the rule is left out',
        )
        return None

    def _print_ritf(self, rule: CompRule) -> str | None:
        """Print the routing interface, or None when it cannot be printed."""
        if not rule.ritf:
            return ''
        obj = rule.ritf[0]
        if isinstance(obj, Interface):
            return obj.name
        self.compiler.error(
            rule,
            f'Object "{getattr(obj, "name", obj)}" is used as the interface '
            f'but is not an interface; the rule is left out',
        )
        return None

    def _print_addr(self, obj) -> str:
        """Print an address object the way ``ip route`` takes it.

        ``default`` is the answer for the "any" address, matching
        ``RoutingCompiler_ipt::PrintRule::_printAddr``, which writes it when
        address and netmask are both zero.  The prefix is left out for a
        host mask there as well, which is why a single address never comes
        out as ``/32``.
        """
        if not isinstance(obj, Address):
            return ''

        addr_str = obj.get_address()
        mask_str = obj.get_netmask()
        if not addr_str:
            return ''

        if mask_str and isinstance(obj, (Network, NetworkIPv6)):
            try:
                net = ipaddress.ip_network(f'{addr_str}/{mask_str}', strict=False)
            except ValueError:
                return addr_str
            if int(net.network_address) == 0 and net.prefixlen == 0:
                return 'default'
            if net.prefixlen == net.max_prefixlen:
                return str(net.network_address)
            return str(net)

        return addr_str
