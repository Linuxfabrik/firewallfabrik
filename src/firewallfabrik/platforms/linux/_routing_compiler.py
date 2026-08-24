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
    VerifyAddressRanges,
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
    RoutingRuleType,
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
        self.add(VerifyAddressRanges('verify address ranges'))
        self.add(VerifyRouteMetrics('verify route metrics'))

        self.add(ExpandGroups('expand groups'))
        self.add(ExpandMultipleAddressesInRouting('expand objects with addresses'))
        self.add(DropRuleWithEmptyRE('drop rules with empty rule elements'))

        self.add(ValidateRoutingDestination('validate destination addresses'))
        self.add(ReachableGateway('check that the gateway is reachable'))
        self.add(GatewayOnRoutingInterface('check the gateway against RItf'))
        self.add(ExpandAddressRangesInRDst('process address ranges'))
        self.add(EliminateDuplicatesInRDst('eliminate duplicates in RDst'))
        self.add(CompetingRoutingRules('check for competing rules'))
        self.add(ConvertToAtomicForRDst('convert to atomic rules by destination'))
        self.add(ClassifyRoutingRules('classify single path and multi path rules'))
        self.add(EliminateDuplicateRoutingRules('eliminate duplicate rules'))

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


class VerifyRouteMetrics(RoutingRuleProcessor):
    """Report a metric ``ip route`` cannot carry, and route without it.

    Two rules to one destination are told apart by their metric, so a
    metric the command refuses is not a detail: iproute2 answers it with
    `"metric" value is invalid` and installs nothing at all, and the
    activation carries on without that route.  Compiling the route
    without the metric at least installs it; which of two competing
    routes wins is then the kernel's choice rather than the
    administrator's, which is why it is said out loud.
    """

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if route_metric(rule) is None:
            self.compiler.warning(
                rule,
                f'"{rule.get_option("metric", 0)}" is not a route metric; it '
                f'takes a number up to {MAX_ROUTE_METRIC}, and iproute2 '
                f'refuses anything else. The route is installed without one',
            )

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


def _interface_networks(fw, want_v6: bool) -> list:
    """Return the networks the firewall is directly attached to.

    Only the addresses of the family being asked about: a gateway is
    reachable through an address of its own family and through no other.
    The C++ walks ``IPv4`` children alone
    (``RoutingCompiler::reachableAddressInRGtw::checkReachableIPAddress``),
    which answers "unreachable" for every IPv6 gateway there is.
    """
    networks = []
    for iface in fw.interfaces:
        for addr in iface.addresses:
            address = addr.get_address()
            netmask = addr.get_netmask()
            if not address or not netmask:
                continue
            try:
                network = ipaddress.ip_network(f'{address}/{netmask}', strict=False)
            except ValueError:
                continue
            if (network.version == 6) == want_v6:
                networks.append((iface, network))
    return networks


def _gateway_address(obj):
    """Return the one address an object offers as a next hop, or None."""
    if isinstance(obj, Interface):
        for addr in obj.addresses:
            address = addr.get_address()
            if address:
                try:
                    return ipaddress.ip_address(address)
                except ValueError:
                    return None
        return None
    if isinstance(obj, Host):
        for iface in obj.interfaces:
            found = _gateway_address(iface)
            if found is not None:
                return found
        return None
    if isinstance(obj, (IPv4, IPv6)):
        address = obj.get_address()
        if not address:
            return None
        try:
            return ipaddress.ip_address(address)
        except ValueError:
            return None
    # A network, an address range or anything else is not a single next
    # hop; the C++ answers "reachable" for those rather than guess.
    return None


class ReachableGateway(RoutingRuleProcessor):
    """Report a gateway that is on none of the firewall's own networks.

    ``ip route add ... via <gw>`` needs the next hop to sit on a network
    the box is attached to; the kernel answers anything else with "Error:
    Nexthop has invalid gateway" and installs nothing (verified against
    iproute2 in a network namespace).  Without this the mistake surfaces
    only at activation time, as one line of stderr in the middle of the
    routing block, and the route the rule was written for is simply not
    there.  Corresponds to ``RoutingCompiler::reachableAddressInRGtw``.
    """

    def __init__(self, name: str = 'check that the gateway is reachable') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        for obj in rule.rgtw:
            gateway = _gateway_address(obj)
            if gateway is None:
                continue
            networks = _interface_networks(self.compiler.fw, gateway.version == 6)
            if any(gateway in network for _iface, network in networks):
                continue
            self.compiler.error(
                rule,
                f'Object "{obj.name}" is used as the gateway but {gateway} is '
                f'on none of the local networks of this firewall, so the '
                f'route cannot be installed; give the interface facing it an '
                f'address in that network. The rule is left out',
            )
            return True

        self.tmp_queue.append(rule)
        return True


class GatewayOnRoutingInterface(RoutingRuleProcessor):
    """Report a gateway that is not on the network of the named interface.

    ``dev`` says which interface the next hop is reached through, so the
    gateway has to be on *that* interface's network; the kernel refuses
    the pair with "Error: Nexthop has invalid gateway" the same way it
    refuses an unreachable one.  Corresponds to
    ``RoutingCompiler::contradictionRGtwAndRItf``, including its early
    exit for a rule that names no interface.
    """

    def __init__(self, name: str = 'check the gateway against RItf') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if not rule.ritf:
            self.tmp_queue.append(rule)
            return True

        iface = rule.ritf[0]
        if not isinstance(iface, Interface):
            self.tmp_queue.append(rule)
            return True

        for obj in rule.rgtw:
            gateway = _gateway_address(obj)
            if gateway is None:
                continue
            networks = [
                network
                for other, network in _interface_networks(
                    self.compiler.fw, gateway.version == 6
                )
                if other.id == iface.id
            ]
            if not networks or any(gateway in network for network in networks):
                # An interface with no address of this family gets its
                # address while the firewall runs, so nothing can be said
                # about it here; the C++ falls through the same way.
                continue
            self.compiler.error(
                rule,
                f'Object "{obj.name}" is used as the gateway but {gateway} is '
                f'not on the network of interface "{iface.name}", which the '
                f'rule routes through, so the route cannot be installed. The '
                f'rule is left out',
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


def _route_table(rule: CompRule) -> str:
    """Return the routing table part of a rule label.

    ``RoutingCompiler::createSortedDstIdsLabel`` cuts the label at the
    opening brace, which leaves the name of the table the route goes into.
    Two rules only compete when they install into the same table.
    """
    label = rule.label or ''
    brace = label.find('(')
    return label[brace:] if brace >= 0 else label


def _destination_key(rule: CompRule) -> str:
    """Return a key that is equal for two rules with the same destination.

    The object ids are sorted so that a rule naming the same destinations
    in a different order gives the same key, which is what
    ``createSortedDstIdsLabel`` is for.
    """
    ids = sorted(str(getattr(obj, 'id', obj)) for obj in rule.rdst)
    return ' '.join([_route_table(rule), *ids])


def _next_hop_key(rule: CompRule) -> str:
    """Return a key for the gateway and interface combination of a rule."""
    gtw = str(getattr(rule.rgtw[0], 'id', '')) if rule.rgtw else ''
    itf = str(getattr(rule.ritf[0], 'id', '')) if rule.ritf else ''
    return f'{gtw}_{itf}'


# `ip route add ... metric N` carries a 32-bit number: iproute2 reads it
# with `get_u32(&metric, *argv, 0)` (iproute2 ip/iproute.c) and answers
# anything else with `Error: argument "..." is wrong: "metric" value is
# invalid`, which leaves that one route uninstalled while the rest of the
# activation carries on.  Verified in a network namespace: 4294967295 is
# taken, 5000000000 and -5 are not.  The editor bounds the field with a
# spin box, so only a hand-edited or foreign data file can carry more.
MAX_ROUTE_METRIC = 0xFFFFFFFF


def route_metric(rule: CompRule) -> int | None:
    """Return the metric of *rule*, or ``None`` when the value is not one.

    An absent metric is zero, which is what iproute2 uses when the option
    is left off, and which every caller here reads as "no metric".
    """
    value = rule.get_option('metric', 0)
    if value is None or value == '':
        return 0
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= number <= MAX_ROUTE_METRIC:
        return None
    return number


def _metric(rule: CompRule) -> str:
    """Return the rule metric as the string the route command carries."""
    number = route_metric(rule)
    return str(number if number is not None else 0)


class CompetingRoutingRules(RoutingRuleProcessor):
    """Leave out a route the firewall would install twice.

    ``ip route add`` for a destination that is already routed the same way
    answers "RTNETLINK answers: File exists" and returns non-zero, so a
    duplicate rule costs an error at activation and installs nothing.  Two
    rules that agree on destination, gateway and interface but not on the
    metric are worse: which of the two the administrator meant cannot be
    guessed, and fwbuilder refuses the pair rather than pick one.
    Corresponds to ``RoutingCompiler::competingRules``.
    """

    def __init__(self, name: str = 'check for competing rules') -> None:
        super().__init__(name)
        self._seen: dict[str, dict[str, tuple[str, str]]] = {}

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        destination = _destination_key(rule)
        next_hop = _next_hop_key(rule)
        metric = _metric(rule)

        seen_for_destination = self._seen.setdefault(destination, {})
        previous = seen_for_destination.get(next_hop)
        if previous is not None:
            previous_metric, previous_label = previous
            if previous_metric == metric:
                self.compiler.warning(
                    rule,
                    f'Routing rules "{previous_label}" and "{rule.label}" are '
                    f'identical; the second one is left out',
                )
            else:
                self.compiler.error(
                    rule,
                    f'Routing rules "{previous_label}" and "{rule.label}" are '
                    f'identical except for the metric, so which route the '
                    f'firewall should install cannot be decided; the second '
                    f'one is left out',
                )
            return True

        seen_for_destination[next_hop] = (metric, rule.label)
        self.tmp_queue.append(rule)
        return True


class ClassifyRoutingRules(RoutingRuleProcessor):
    """Mark the rules that share a destination and a metric as multi path.

    Two routes to the same destination with the same metric are not two
    routes: the kernel takes the first and refuses the second with "File
    exists", so the second path is silently not there.  What the
    administrator asked for is one route with several next hops, which is
    what ``ip route add <dst> nexthop ... nexthop ...`` installs.
    Corresponds to ``RoutingCompiler::classifyRoutingRules``; like
    fwbuilder this does not ask for an option first, because the
    alternative is a command that fails.
    """

    def __init__(self, name: str = 'classify single path and multi path rules') -> None:
        super().__init__(name)

    def process_next(self) -> bool:
        self.slurp()
        if not self.tmp_queue:
            return False

        seen: dict[str, dict[str, tuple[str, CompRule]]] = {}
        for rule in self.tmp_queue:
            rule.routing_rule_type = RoutingRuleType.SinglePath

        for rule in self.tmp_queue:
            destination = _destination_key(rule)
            next_hop = _next_hop_key(rule)
            metric = _metric(rule)

            seen_for_destination = seen.setdefault(destination, {})
            if next_hop in seen_for_destination:
                continue

            for other_metric, other_rule in seen_for_destination.values():
                if other_metric == metric:
                    rule.routing_rule_type = RoutingRuleType.MultiPath
                    other_rule.routing_rule_type = RoutingRuleType.MultiPath

            seen_for_destination[next_hop] = (metric, rule)

        return True


class EliminateDuplicateRoutingRules(RoutingRuleProcessor):
    """Leave out an atomic route another rule already installs.

    ``CompetingRoutingRules`` compares the destination *lists* of two
    rules, so a rule routing "A and B" and one routing "B" pass it and only
    collide once every destination has its own command.  Corresponds to
    ``RoutingCompiler_ipt::eliminateDuplicateRules`` and, for the silent
    half, to ``RoutingCompiler_ipt::optimize3``: two copies of the *same*
    rule are an artifact of the atomic split - two destination objects
    holding the same address - and there is nothing an administrator could
    do about them, so only a collision between two different rules is
    worth a word.
    """

    def __init__(self, name: str = 'eliminate duplicate rules') -> None:
        super().__init__(name)
        self._seen: dict[tuple, str] = {}

    def process_next(self) -> bool:
        rule = self.get_next()
        if rule is None:
            return False

        if rule.fallback or rule.hidden:
            self.tmp_queue.append(rule)
            return True

        key = (
            _route_table(rule),
            str(getattr(rule.rdst[0], 'id', '')) if rule.rdst else '',
            _metric(rule),
            _next_hop_key(rule),
        )
        previous = self._seen.get(key)
        if previous is not None:
            if previous != rule.label:
                self.compiler.warning(
                    rule,
                    f'Routing rules "{previous}" and "{rule.label}" install '
                    f'the same route; the second one is left out',
                )
            return True

        self._seen[key] = rule.label
        self.tmp_queue.append(rule)
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

        if rule.routing_rule_type == RoutingRuleType.MultiPath:
            self._buffer_multi_path(rule)
        else:
            output = self._routing_rule_to_string(rule)
            if output:
                self.compiler.output.write(output)
                self.compiler.output.write('\n')

        self.tmp_queue.append(rule)
        return True

    def _buffer_multi_path(self, rule: CompRule) -> None:
        """Collect one leg of an equal-cost multi path route.

        The legs of one route have to leave the compiler as a single
        command, so they are buffered here and written by ``epilog()``.
        Corresponds to the ``MultiPath`` branch of
        ``RoutingCompiler_ipt::PrintRule::processNext``.
        """
        dst = self._print_rdst(rule)
        gtw = self._print_rgtw(rule)
        itf = self._print_ritf(rule)
        if dst is None or gtw is None or itf is None:
            return

        metric = _metric(rule)
        key = f'{_destination_key(rule)}#{metric}'
        rules = self.compiler.ecmp_rules_buffer
        comments = self.compiler.ecmp_comments_buffer

        if key not in rules:
            family = ' -6' if self._is_ipv6_route(rule) else ''
            head = f'$IP{family} route add {dst}'
            if metric != '0':
                head += f' metric {metric}'
            rules[key] = head
            comments[key] = (
                '# The following routing rules share a destination and a '
                'metric, so they\n'
                '# install one route with several next hops rather than '
                'competing ones:\n'
            )

        comments[key] += f'# Rule {rule.label}\n'

        next_hop = ' \\\n    nexthop'
        if gtw:
            next_hop += f' via {gtw}'
        if itf:
            next_hop += f' dev {itf}'
        rules[key] += next_hop

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
        metric = _metric(rule)

        parts.append(dst)
        # fwbuilder writes the metric right behind the destination
        # (RoutingCompiler_ipt_writers.cpp RoutingRuleToString).  The
        # multi-path branch reads the same value through the same helper,
        # or the two spellings of one metric would end up in two commands.
        if metric != '0':
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
