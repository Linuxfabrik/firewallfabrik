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

"""Compiler base class managing the rule processor pipeline.

Corresponds to fwbuilder's Compiler class, rewritten for SQLAlchemy
models and CompRule dataclasses.
"""

from __future__ import annotations

import io
import ipaddress
import socket
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy

from firewallfabrik.compiler._base import BaseCompiler, CompilerStatus
from firewallfabrik.compiler._combined_address import (
    CombinedAddress,
    host_matches_by_mac,
)
from firewallfabrik.compiler._comp_rule import CompRule, expand_group
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor, Debug
from firewallfabrik.core.objects import (
    Address,
    AddressRange,
    AddressTable,
    DNSName,
    DynamicGroup,
    Firewall,
    Group,
    Host,
    Interface,
    IPv4,
    IPv6,
    MultiAddress,
    Network,
    NetworkIPv6,
    PhysAddress,
    RuleSet,
)

if TYPE_CHECKING:
    import sqlalchemy.orm

# Types eligible for DynamicGroup membership (mirrors fwbuilder's
# Address::cast / ObjectGroup::cast / Host checks).
_DG_ADDRESS_TYPES = frozenset(
    {
        'AddressRange',
        'AddressTable',
        'AttachedNetworks',
        'DNSName',
        'DynamicGroup',
        'IPv4',
        'IPv6',
        'MultiAddress',
        'MultiAddressRunTime',
        'Network',
        'NetworkIPv6',
        'PhysAddress',
    }
)
_DG_GROUP_TYPES = frozenset({'ObjectGroup'})
_DG_DEVICE_TYPES = frozenset({'Cluster', 'Firewall', 'Host'})
_DG_ELIGIBLE = _DG_ADDRESS_TYPES | _DG_GROUP_TYPES | _DG_DEVICE_TYPES


def _matches_dynamic_criteria(
    obj, criteria: list[dict], match_mode: str = 'AND'
) -> bool:
    """Return True if *obj* matches the *criteria* under *match_mode*.

    *match_mode*:
      - ``'AND'`` (default for new groups): every criterion must match.
      - ``'OR'``: at least one criterion must match. Used for groups
        imported from fwbuilder ``.fwb`` files, since fwbuilder only
        supports OR semantics in ``DynamicGroup::isMemberOfGroup()``.
    """
    obj_type = getattr(obj, 'type', '')
    if obj_type not in _DG_ELIGIBLE:
        return False

    # Exclude deleted-objects library.
    lib = getattr(obj, 'library', None)
    if lib is None:
        return False
    if getattr(lib, 'name', '') == 'Deleted Objects':
        return False

    # Exclude standard ObjectGroups near the tree root (depth <= 3).
    if obj_type in _DG_GROUP_TYPES:
        depth = 2
        parent = getattr(obj, 'parent_group', None)
        while parent is not None:
            depth += 1
            parent = getattr(parent, 'parent_group', None)
        if depth <= 3:
            return False

    keywords = getattr(obj, 'keywords', None) or set()
    active = []
    for entry in criteria:
        type_val = entry.get('type', 'none')
        keyword_val = entry.get('keyword', ',')
        if type_val == 'none' or keyword_val == ',':
            continue
        type_match = type_val == 'any' or obj_type == type_val
        keyword_match = keyword_val == '' or keyword_val in keywords
        active.append(type_match and keyword_match)

    if not active:
        return False
    if match_mode == 'OR':
        return any(active)
    return all(active)


def _is_broadcast_address(ip) -> bool:
    """Whether *ip* is what ``InetAddr::isBroadcast()`` calls a broadcast.

    For IPv4 that is 255.255.255.255 alone.  IPv6 has no broadcast, and
    fwbuilder answers with link-local multicast there (``InetAddr.h``,
    ``IN6_IS_ADDR_MC_LINKLOCAL``), which is what carries neighbour
    discovery and the routing protocols - the same traffic the IPv4
    broadcast carries.
    """
    if ip.version == 4:
        return int(ip) == 0xFFFFFFFF
    return ip.is_multicast and ip.packed[1] & 0x0F == 0x02


def _is_broadcast_or_multicast(
    ip, recognize_broadcasts: bool, recognize_multicasts: bool
) -> bool:
    """The head of ``checkComplexMatchForSingleAddress``.

    Such a packet is delivered locally, can be sent by the firewall itself
    and is never routed, so a rule naming one belongs in INPUT and OUTPUT.
    ``InetAddr::isAny()`` reads the address alone, where ``Address.is_any()``
    also wants a zero netmask - which is why the "old broadcast" 0.0.0.0 is
    asked about here and not through the object.
    """
    if recognize_broadcasts and (_is_broadcast_address(ip) or int(ip) == 0):
        return True
    return bool(recognize_multicasts and ip.is_multicast)


def _carries_ip_address(iface) -> bool:
    """Does *iface* carry an IP address of either family?

    Asked to tell the two reasons an expansion can come out empty apart:
    an interface with an address of the other family is the ordinary case
    of a single-stack object in the wrong pass, one with no IP address at
    all is not.  A MAC address belongs to no family and does not count.
    """
    return any(
        not isinstance(addr, PhysAddress) and addr.get_address()
        for addr in getattr(iface, 'addresses', [])
    )


def _first_inet_address_object(iface):
    """The address object ``Interface::getAddressObject()`` answers with.

    The first IPv4 of the interface, else its first IPv6, whatever family
    is being compiled (Interface.cpp:461).  ``None`` when the interface
    carries no IP address at all - a MAC-only or unnumbered one.
    """
    for wanted_v6 in (False, True):
        for addr in getattr(iface, 'addresses', []):
            if addr.is_v6() != wanted_v6:
                continue
            if hasattr(addr, 'get_address') and addr.get_address():
                return addr
    return None


def _first_inet_address(iface):
    """The same address as an :mod:`ipaddress` object, or ``None``."""
    addr = _first_inet_address_object(iface)
    if addr is None:
        return None
    try:
        return ipaddress.ip_address(addr.get_address())
    except ValueError:
        return None


def _is_host_mask(mask: str, version: int) -> bool:
    """Whether *mask* covers a single address (``InetAddr::isHostMask``)."""
    try:
        if mask.isdigit():
            return int(mask) == (32 if version == 4 else 128)
        return int(ipaddress.ip_address(mask)) == (
            0xFFFFFFFF if version == 4 else (1 << 128) - 1
        )
    except ValueError:
        return False


class Compiler(BaseCompiler):
    """Base compiler. Manages the rule processor pipeline."""

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6_policy: bool,
    ) -> None:
        super().__init__()
        self.session: sqlalchemy.orm.Session = session
        self.fw: Firewall = fw
        self.ipv6_policy: bool = ipv6_policy

        self.source_ruleset: RuleSet | None = None
        self.rules: list[CompRule] = []

        self.rule_processors: list[BasicRuleProcessor] = []
        self.output: io.StringIO = io.StringIO()

        self.single_rule_compile_mode: bool = False
        self.single_rule_id: str = ''
        self.rule_debug_on: bool = False
        self.debug_rule: int = -1
        self.verbose: bool = False
        self.source_dir: str = '.'

        self._multi_address_cache: dict = {}

    def set_source_ruleset(self, rs: RuleSet) -> None:
        self.source_ruleset = rs

    # -- Processor chain --

    def add(self, rp: BasicRuleProcessor) -> None:
        """Add a processor to the chain.

        When single-rule compile mode is active, a
        :class:`SingleRuleFilter` is injected automatically after the
        :class:`Begin` processor so that only the target rule is compiled.

        If debugging is ON (rule_debug_on), also adds a Debug processor
        after it — except after SimplePrintProgress.
        """
        from firewallfabrik.compiler.processors._generic import (
            Begin,
            SimplePrintProgress,
            SingleRuleFilter,
        )

        self.rule_processors.append(rp)
        if isinstance(rp, Begin) and self.single_rule_compile_mode:
            self.rule_processors.append(SingleRuleFilter())
        if self.rule_debug_on and not isinstance(rp, SimplePrintProgress):
            self.rule_processors.append(Debug())

    def run_rule_processors(self) -> None:
        """Link and execute the processor pipeline."""
        if not self.rule_processors:
            return

        # Set context for all processors and link the chain
        self.rule_processors[0].set_context(self)
        for i in range(1, len(self.rule_processors)):
            self.rule_processors[i].set_context(self)
            self.rule_processors[i].set_data_source(self.rule_processors[i - 1])

        # Execute: call process_next() on the LAST processor
        last = self.rule_processors[-1]
        while last.process_next():
            pass

    def delete_rule_processors(self) -> None:
        self.rule_processors.clear()

    # -- Compilation entry points --

    def prolog(self) -> int:
        """Initialize compilation. Returns rule count."""
        return 0

    def compile(self) -> None:
        """Override in platform-specific subclasses to add processors."""
        pass

    def epilog(self) -> None:
        pass

    # -- Accessors --

    @property
    def ipv6(self) -> bool:
        return self.ipv6_policy

    def get_rule_set_name(self) -> str:
        if self.source_ruleset is not None:
            return self.source_ruleset.name
        return ''

    def get_compiled_script_length(self) -> int:
        return self.output.tell()

    def in_single_rule_compile_mode(self) -> bool:
        return self.single_rule_compile_mode

    def create_rule_label(self, prefix: str, txt: str, rule_num: int) -> str:
        """Create a human-readable label for a rule."""
        parts = []
        if prefix:
            parts.append(prefix)
        parts.append(f'{rule_num} ({txt})')
        return ' '.join(parts)

    # -- Warning with formatted output --

    def warning(self, rule_or_msg, msg: str | None = None) -> None:
        """Emit a warning formatted as fwname:rsname:pos: warning: msg.

        Only the wording differs from ``BaseCompiler.warning``; the two
        rules that hold for every message hold here as well.  A muted
        block records nothing, because the dedup pass renders each rule a
        second time only to compare the result, and a message about a rule
        is recorded once and not once per copy of it - one rule as the
        editor shows it reaches the printer as several, and repeating the
        same sentence per copy buries the rest of the report.  Overriding
        this method without carrying both over is how half of all warnings
        came to be repeats.
        """
        if msg is None:
            super().warning(rule_or_msg)
            return
        if self._muted:
            return
        fw_name = self.fw.name if self.fw else ''
        rs_name = self.source_ruleset.name if self.source_ruleset else ''
        pos = ''
        if hasattr(rule_or_msg, 'position'):
            pos = str(rule_or_msg.position)
        formatted = f'{fw_name}:{rs_name}:{pos}: warning: {msg}'
        label = getattr(rule_or_msg, 'label', '') or ''
        if self._already_reported(label, formatted):
            return
        self._warnings.append(formatted)
        if label:
            self._rule_errors.setdefault(label, []).append(formatted)
        if self._status == CompilerStatus.FWCOMPILER_SUCCESS:
            self._status = CompilerStatus.FWCOMPILER_WARNING

    def debug_print_rule(self, rule: CompRule) -> str:
        """Basic debug output for a rule. Override in subclasses for richer output."""
        return rule.label

    # -- Helper methods for rule processors --

    def expand_groups_in_element(self, comp_rule: CompRule, slot: str) -> None:
        """Expand all groups in a rule element slot, replacing group objects
        with their leaf members.

        A compile-time MultiAddress (DNSName, AddressTable) named directly
        in the element has already been resolved by ``ResolveMultiAddress``,
        but one that sits *inside* a group only becomes visible here, so it
        is resolved on the way out.  fwbuilder has no such second place
        because it resolves every one of them in a preprocessor pass over
        the whole object tree before any rule is looked at
        (``Preprocessor::convertObject``).  A run-time MultiAddress is kept
        as-is: what is in it is only known when the script runs.

        After expansion, elements are sorted by name to match C++
        Compiler::expandGroupsInRuleElement() which uses
        FWObjectNameCmpPredicate.
        """
        elements = getattr(comp_rule, slot)
        if not elements:
            return
        new_elements = []
        emptied_by = []
        for obj in elements:
            if isinstance(obj, MultiAddress):
                members = self._expand_multi_address_member(obj, emptied_by)
                new_elements.extend(members)
            elif isinstance(obj, Group):
                for member in expand_group(self.session, obj):
                    if isinstance(member, MultiAddress):
                        new_elements.extend(
                            self._expand_multi_address_member(member, emptied_by),
                        )
                    else:
                        new_elements.append(member)
            else:
                new_elements.append(obj)
        if not new_elements and emptied_by:
            # An element nothing is left in reads as "any" everywhere
            # downstream, so a rule written for the addresses behind these
            # objects would match every address there is.
            comp_rule.has_empty_re = True
            comp_rule.empty_re_reason = (
                f'"{emptied_by[0]}" resolves to no address at all'
            )
        new_elements.sort(key=lambda obj: getattr(obj, 'name', ''))
        setattr(comp_rule, slot, new_elements)

    def _expand_multi_address_member(self, obj: MultiAddress, emptied_by: list) -> list:
        """Return what one MultiAddress contributes to an expanded element."""
        if (obj.data or {}).get('run_time'):
            return [obj]
        resolved = self._resolve_multi_address(obj)
        if not resolved:
            emptied_by.append(obj.name)
        return resolved

    def _resolve_multi_address(self, obj: MultiAddress) -> list:
        """Resolve a compile-time MultiAddress to Address objects.

        For DNSName: resolves hostname via DNS.
        For AddressTable: loads addresses from the referenced file.
        For DynamicGroup: evaluates selection_criteria against the database.
        Falls back to obj.addresses if already populated.

        Matches C++ Preprocessor::convertObject() + MultiAddress::loadFromSource().

        The answer is kept for the rest of the compile: fwbuilder resolves
        each object once in a preprocessor pass, and a DNS lookup or a file
        read that happens once per rule would both cost more and be able to
        answer differently from one rule to the next.
        """
        # If the object already has child addresses (e.g. previously resolved),
        # return them directly.
        if obj.addresses:
            return list(obj.addresses)

        cached = self._multi_address_cache.get(obj.id)
        if cached is not None:
            return list(cached)

        if isinstance(obj, DynamicGroup):
            resolved = self._resolve_dynamic_group(obj)
        elif isinstance(obj, DNSName):
            resolved = self._resolve_dns_name(obj)
        elif isinstance(obj, AddressTable):
            resolved = self._load_address_table(obj)
        else:
            resolved = []

        self._multi_address_cache[obj.id] = resolved
        return list(resolved)

    def _resolve_dynamic_group(self, obj: DynamicGroup) -> list:
        """Resolve a DynamicGroup by evaluating its criteria against the DB.

        Default match mode is ``AND`` across criteria. Groups imported
        from a fwbuilder ``.fwb`` file carry an explicit
        ``match_mode='OR'``, preserving fwbuilder's original semantics
        (``DynamicGroup::isMemberOfGroup`` only supports OR). Users can
        toggle the mode per group in the editor afterwards.
        """
        data = obj.data or {}
        criteria = data.get('selection_criteria', [])
        if not criteria:
            return []
        match_mode = data.get('match_mode', 'AND')

        self_id = obj.id
        result = []
        for cls in (Address, Group, Host):
            objs = self.session.scalars(sqlalchemy.select(cls)).unique().all()
            for candidate in objs:
                if candidate.id == self_id:
                    continue
                if _matches_dynamic_criteria(candidate, criteria, match_mode):
                    result.append(candidate)
        result.sort(key=lambda o: getattr(o, 'name', ''))
        return result

    def _resolve_dns_name(self, obj: DNSName) -> list:
        """Resolve a compile-time DNSName via DNS lookup."""
        dnsrec = obj.get_source_name() or obj.name
        if not dnsrec:
            return []

        af = socket.AF_INET6 if self.ipv6_policy else socket.AF_INET
        try:
            infos = socket.getaddrinfo(dnsrec, None, af, socket.SOCK_STREAM)
        except socket.gaierror:
            self.abort(
                f'DNSName "{obj.name}" cannot resolve "{dnsrec}": DNS lookup failed'
            )
            return []

        seen: set[str] = set()
        results: list[Address] = []
        addr_type = IPv6 if self.ipv6_policy else IPv4
        netmask = (
            'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
            if self.ipv6_policy
            else '255.255.255.255'
        )
        for info in infos:
            ip_str = str(info[4][0])
            if ip_str in seen:
                continue
            seen.add(ip_str)
            addr = addr_type(
                id=uuid.uuid4(),
                type=addr_type.__mapper_args__['polymorphic_identity'],
                name='address',
                inet_addr_mask={'address': ip_str, 'netmask': netmask},
            )
            results.append(addr)
        return results

    def _load_address_table(self, obj: AddressTable) -> list:
        """Load addresses from a file referenced by an AddressTable object.

        Matches C++ AddressTable::loadFromSource().
        File format: one address or network (CIDR) per line; lines starting
        with '#' or empty lines are ignored.
        """
        filename = obj.get_source_name()
        if not filename:
            return []

        # C++ AddressTable::getFilename() substitutes %DATADIR%
        if '%DATADIR%' in filename:
            filename = filename.replace('%DATADIR%', self.source_dir)

        # Search: source_dir first, then CWD
        path = Path(self.source_dir) / filename
        if not path.is_file():
            path = Path(filename)
        if not path.is_file():
            # C++ always throws here; Preprocessor catches and calls abort()
            self.abort(f'AddressTable "{obj.name}": file not found ({filename})')
            return []

        results: list[Address] = []
        line_num = 0
        for line in path.read_text().splitlines():
            line_num += 1
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # C++ keeps only valid address chars: 0-9 a-f : / .
            addr_str = ''
            for ch in line:
                if ch in '0123456789abcdef:/.':
                    addr_str += ch
                else:
                    break
            if not addr_str:
                continue

            # Determine if IPv4 or IPv6 and filter by address family
            if '.' in addr_str and not self.ipv6_policy:
                try:
                    net = ipaddress.ip_network(addr_str, strict=False)
                except ValueError:
                    # C++ throws with file:line and value
                    self.abort(f'Invalid address: {path}:{line_num} "{addr_str}"')
                    return results
                addr = Network(
                    id=uuid.uuid4(),
                    type='Network',
                    name=addr_str,
                    inet_addr_mask={
                        'address': str(net.network_address),
                        'netmask': str(net.netmask),
                    },
                )
                results.append(addr)
            elif ':' in addr_str and self.ipv6_policy:
                try:
                    net = ipaddress.ip_network(addr_str, strict=False)
                except ValueError:
                    self.abort(f'Invalid address: {path}:{line_num} "{addr_str}"')
                    return results
                addr = NetworkIPv6(
                    id=uuid.uuid4(),
                    type='NetworkIPv6',
                    name=addr_str,
                    inet_addr_mask={
                        'address': str(net.network_address),
                        'netmask': str(net.netmask),
                    },
                )
                results.append(addr)
        return results

    def expand_addr(self, comp_rule: CompRule, slot: str) -> None:
        """Expand hosts/firewalls in an element slot into their interface addresses.

        Replaces Host/Firewall objects with their IPv4 or IPv6 addresses
        (depending on ipv6_policy). Skips loopback interfaces unless the
        rule is attached to loopback.

        An interface that also carries a MAC address contributes the two
        together, as a :class:`CombinedAddress` per IP address, so the rule
        asks for the address *and* the MAC.  Which is what the host's
        "MAC address matching" option means; without it the MAC stays out of
        the ruleset entirely.  fwbuilder splits the same three cases in
        ``expand_interface_with_phys_address`` (fwbuilder iptlib/ipt_utils.cpp)
        and reads the option in ``Compiler::_expand_interface``
        (libfwbuilder/fwcompiler/Compiler.cpp).

        An element naming nothing but objects of the other address family
        comes out of this empty, and an empty element means "any" here, so
        the rule would ask for every address there is instead of the few it
        names.  It is flagged for ``DropRuleWithEmptyRE`` instead.
        fwbuilder arrives at the same place from the other side: an "any"
        element is never empty there but holds a reference to the "Any"
        object (``RuleElement::isAny()``,
        libfwbuilder/fwbuilder/RuleElement.cpp), so
        ``DropRulesByAddressFamilyAndServiceType`` compares the element
        before and after the filtering and drops the rule when the filtering
        turned it into "any" (libfwbuilder/fwcompiler/Compiler.cpp).

        Which of the two reasons emptied the element decides whether the
        rule's disappearance is worth a word.  The address family is the
        ordinary fate of a single-stack rule in the other family's pass
        and stays silent there, because the rule is compiled for the
        family it names; a host that carries no usable address at all is
        a different matter and has to be said, whichever pass finds it.
        """
        elements = getattr(comp_rule, slot)
        if not elements:
            return

        # Check if rule is on loopback
        on_loopback = False
        if comp_rule.itf:
            first_itf = comp_rule.itf[0]
            if isinstance(first_itf, Interface) and first_itf.is_loopback():
                on_loopback = True

        new_elements = []
        contributed_nothing = []
        for obj in elements:
            if isinstance(obj, Host) and not isinstance(obj, Interface):
                use_mac = host_matches_by_mac(obj)
                before = len(new_elements)
                other_family = False
                # Expand host to its interface addresses
                for iface in obj.interfaces:
                    if iface.is_loopback() and not on_loopback:
                        continue
                    expanded = self._expand_interface(iface, use_mac)
                    new_elements.extend(expanded)
                    if not expanded and _carries_ip_address(iface):
                        other_family = True
                if len(new_elements) == before and not other_family:
                    contributed_nothing.append(obj.name)
            else:
                new_elements.append(obj)

        if not new_elements:
            comp_rule.has_empty_re = True
            if contributed_nothing:
                comp_rule.empty_re_family_only = False
                comp_rule.empty_re_reason = (
                    f'"{contributed_nothing[0]}" contributes no address to it'
                )
            else:
                comp_rule.empty_re_family_only = True
                comp_rule.empty_re_reason = (
                    'none of the addresses it names belong to the address family '
                    'being compiled'
                )

        # Sort by address
        new_elements.sort(key=_addr_sort_key)
        setattr(comp_rule, slot, new_elements)

    def _expand_interface(self, iface: Interface, use_mac: bool) -> list:
        """Return what one interface contributes to an expanded element.

        A dynamic interface contributes *itself*: its address is only known
        on the firewall, and Firewall Builder stores a placeholder child of
        0.0.0.0 for it (``Compiler::_expand_interface`` returns the
        interface before it looks at any child).  Taking that placeholder
        instead writes ``-s 0.0.0.0`` - which iptables reads as
        ``0.0.0.0/32`` and no packet carries - where the rule has to become
        the run-time loop over the interface's addresses.  On an
        anti-spoofing rule that is a hole: the address the rule is written
        about is never matched.

        A MAC address belongs to no address family, so the family filter
        must not touch it: an interface known only by its MAC has to survive
        both passes, otherwise the element silently loses its only object.

        An address object that carries no address at all matches nothing and
        is left out; the element it came from then either still names
        something or is reported empty.
        """
        if iface.is_dynamic():
            return [iface]

        addresses = []
        phys_address = None
        for addr in iface.addresses:
            if not addr.get_address():
                continue
            if isinstance(addr, PhysAddress):
                phys_address = addr
                continue
            if (self.ipv6_policy and addr.is_v6()) or (
                not self.ipv6_policy and addr.is_v4()
            ):
                addresses.append(addr)

        if phys_address is None or not use_mac:
            return addresses
        if not addresses:
            return [phys_address]
        return [CombinedAddress(addr, phys_address) for addr in addresses]

    def eliminate_duplicates_in_element(self, comp_rule: CompRule, slot: str) -> None:
        """Remove duplicate objects from a rule element slot."""
        elements = getattr(comp_rule, slot)
        seen_ids: set = set()
        new_elements = []
        for obj in elements:
            obj_id = obj.id
            if obj_id not in seen_ids:
                seen_ids.add(obj_id)
                new_elements.append(obj)
        setattr(comp_rule, slot, new_elements)

    def get_first_obj(self, comp_rule: CompRule, slot: str) -> object | None:
        """Get the first object from a rule element slot."""
        elements = getattr(comp_rule, slot, [])
        if elements:
            return elements[0]
        return None

    def get_first_src(self, comp_rule: CompRule) -> object | None:
        return self.get_first_obj(comp_rule, 'src')

    def get_first_dst(self, comp_rule: CompRule) -> object | None:
        return self.get_first_obj(comp_rule, 'dst')

    def get_first_srv(self, comp_rule: CompRule) -> object | None:
        return self.get_first_obj(comp_rule, 'srv')

    def get_first_itf(self, comp_rule: CompRule) -> Interface | None:
        if comp_rule.itf:
            obj = comp_rule.itf[0]
            if isinstance(obj, Interface):
                return obj
        return None

    def is_firewall_or_cluster(self, obj) -> bool:
        """Check if obj is (or matches) the firewall being compiled."""
        if obj is None or self.fw is None:
            return False
        return obj.id == self.fw.id

    def expand_address_ranges(self, rule, slot: str) -> None:
        """Replace every AddressRange in *slot* with a list of Networks.

        Mirrors fwbuilder's ``Compiler::_expandAddressRanges``: each
        AddressRange is decomposed into the minimum set of CIDR blocks
        that cover its [start, end] span.  Non-AddressRange objects are
        left in place.  The rule's slot is rewritten to the combined
        list.

        iptables' ``-s`` / ``-d`` only accept a single address or CIDR
        prefix, so ranges that do not align with a CIDR boundary (e.g.
        192.168.4.10-192.168.4.50) must be pre-expanded into multiple
        Networks before atomisation and printing; otherwise the
        generated shell script would emit syntactically invalid lines.
        """
        import uuid as _uuid

        elements = getattr(rule, slot, None)
        if not elements:
            return
        new_elements = []
        changed = False
        for obj in elements:
            if not isinstance(obj, AddressRange):
                new_elements.append(obj)
                continue
            start = obj.get_start_address()
            end = obj.get_end_address()
            if not start or not end:
                new_elements.append(obj)
                continue
            try:
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)
            except ValueError:
                new_elements.append(obj)
                continue
            if start_ip.version != end_ip.version:
                new_elements.append(obj)
                continue
            if int(start_ip) > int(end_ip):
                new_elements.append(obj)
                continue
            networks = list(
                ipaddress.summarize_address_range(start_ip, end_ip),
            )
            if not networks:
                new_elements.append(obj)
                continue
            for net in networks:
                if net.version == 6:
                    stand_in = NetworkIPv6(
                        id=_uuid.uuid4(),
                        name=f'{obj.name} %n-{net.with_prefixlen}%',
                    )
                else:
                    stand_in = Network(
                        id=_uuid.uuid4(),
                        name=f'{obj.name} %n-{net.with_prefixlen}%',
                    )
                stand_in.inet_addr_mask = {
                    'address': str(net.network_address),
                    'netmask': str(net.netmask),
                }
                new_elements.append(stand_in)
            changed = True
        if changed:
            setattr(rule, slot, new_elements)

    def complex_match(
        self,
        obj,
        fw: Firewall,
        recognize_broadcasts: bool = True,
        recognize_multicasts: bool = True,
    ) -> bool:
        """Check if an address object matches the firewall.

        Returns True if obj is the firewall itself, one of its interfaces,
        an address on one of its interfaces, or (when the flags are on) a
        broadcast or multicast address.

        Both flags default to on, the way ``Compiler::complexMatch``
        declares them (``Compiler.h:955``).  A broadcast is delivered
        locally *and* can be sent by the firewall itself, and it is never
        routed, so a rule naming one belongs in INPUT and OUTPUT and not
        in FORWARD.  Only the two chain decisions of a bridging firewall
        ask with the flags off, and they say so at the call site.
        """
        if obj is None or fw is None:
            return False
        if obj.id == fw.id:
            return True

        if isinstance(obj, Interface):
            # ``ObjectMatcher::dispatch(Interface*)`` (ObjectMatcher.cpp:276)
            # has five lines and the port had the first one.  An interface
            # of *another* device whose single address is one the firewall
            # carries is the firewall too - a machine reachable under one
            # address described from both ends, which is the same shape the
            # Host branch below answers for and the standalone address in
            # ``_address_is_on_the_firewall`` one level down.
            if obj.device_id == fw.id:
                return True
            if not obj.is_regular():
                return False
            addresses = list(getattr(obj, 'addresses', []))
            # The C++ gives up on more than one address per family, because
            # `getAddressPtr()` would answer for the first one alone and
            # the others would go unasked.
            if len([a for a in addresses if a.is_v4()]) > 1:
                return False
            if len([a for a in addresses if a.is_v6()]) > 1:
                return False
            address = _first_inet_address(obj)
            if address is None:
                return False
            return self._single_address_matches(
                address, fw, recognize_broadcasts, recognize_multicasts
            )

        if isinstance(obj, Host):
            # ``ObjectMatcher::dispatch(Host*)`` (ObjectMatcher.cpp:453):
            # a host is the firewall when *every* one of its interfaces
            # is, which is how a machine modelled twice - once as the
            # Firewall object and once as a Host, in another library or
            # in a rule written before the firewall object existed - is
            # still recognised.  The port answered False for every host
            # there is, so such a rule was chained as if it were about
            # some other machine: into FORWARD, where the firewall's own
            # traffic never goes.  Same shape as the standalone address
            # of ``_address_is_on_the_firewall`` one level up.
            #
            # ``dispatch(Firewall*)`` and ``dispatch(Cluster*)`` end in
            # the same loop, and both derive from Host here, so they are
            # covered by it.
            #
            # A host with no interfaces at all answers True, because the
            # C++ starts from ``res = true`` and never enters the loop.
            # Faithful and harmless: such an object contributes no
            # address, so the rule element is emptied and the rule is
            # dropped long before the chain decision matters.
            for iface in getattr(obj, 'interfaces', []):
                address = _first_inet_address(iface)
                if address is None:
                    # ``checkComplexMatchForSingleAddress(Address*, ...)``
                    # answers False for an object with no address at all,
                    # so one unnumbered interface is enough to say no.
                    return False
                if not self._single_address_matches(
                    address, fw, recognize_broadcasts, recognize_multicasts
                ):
                    return False
            return True

        if isinstance(obj, AddressRange):
            # Matches if any of the firewall's interface addresses
            # falls inside the [start, end] range (fwbuilder's
            # InetAddrMask range comparison, #2650).  Also matches
            # broadcast / multicast ranges when those flags are set -
            # fwbuilder recognises the standard-library "broadcast"
            # AddressRange (255.255.255.255-255.255.255.255) and any
            # range falling into the multicast space as "matches fw"
            # so that rules targeting them land in INPUT rather than
            # FORWARD (fwbuilder #811860, b=m=true).
            start = obj.get_start_address()
            end = obj.get_end_address()
            if not start or not end:
                return False
            try:
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)
            except ValueError:
                return False
            # ``ObjectMatcher::dispatch(AddressRange*)`` asks the two ends
            # separately, and one of them answering is enough.
            for end_point in (start_ip, end_ip):
                if int(end_point) == 0:
                    continue
                if recognize_broadcasts and _is_broadcast_address(end_point):
                    return True
                if recognize_multicasts and end_point.is_multicast:
                    return True
            # The "old broadcast" 0.0.0.0-0.0.0.0 of the standard library.
            if recognize_broadcasts and start_ip == end_ip and int(start_ip) == 0:
                return True
            for iface in fw.interfaces:
                for addr in getattr(iface, 'addresses', []):
                    addr_str = (
                        addr.get_address() if hasattr(addr, 'get_address') else ''
                    )
                    if not addr_str:
                        continue
                    try:
                        ip = ipaddress.ip_address(addr_str)
                    except ValueError:
                        continue
                    if ip.version != start_ip.version:
                        continue
                    if start_ip <= ip <= end_ip:
                        return True
            return False

        if isinstance(obj, Address):
            # Check if address belongs to a firewall interface
            if obj.interface_id is not None:
                for iface in fw.interfaces:
                    if iface.id == obj.interface_id:
                        return True

            addr_str = obj.get_address()
            if not addr_str:
                return False
            try:
                ip = ipaddress.ip_address(addr_str)
            except ValueError:
                return False

            if _is_broadcast_or_multicast(
                ip, recognize_broadcasts, recognize_multicasts
            ):
                return True

            if isinstance(obj, (Network, NetworkIPv6)):
                # ``ObjectMatcher::dispatch(Network*)`` stops here unless
                # the mask covers a single address.  A network the firewall
                # merely has an address on is not the firewall - whether it
                # counts is the "assume firewall is part of any and
                # networks" question, which the callers ask separately.
                mask = obj.get_netmask()
                if not mask or not _is_host_mask(mask, ip.version):
                    return False

            return self._address_is_on_the_firewall(ip, fw, recognize_broadcasts)

        return False

    def _single_address_matches(
        self, ip, fw, recognize_broadcasts: bool, recognize_multicasts: bool
    ) -> bool:
        """Whether one bare address is the firewall.

        ``ObjectMatcher::checkComplexMatchForSingleAddress(const InetAddr*,
        FWObject*)`` whole: the broadcast / multicast shortcut, and then
        every address of every interface of the firewall.
        """
        return _is_broadcast_or_multicast(
            ip, recognize_broadcasts, recognize_multicasts
        ) or self._address_is_on_the_firewall(ip, fw, recognize_broadcasts)

    @staticmethod
    def _address_is_on_the_firewall(ip, fw, recognize_broadcasts: bool) -> bool:
        """Whether *ip* is an address of one of the firewall's interfaces.

        Ports the tail of
        ``ObjectMatcher::checkComplexMatchForSingleAddress``, which walks
        every address of every interface of the firewall and compares
        through ``matchRHS``.  With broadcasts recognised that comparison
        also answers for the network address and the broadcast address of
        the subnet each interface address defines - a packet to either
        travels in a broadcast frame and is delivered locally, which is
        fwbuilder's bug #1040773.

        The port only ever asked whether the object *is* a child of an
        interface, so a standalone address object carrying the firewall's
        own address was not the firewall, and every rule naming one was
        chained as if it were about some other host.
        """
        for iface in fw.interfaces:
            for addr in getattr(iface, 'addresses', []):
                addr_str = addr.get_address() if hasattr(addr, 'get_address') else ''
                if not addr_str:
                    continue
                try:
                    rhs = ipaddress.ip_address(addr_str)
                except ValueError:
                    continue
                if rhs.version != ip.version:
                    continue
                if rhs == ip:
                    return True
                if not recognize_broadcasts:
                    continue
                mask = addr.get_netmask() if hasattr(addr, 'get_netmask') else ''
                if not mask:
                    continue
                try:
                    net = ipaddress.ip_network(f'{addr_str}/{mask}', strict=False)
                except ValueError:
                    continue
                if ip in (net.network_address, net.broadcast_address):
                    return True
        return False

    def find_address_for(self, obj1, obj2) -> Address | Interface | None:
        """Find address of obj2 that matches network of obj1.

        Scans all interfaces of obj2 looking for an address that belongs
        to the network described by obj1.
        """
        if not isinstance(obj2, Host):
            return None

        obj1_addr = obj1.get_address() if isinstance(obj1, Address) else ''
        if not obj1_addr:
            return None

        for iface in obj2.interfaces:
            if isinstance(obj1, Interface) and iface.id == obj1.id:
                return iface

            if not iface.is_regular():
                continue

            for addr in iface.addresses:
                if _check_addresses_match(addr, obj1):
                    return addr

        return None

    def find_interface_for(self, obj1, obj2) -> Interface | None:
        """The interface of *obj2* on the network *obj1* is on.

        ``Compiler::findInterfaceFor`` (Compiler_object_match.cpp:72), the
        same walk as :meth:`find_address_for` one method up, answering with
        the interface rather than with the address that matched.  The two
        are written side by side in the C++ for that reason, and here they
        share ``_check_addresses_match`` - which since it learnt that the
        netmask on an interface address describes the network the
        interface is on, is a different answer than a containment test
        written out by hand.

        The identity line is the one the two NAT compilers had each
        dropped from their own copy: an object that *is* one of the
        interfaces answers with itself, whatever addresses it carries.
        That is the only branch an interface with no address at all can
        take.
        """
        if not isinstance(obj2, Host):
            return None

        # An Interface derives from Address in fwbuilder, so `obj1` may be
        # one and `getAddressPtr()` then answers with the address it
        # carries.  It does not derive from Address here, so the address
        # object has to be picked out before the comparison.
        target = obj1
        if isinstance(obj1, Interface):
            target = _first_inet_address_object(obj1)

        for iface in obj2.interfaces:
            if obj1 is not None and iface.id == getattr(obj1, 'id', None):
                return iface

            if not iface.is_regular() or target is None:
                continue

            for addr in iface.addresses:
                if _check_addresses_match(addr, target):
                    return iface

        return None


def _addr_sort_key(obj):
    """Sort key for address objects: sort by numeric IP address."""
    if isinstance(obj, Address):
        addr_str = obj.get_address()
        if addr_str:
            try:
                return (0, int(ipaddress.ip_address(addr_str)))
            except ValueError:
                pass
    name = getattr(obj, 'name', '')
    return (1, name)


def _defines_a_subnet(obj) -> bool:
    """Whether *obj* stands for a subnet rather than for one address.

    ``Compiler::checkIfAddressesMatch`` asks that of both sides, and it
    counts two shapes: a Network object, and an address that hangs under
    an interface - the netmask an interface carries describes the network
    the interface is on, which is exactly what the question is about.
    Only the first shape was ported, so an interface never contributed
    its own subnet and the answer was one-sided.
    """
    if isinstance(obj, (Network, NetworkIPv6)):
        return True
    return isinstance(obj, Address) and obj.interface_id is not None


def _check_addresses_match(a1, a2) -> bool:
    """Check if two address objects match (same address or same network)."""
    if a1.id == a2.id:
        return True

    addr1 = a1.get_address() if isinstance(a1, Address) else ''
    addr2 = a2.get_address() if isinstance(a2, Address) else ''
    if not addr1 or not addr2:
        return False

    if addr1 == addr2:
        return True

    # Check if one belongs to the other's network
    try:
        ip1 = ipaddress.ip_address(addr1)
        ip2 = ipaddress.ip_address(addr2)
        mask2 = a2.get_netmask() if isinstance(a2, Address) else ''
        mask1 = a1.get_netmask() if isinstance(a1, Address) else ''

        if mask2 and _defines_a_subnet(a2):
            net2 = ipaddress.ip_network(f'{addr2}/{mask2}', strict=False)
            if ip1 in net2:
                return True

        if mask1 and _defines_a_subnet(a1):
            net1 = ipaddress.ip_network(f'{addr1}/{mask1}', strict=False)
            if ip2 in net1:
                return True
    except ValueError:
        pass

    return False
