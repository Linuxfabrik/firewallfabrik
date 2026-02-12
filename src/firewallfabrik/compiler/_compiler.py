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

from firewallfabrik.compiler._base import BaseCompiler, CompilerStatus
from firewallfabrik.compiler._comp_rule import CompRule, expand_group
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor, Debug
from firewallfabrik.core.objects import (
    Address,
    AddressTable,
    DNSName,
    Firewall,
    Group,
    Host,
    Interface,
    IPv4,
    IPv6,
    MultiAddress,
    Network,
    NetworkIPv6,
    RuleSet,
)

if TYPE_CHECKING:
    import sqlalchemy.orm


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

        self._current_rule_label: str = ''
        self._rule_counter: int = 0

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
        """Emit a warning formatted as fwname:rsname:pos: warning: msg."""
        if msg is None:
            super().warning(rule_or_msg)
        else:
            fw_name = self.fw.name if self.fw else ''
            rs_name = self.source_ruleset.name if self.source_ruleset else ''
            pos = ''
            if hasattr(rule_or_msg, 'position'):
                pos = str(rule_or_msg.position)
            formatted = f'{fw_name}:{rs_name}:{pos}: warning: {msg}'
            self._warnings.append(formatted)
            label = getattr(rule_or_msg, 'label', '') or ''
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

        Compile-time MultiAddress objects (DNSName, AddressTable) have
        already been resolved by the ``ResolveMultiAddress`` processor.
        Runtime MultiAddress objects are kept as-is.

        After expansion, elements are sorted by name to match C++
        Compiler::expandGroupsInRuleElement() which uses
        FWObjectNameCmpPredicate.
        """
        elements = getattr(comp_rule, slot)
        new_elements = []
        for obj in elements:
            if isinstance(obj, MultiAddress):
                # Runtime MultiAddress — keep as-is
                new_elements.append(obj)
            elif isinstance(obj, Group):
                members = expand_group(self.session, obj)
                new_elements.extend(members)
            else:
                new_elements.append(obj)
        new_elements.sort(key=lambda obj: getattr(obj, 'name', ''))
        setattr(comp_rule, slot, new_elements)

    def _resolve_multi_address(self, obj: MultiAddress) -> list:
        """Resolve a compile-time MultiAddress to Address objects.

        For DNSName: resolves hostname via DNS.
        For AddressTable: loads addresses from the referenced file.
        Falls back to obj.addresses if already populated.

        Matches C++ Preprocessor::convertObject() + DNSName::loadFromSource().
        """
        # If the object already has child addresses (e.g. previously resolved),
        # return them directly.
        if obj.addresses:
            return list(obj.addresses)

        if isinstance(obj, DNSName):
            return self._resolve_dns_name(obj)
        if isinstance(obj, AddressTable):
            return self._load_address_table(obj)

        return []

    def _resolve_dns_name(self, obj: DNSName) -> list:
        """Resolve a compile-time DNSName via DNS lookup."""
        dnsrec = (obj.data or {}).get('dnsrec', obj.name)
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
            ip_str = info[4][0]
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
        filename = (obj.data or {}).get('filename', '')
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
        for obj in elements:
            if isinstance(obj, Host) and not isinstance(obj, Interface):
                # Expand host to its interface addresses
                for iface in obj.interfaces:
                    if iface.is_loopback() and not on_loopback:
                        continue
                    for addr in iface.addresses:
                        if (self.ipv6_policy and addr.is_v6()) or (
                            not self.ipv6_policy and addr.is_v4()
                        ):
                            new_elements.append(addr)
            else:
                new_elements.append(obj)

        # Sort by address
        new_elements.sort(key=_addr_sort_key)
        setattr(comp_rule, slot, new_elements)

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

    def complex_match(
        self,
        obj,
        fw: Firewall,
        recognize_broadcasts: bool = False,
        recognize_multicasts: bool = False,
    ) -> bool:
        """Check if an address object matches the firewall.

        Returns True if obj is the firewall itself, one of its interfaces,
        an address on one of its interfaces, or (when flags set) a
        broadcast/multicast address.
        """
        if obj is None or fw is None:
            return False
        if obj.id == fw.id:
            return True

        if isinstance(obj, Interface):
            return obj.device_id == fw.id

        if isinstance(obj, Host):
            return False

        if isinstance(obj, Address):
            # Check if address belongs to a firewall interface
            if obj.interface_id is not None:
                for iface in fw.interfaces:
                    if iface.id == obj.interface_id:
                        return True

            addr_str = obj.get_address()
            if addr_str:
                if recognize_broadcasts and obj.is_broadcast():
                    return True
                if recognize_broadcasts and obj.is_any():
                    return True
                try:
                    ip = ipaddress.ip_address(addr_str)
                    if recognize_multicasts and ip.is_multicast:
                        return True
                except ValueError:
                    pass

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

        if mask2 and isinstance(a2, (Network, NetworkIPv6)):
            net2 = ipaddress.ip_network(f'{addr2}/{mask2}', strict=False)
            if ip1 in net2:
                return True

        if mask1 and isinstance(a1, (Network, NetworkIPv6)):
            net1 = ipaddress.ip_network(f'{addr1}/{mask1}', strict=False)
            if ip2 in net1:
                return True
    except ValueError:
        pass

    return False
