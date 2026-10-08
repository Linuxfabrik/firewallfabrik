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

"""Interface name validation per platform."""

from __future__ import annotations

import re

from firewallfabrik.core.objects import (
    Interface,
)

#: The failover protocols whose shared address the generated script puts
#: on the interface itself, rather than leaving it to the daemon.  Empty
#: on Linux: `res/os/linux24.xml` sets `manage_addresses` False for vrrp,
#: heartbeat and openais.  It is a set rather than a constant because the
#: question is per protocol, and a resource file is where the answer comes
#: from.
FAILOVER_PROTOCOLS_MANAGING_ADDRESSES: frozenset[str] = frozenset()

#: The failover protocols whose cluster interface may carry no address at
#: all.  `no_ip_ok` in `res/os/linux24.xml`: True for heartbeat, openais
#: and "none", False for vrrp, which needs one.  Every other regular
#: interface without an address is refused, because a rule naming it
#: compiles into an element that matches everything.
FAILOVER_PROTOCOLS_WITHOUT_AN_ADDRESS: frozenset[str] = frozenset(
    {'heartbeat', 'none', 'openais'}
)


def get_interface_var_name(iface: Interface, suffix: str = '') -> str:
    """Generate a shell variable name for an interface.

    Replaces characters not valid in shell variable names with underscores.
    E.g., "eth0.100" -> "i_eth0_100"
    """
    name = iface.name
    # Replace non-alphanumeric characters with underscore
    var_name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    if suffix:
        return f'i_{var_name}_{suffix}'
    return f'i_{var_name}'


class InterfaceProperties:
    """Platform-agnostic interface validation and name checking."""

    # -- Names and the interface hierarchy (compiler_lib/interfaceProperties.cpp)

    def parse_vlan(self, name: str) -> tuple[str, int] | None:
        """Return ``(base name, vlan id)`` if *name* looks like a VLAN.

        ``interfaceProperties::parseVlan`` knows no VLAN; the platform
        subclass does.
        """
        return None

    def looks_like_vlan(self, name: str) -> bool:
        """``interfaceProperties::looksLikeVlanInterface``."""
        return self.parse_vlan(name) is not None

    def basic_name_problem(self, name: str) -> str:
        """``basicValidateInterfaceName``: no white space and no "-"."""
        if ' ' in name or '-' in name:
            return f'Interface name \'{name}\' can not contain white space and "-"'
        return ''

    def vlan_name_problem(self, name: str, parent_name: str) -> str:
        """``interfaceProperties::isValidVlanInterfaceName`` (interfaceProperties.cpp:98).

        A VLAN name has to name its parent interface ("eth0.100" under
        "eth0"; "vlan100" anywhere), and the VLAN id has to fit in twelve
        bits.  An empty *parent_name* skips the first check: a cluster may
        have top-level VLAN interfaces, and a VLAN may be a bridge port.
        """
        parsed = self.parse_vlan(name)
        if parsed is None:
            return f"'{name}' is not a valid vlan interface name"
        base, vlan_id = parsed
        if parent_name and base != 'vlan' and parent_name != base:
            return (
                f"'{name}' looks like a name of a vlan interface but it does "
                f"not match the name of the parent interface '{parent_name}'"
            )
        if vlan_id > 4095:
            return (
                f"'{name}' looks like a name of a vlan interface but vlan ID "
                f'it defines is outside of the valid range.'
            )
        return ''

    def interface_problem(self, target, iface=None, *, name=None) -> str:
        """Return why an interface may not become a child of *target*, or ''.

        ``interfaceProperties::validateInterface`` (interfaceProperties.cpp:246
        and :346), which ``FWBTree::validateForInsertion`` and
        ``InterfaceDialog::validate`` ask for every interface placed under a
        firewall, a cluster or another interface.  *iface* is the
        interface object; *name* overrides its name, for a rename that is
        not stored yet.
        """
        from firewallfabrik.core.objects import Cluster, Host

        name = name if name is not None else iface.name
        if (
            iface is not None
            and isinstance(target, Interface)
            and (target.parent_interface_id is not None or iface.sub_interfaces)
        ):
            return (
                f'Interface {name} can not become subinterface of '
                f'{target.name} because only one level of subinterfaces '
                f'is allowed.'
            )
        if iface is not None and isinstance(target, Cluster):
            parent = iface.parent_interface
            if parent is not None:
                own_type = (iface.options or {}).get('type') or 'ethernet'
                parent_type = (parent.options or {}).get('type') or 'ethernet'
                if parent_type == 'bridge' and own_type == 'ethernet':
                    return (
                        f'Interface {name} is a bridge port, it can not belong '
                        f'to a cluster'
                    )
                if parent_type == 'bonding' and own_type == 'ethernet':
                    return (
                        f'Interface {name} is a bonding interface slave, it can '
                        f'not belong to a cluster'
                    )

        if isinstance(target, Host):
            if self.looks_like_vlan(name):
                parent_name = '' if isinstance(target, Cluster) else target.name
                return self.vlan_name_problem(name, parent_name)
            return ''
        if isinstance(target, Interface):
            target_type = (target.options or {}).get('type') or ''
            if self.looks_like_vlan(name):
                parent_name = '' if target_type == 'bridge' else target.name
                return self.vlan_name_problem(name, parent_name)
            if target_type not in ('bridge', 'bonding'):
                return (
                    f'Interface {name} which is not a vlan can only be a '
                    f'subinterface of a bridge or bonding interface'
                )
            return ''
        return f'Interface can not be a child object of {type(target).__name__}'

    def is_eligible_for_cluster(self, iface: Interface) -> bool:
        """Whether *iface* can stand behind a cluster interface.

        Ports ``interfaceProperties::isEligibleForCluster`` (fwbuilder
        ticket #727): a bridge port cannot, a VLAN, bridge or bond
        interface can, and an Ethernet interface cannot when it is a port
        of a bridge, a slave of a bond, or the parent of VLAN
        sub-interfaces - in each of those cases the address, and so the
        failover, lives on the other interface.  The loopback is eligible,
        as in Firewall Builder, and gets the failover protocol None in the
        New Cluster wizard if no failover rules are wanted on it.
        """
        if iface.is_bridge_port():
            return False
        iface_type = iface.get_option('type', '') or 'ethernet'
        if iface_type in ('8021q', 'bridge', 'bonding'):
            return True
        if iface_type != 'ethernet':
            return True
        parent = iface.parent_interface
        if parent is not None and parent.get_option('type', '') == 'bridge':
            return False
        device = iface.device
        for other in device.interfaces if device is not None else ():
            other_parent = other.parent_interface
            if (
                other_parent is not None
                and other_parent.get_option('type', '') == 'bonding'
                and other.name == iface.name
            ):
                return False
        return not iface.sub_interfaces

    def manage_ip_addresses(
        self,
        iface: Interface,
    ) -> tuple[bool, list[str], list[str]]:
        """Which addresses of *iface* the generated script configures.

        Returns ``(should_manage, update_addresses, ignore_addresses)``,
        the three arguments of the ``update_addresses_of_interface`` shell
        function: whether to emit the call at all, the addresses the
        interface is to end up with, and the addresses the function must
        leave exactly as it finds them.

        Ports ``interfaceProperties::manageIpAddresses``.  The second list
        exists for clusters: the address a failover group shares is put on
        and taken off the interface by keepalived, heartbeat or corosync,
        and none of the three wants it managed from outside
        (``manage_addresses`` is false for every one of them in Firewall
        Builder's host OS resource file).  So the copy of a cluster
        interface configures nothing of its own, and the member's own
        interface of that name says "ignore the shared address" - without
        which the script would take the address away from whichever member
        is master, on every activation, and add it on the other one at the
        same time.
        """
        update_addresses: list[str] = []
        ignore_addresses: list[str] = []

        if (
            iface.is_dynamic()
            or iface.is_bridge_port()
            or iface.is_slave()
            or iface.is_unnumbered()
        ):
            return False, update_addresses, ignore_addresses

        if iface.cluster_interface:
            if iface.is_loopback():
                return False, update_addresses, ignore_addresses
            if self._failover_manages_addresses(iface):
                return True, self._get_list_of_addresses(iface), ignore_addresses
            return False, update_addresses, ignore_addresses

        update_addresses = self._get_list_of_addresses(iface)
        device = iface.device
        for other in getattr(device, 'interfaces', []) or []:
            # Only a cluster interface that runs a failover protocol has an
            # address somebody else owns.  The C++ asks
            # `isFailoverInterface()` before it asks the protocol
            # (`interfaceProperties::manageIpAddresses`), and without that
            # question every cluster interface without a group - a cluster's
            # loopback, for one - puts the member's own addresses of that
            # name on the ignore list, and the script then never configures
            # or corrects them.
            if (
                other.name == iface.name
                and other.cluster_interface
                and self._runs_a_failover_protocol(other)
                and not self._failover_manages_addresses(other)
            ):
                ignore_addresses = self._get_list_of_addresses(other)
                break
        return True, update_addresses, ignore_addresses

    @staticmethod
    def _runs_a_failover_protocol(cluster_iface: Interface) -> bool:
        """Does a failover group hang under this cluster interface?

        ``Interface::isFailoverInterface`` asks the object tree; the copy
        the driver makes for the member points back at the group under the
        cluster instead, so it is the id in its options that answers here
        (the same value ``AutomaticRules`` reads).
        """
        return bool(cluster_iface.get_option('failover_group_id', ''))

    @staticmethod
    def _failover_manages_addresses(cluster_iface: Interface) -> bool:
        """Does the failover protocol want its address configured for it?

        `manage_addresses` in Firewall Builder's host OS resource file,
        which says False for vrrp, heartbeat and openais alike - on Linux
        the daemon owns the address, and taking it away from under one is
        what the ignore list exists to prevent.  A cluster interface with
        no failover group (the loopback of a cluster) answers False too:
        there is no protocol to ask.
        """
        protocol = (cluster_iface.options or {}).get('failover_protocol', '')
        return protocol in FAILOVER_PROTOCOLS_MANAGING_ADDRESSES

    @staticmethod
    def _get_list_of_addresses(iface: Interface) -> list[str]:
        """The addresses of *iface* as ``addr/prefix``, IPv6 ones first.

        ``interfaceProperties::getListOfAddresses`` collects the IPv4 and
        the IPv6 children separately and splices the IPv6 list onto the
        *front*, so that is the order the list is written in.  The shell
        function sorts what it is given before it compares, so nothing
        turns on it - but the two compilers writing the same interface out
        differently is noise in every diff against the reference.
        """
        import ipaddress

        v4: list[str] = []
        v6: list[str] = []
        for addr_obj in iface.addresses:
            addr_str = addr_obj.get_address()
            mask_str = addr_obj.get_netmask()
            if not addr_str or not mask_str:
                continue
            try:
                net = ipaddress.ip_network(f'{addr_str}/{mask_str}', strict=False)
            except ValueError:
                v4.append(f'{addr_str}/{mask_str}')
                continue
            (v6 if net.version == 6 else v4).append(f'{addr_str}/{net.prefixlen}')
        return v6 + v4


# ``linux24Interfaces::parseVlan`` (linux24Interfaces.cpp:41).  Qt's
# ``indexOf`` searches, so these are searched for, not matched in full.
_LINUX_VLAN_PATTERNS = (
    re.compile(r'([a-zA-Z0-9-]+\d{1,})\.(\d{1,})'),
    re.compile(r'(vlan)(\d{1,})'),
)


class LinuxInterfaceProperties(InterfaceProperties):
    """Linux-specific interface validation (``linux24Interfaces``)."""

    def parse_vlan(self, name: str) -> tuple[str, int] | None:
        for pattern in _LINUX_VLAN_PATTERNS:
            match = pattern.search(name or '')
            if match:
                return match.group(1), int(match.group(2))
        return None

    def basic_name_problem(self, name: str) -> str:
        """Linux allows "-" (OpenWRT ``ppp-dsl``, fwbuilder #1856), not spaces."""
        if ' ' in name:
            return f"Interface name '{name}' can not contain white space"
        return ''

    def interface_problem(self, target, iface=None, *, name=None) -> str:
        name = name if name is not None else iface.name
        return self.basic_name_problem(name) or super().interface_problem(
            target, iface, name=name
        )
