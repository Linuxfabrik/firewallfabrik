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

"""What may go where: Firewall Builder's ``validateChild``, ported once.

Firewall Builder answers "may this object go in there?" in one place per
container, the ``validateChild`` of the container's class, and every path
that inserts something - a drop, a paste, the "Group" action, Find and
Replace - asks it.  Most of them are exclusion lists ("anything but a
service"), not lists of what is allowed.  The editor here once answered
the question in each path for itself, with a list of allowed types taken
from the "New object" menu (``getAllowedTypesOfChildren``), which is a
different question, and so refused interfaces as group members (#189).

Each function below names the function it ports and keeps its form.
Where it deviates, the docstring says so and why.  Line numbers refer to
the fwbuilder5 tree.
"""

import ipaddress

from firewallfabrik.core.objects import (
    Address,
    Cluster,
    ClusterGroup,
    FailoverClusterGroup,
    Firewall,
    Group,
    Host,
    Interface,
    Interval,
    IntervalGroup,
    IPv4,
    IPv6,
    Library,
    Network,
    NetworkIPv6,
    ObjectGroup,
    PhysAddress,
    Routing,
    Rule,
    RuleSet,
    Service,
    ServiceGroup,
    StateSyncClusterGroup,
    TagService,
)

# Rule element slots by the container they are validated like.
ADDRESS_SLOTS = frozenset({'dst', 'odst', 'osrc', 'rdst', 'src', 'tdst', 'tsrc'})
SERVICE_SLOTS = frozenset({'osrv', 'srv', 'tsrv'})
INTERFACE_SLOTS = frozenset({'itf', 'itf_inb', 'itf_outb'})
# Elements that take one object (RuleElementRGtw / RuleElementRItf
# ::validateChild refuse a second child, RuleElement.cpp:661 and :699).
SINGLE_OBJECT_SLOTS = frozenset({'rgtw', 'ritf'})

# Never a member of anything and never in a rule: the containers of the
# tree itself.
_STRUCTURE = (Library, Rule, RuleSet)


def object_group_accepts(obj) -> bool:
    """``ObjectGroup::validateChild`` (ObjectGroup.cpp:59).

    Anything but a service, a service group, a time interval and a rule
    set: addresses, hosts, firewalls, clusters, interfaces, MAC addresses
    and every kind of object group, the cluster groups included.

    Deviation: a time interval *group* and a library are refused as well.
    Firewall Builder lets both through only because neither is an
    ``Interval`` or ``RuleSet``, and its compiler then aborts on them.
    """
    return not isinstance(
        obj, (Service, ServiceGroup, Interval, IntervalGroup, *_STRUCTURE)
    )


def service_group_accepts(obj) -> bool:
    """``ServiceGroup::validateChild`` (ServiceGroup.cpp:60).

    Anything but an address (which includes hosts, firewalls and
    interfaces), an object group, a time interval and a rule set - so
    services and service groups.  Deviation as above: a time interval
    group and a library are refused too.
    """
    return not isinstance(
        obj,
        (Address, Host, Interface, ObjectGroup, Interval, IntervalGroup, *_STRUCTURE),
    )


def interval_group_accepts(obj) -> bool:
    """``IntervalGroup::validateChild`` (IntervalGroup.cpp:43)."""
    return isinstance(obj, (Interval, IntervalGroup))


def cluster_group_accepts(obj) -> bool:
    """``ClusterGroup::validateChild`` (ClusterGroup.cpp:45): interfaces."""
    return isinstance(obj, Interface)


def group_accepts(group, obj) -> bool:
    """Return whether *obj* may become a member of *group*.

    Dispatches to the ``validateChild`` of the group's class, the way
    ``GroupObjectDialog::insertObject`` asks ``g->validateChild(o)``
    (GroupObjectDialog.cpp:343) and ``FWObject::addRef`` asks it for every
    other path.  A group never contains itself.
    """
    if getattr(obj, 'id', None) is not None and obj.id == getattr(group, 'id', None):
        return False
    if isinstance(group, ClusterGroup):
        return cluster_group_accepts(obj)
    if isinstance(group, ObjectGroup):
        return object_group_accepts(obj)
    if isinstance(group, ServiceGroup):
        return service_group_accepts(obj)
    if isinstance(group, IntervalGroup):
        return interval_group_accepts(obj)
    return False


def _contains_tag_service(obj, seen=None) -> bool:
    if isinstance(obj, TagService):
        return True
    if not isinstance(obj, Group):
        return False
    seen = seen if seen is not None else set()
    if obj.id in seen:
        return False
    seen.add(obj.id)
    return any(_contains_tag_service(m, seen) for m in obj.get_member_objects())


def is_interface_group(obj) -> bool:
    """The group branch of ``RuleElementItf::validateChild`` (RuleElement.cpp:315).

    An object group that is not empty and whose members are all exactly
    interfaces (``Interface::isA``), so a group of groups does not count.
    """
    if not isinstance(obj, ObjectGroup):
        return False
    members = obj.get_member_objects()
    return bool(members) and all(type(m) is Interface for m in members)


def _single_address_count(obj) -> int:
    """How many addresses a gateway candidate carries."""
    if isinstance(obj, Interface):
        return len([a for a in obj.addresses if isinstance(a, (IPv4, IPv6))])
    if isinstance(obj, Host):
        return sum(_single_address_count(i) for i in obj.interfaces)
    return 1


def is_gateway(obj) -> bool:
    """``RuleElementRGtw::checkSingleIPAdress`` (RuleElement.cpp:666).

    A host with one interface carrying one address, an interface carrying
    one address, or an address object.

    Deviation: an IPv6 address counts as well as an IPv4 one, because fwf
    installs IPv6 routes, and so does a network with a host mask, which is
    how the importer writes a gateway it found among the existing objects.
    """
    if isinstance(obj, Host):
        return len(obj.interfaces) == 1 and _single_address_count(obj) == 1
    if isinstance(obj, Interface):
        return _single_address_count(obj) == 1
    if isinstance(obj, (IPv4, IPv6)):
        return True
    if isinstance(obj, (Network, NetworkIPv6)):
        try:
            net = ipaddress.ip_network(
                f'{obj.get_address()}/{obj.get_netmask()}', strict=False
            )
        except ValueError:
            return False
        return net.prefixlen == net.max_prefixlen
    return False


def rule_element_accepts(slot: str, obj) -> bool:
    """Return whether *obj* may go into the rule element *slot*.

    The ``validateChild`` of each ``RuleElement`` class:

    - Src, Dst, OSrc, ODst, TSrc, TDst, RDst: ``ObjectGroup::validateChild``
    - Srv, OSrv: ``ServiceGroup::validateChild``
    - TSrv: the same, but no Tag Service, not even inside a service group
      (RuleElement.cpp:563)
    - Itf, ItfInb, ItfOutb: an interface, or a group of interfaces
      (RuleElement.cpp:315)
    - RItf: an interface (RuleElement.cpp:695)
    - RGtw: a single address (RuleElement.cpp:658)
    - When: an interval or an interval group (RuleElement.cpp:604)

    That the element takes one object only (RGtw, RItf) and that an
    interface belongs to the firewall (``checkItfChildOfThisFw``) depend
    on the rule, so :func:`rule_element_refusal` asks them.
    """
    if slot in ADDRESS_SLOTS:
        return object_group_accepts(obj)
    if slot == 'tsrv':
        return service_group_accepts(obj) and not _contains_tag_service(obj)
    if slot in SERVICE_SLOTS:
        return service_group_accepts(obj)
    if slot in INTERFACE_SLOTS:
        return isinstance(obj, Interface) or is_interface_group(obj)
    if slot == 'ritf':
        return isinstance(obj, Interface)
    if slot == 'rgtw':
        return is_gateway(obj)
    if slot == 'when':
        return interval_group_accepts(obj)
    return False


def _owning_firewall(obj):
    """Walk up from *obj* to the Firewall (or Cluster) it belongs to."""
    seen = set()
    while obj is not None and id(obj) not in seen:
        seen.add(id(obj))
        if isinstance(obj, Firewall):
            return obj
        obj = (
            getattr(obj, 'parent_interface', None)
            or getattr(obj, 'device', None)
            or getattr(obj, 'interface', None)
        )
    return None


def interface_belongs_to(fw, obj) -> bool:
    """``RuleElementItf::checkItfChildOfThisFw`` (RuleElement.cpp:377).

    An interface belongs when it is one of *fw*'s own (Firewall and
    Cluster alike); a group belongs when every member does.  Firewall
    Builder asks it in the editor only (``validateForInsertionToInterfaceRE``,
    RuleSetView.cpp:2371) - its compiler never checks - and an interface
    of another machine compiles into a rule about a device this one does
    not have.
    """
    if isinstance(obj, Group):
        return all(interface_belongs_to(fw, m) for m in obj.get_member_objects())
    owner = _owning_firewall(obj)
    return owner is not None and fw is not None and owner.id == fw.id


def rule_element_refusal(slot: str, obj, fw, current: list) -> str:
    """Return why *obj* may not go into *slot* of a rule of *fw*, or ''.

    Ports ``RuleSetView::validateForInsertion`` (RuleSetView.cpp:2388):
    the element's ``validateChild``, a second object in an element that
    takes one, a duplicate, and the firewall an interface belongs to.
    *current* is the list of objects the element holds now.
    """
    if not rule_element_accepts(slot, obj):
        if slot == 'ritf':
            return 'A single interface belonging to this firewall is expected here.'
        if slot == 'rgtw':
            return (
                'A single IP address is expected here. You may also insert a '
                'host or an interface that carries a single IP address.'
            )
        return f'"{obj.name}" cannot be used in this field.'
    if any(getattr(o, 'id', None) == obj.id for o in current):
        return f'"{obj.name}" is already in this field.'
    if slot in SINGLE_OBJECT_SLOTS and current:
        if slot == 'ritf':
            return 'A single interface belonging to this firewall is expected here.'
        return 'A single IP address is expected here.'
    if (slot in INTERFACE_SLOTS or slot == 'ritf') and not interface_belongs_to(
        fw, obj
    ):
        return f'"{obj.name}" is not an interface of this firewall.'
    return ''


def load_object(session, obj_id):
    """Return the model object with *obj_id* from whichever table holds it."""
    for cls in (Address, Group, Host, Interface, Interval, Service):
        obj = session.get(cls, obj_id)
        if obj is not None:
            return obj
    return None


def _type_name(obj) -> str:
    return getattr(obj, 'type', None) or type(obj).__name__


def incompatible(obj, target) -> str:
    """The refusal ``FWBTree::validateForInsertion`` words (FWBTree.cpp:412)."""
    return (
        f'Impossible to insert object {obj.name} (type {_type_name(obj)}) '
        f'into {target}\nbecause of incompatible type.'
    )


def rule_set_refusal(device, rule_set) -> str:
    """``Firewall::validateChild`` for a rule set (Firewall.cpp:205).

    A firewall or cluster takes any number of Policy and NAT rule sets and
    one Routing rule set ("there can be only one").  A host takes none.
    """
    if not isinstance(device, Firewall):
        return incompatible(rule_set, device.name)
    if isinstance(rule_set, Routing) and any(
        isinstance(rs, Routing) for rs in device.rule_sets
    ):
        return f'{device.name} already has a routing rule set, and it can have one.'
    return ''


def tree_child_refusal(target, obj) -> str:
    """Return why *obj* may not be pasted into *target*, or ''.

    The object branches of ``FWBTree::validateForInsertion`` (FWBTree.cpp:403):

    - a host, firewall or cluster takes interfaces; a firewall or cluster
      rule sets (:func:`rule_set_refusal`); a cluster state sync groups
      (``Cluster::validateChild``, Cluster.cpp:128)
    - an interface takes addresses and a MAC address, a failover group, and
      an interface as a sub-interface - but only one level of them
      (``Interface::validateChild``, Interface.cpp:351)
    - a group that is not a standard folder takes what its
      ``validateChild`` takes (:func:`group_accepts`)

    A standard folder and a library take an object only into its standard
    slot, which the caller answers from the tree.
    """
    if isinstance(target, Host):
        if isinstance(obj, Interface):
            return ''
        if isinstance(obj, RuleSet):
            return rule_set_refusal(target, obj)
        if isinstance(obj, StateSyncClusterGroup) and isinstance(target, Cluster):
            return ''
        return incompatible(obj, target.name)
    if isinstance(target, Interface):
        if isinstance(obj, (IPv4, IPv6, PhysAddress, FailoverClusterGroup)):
            return ''
        if isinstance(obj, Interface):
            if target.parent_interface_id is not None or obj.sub_interfaces:
                return (
                    f'Interface {obj.name} can not become subinterface of '
                    f'{target.name} because only one level of subinterfaces '
                    f'is allowed.'
                )
            return ''
        return incompatible(obj, target.name)
    if isinstance(target, Group):
        return '' if group_accepts(target, obj) else incompatible(obj, target.name)
    return incompatible(obj, getattr(target, 'name', ''))


def replace_kind(obj) -> str:
    """Return 'address', 'service' or '' for Find and Replace.

    ``FindObjectWidget::validateReplaceObject`` (FindObjectWidget.cpp:509)
    lets an object replace another of the same kind: address-like is
    ``Address::cast``, ``MultiAddress::cast`` or ``ObjectGroup::cast`` -
    which takes in hosts, firewalls, interfaces, dynamic and cluster
    groups - and service-like a service or a service group.
    """
    if isinstance(obj, (Address, Host, Interface, ObjectGroup)):
        return 'address'
    if isinstance(obj, (Service, ServiceGroup)):
        return 'service'
    return ''
