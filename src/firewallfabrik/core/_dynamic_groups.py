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

"""Which objects a Dynamic Group selects.

Port of ``DynamicGroup::loadFromSource`` and ``isMemberOfGroup``
(fwbuilder5 DynamicGroup.cpp:148, :172), shared by the compiler and the
editor so that the list the editor shows is the list that is compiled.
"""

import sqlalchemy

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    ObjectGroup,
    placeholder_kind,
)

TYPE_NONE = 'none'
TYPE_ANY = 'any'
KEYWORD_NONE = ','
KEYWORD_ANY = ''

DELETED_OBJECTS_LIBRARY = 'Deleted Objects'

# Firewall Builder walks the whole tree.  Its objects live in four tables
# here; services and intervals cannot be members, rule sets and libraries
# are no objects a rule can name.
_CANDIDATE_CLASSES = (Address, Group, Host, Interface)


def object_type_name(obj) -> str:
    """Return the type name the criteria compare against.

    Every model class carries its type in ``type`` except ``Interface``,
    which is a table of its own without a discriminator.
    """
    return getattr(obj, 'type', None) or type(obj).__name__


def _is_eligible(obj) -> bool:
    """``ObjectGroup::cast(obj) || Address::cast(obj)``.

    ``Address::cast`` holds for every address object, for Host, Firewall
    and Cluster, and for Interface (``class Interface : public Address``,
    Interface.h:43).  ``ObjectGroup::cast`` holds for object groups and
    everything derived from them: Address Table, DNS Name, Attached
    Networks, Dynamic Group and the failover and state sync groups of a
    cluster.  Service and time groups are no object groups.
    """
    return isinstance(obj, (Address, Host, Interface, ObjectGroup))


def _library(obj):
    """Return the library *obj* lives in, following its parents."""
    seen = set()
    while obj is not None and id(obj) not in seen:
        seen.add(id(obj))
        library = getattr(obj, 'library', None)
        if library is not None:
            return library
        obj = (
            getattr(obj, 'interface', None)
            or getattr(obj, 'parent_interface', None)
            or getattr(obj, 'device', None)
            or getattr(obj, 'parent_group', None)
            or getattr(obj, 'group', None)
        )
    return None


def _distance_from_root(group) -> int:
    """``FWObject::getDistanceFromRoot`` for a group.

    The database is 0 and a library 1, so a top-level folder is 2 and a
    group inside one of the standard folders 4.  A group below a device
    or an interface - a state sync or failover group, Attached Networks -
    sits deeper than any standard folder.
    """
    if getattr(group, 'interface_id', None) or getattr(group, 'device_id', None):
        return 4
    depth = 2
    parent = getattr(group, 'parent_group', None)
    while parent is not None:
        depth += 1
        parent = getattr(parent, 'parent_group', None)
    return depth


def is_dynamic_group_member(obj, criteria, match_mode: str = 'AND') -> bool:
    """Return whether *obj* matches *criteria* under *match_mode*.

    *criteria* is a list of ``(type, keyword)`` pairs; a pair naming
    ``TYPE_NONE`` or ``KEYWORD_NONE`` is not a criterion.  *match_mode* is
    ``'OR'``, Firewall Builder's only mode, or ``'AND'``, the default of a
    group created here.

    Deliberately unlike Firewall Builder, the Standard library's "Any"
    and "Dummy" placeholders are never members: "any type, any keyword"
    would otherwise put 0.0.0.0/0 into the group and make it match every
    address.
    """
    if not _is_eligible(obj):
        return False
    if placeholder_kind(obj):
        return False
    library = _library(obj)
    if library is None or library.name == DELETED_OBJECTS_LIBRARY:
        return False
    # "There's no way to figure out what are the "standard" object groups
    # [...] so we rely on counting how deep we are in the tree instead."
    if isinstance(obj, ObjectGroup) and _distance_from_root(obj) <= 3:
        return False

    obj_type = object_type_name(obj)
    keywords = getattr(obj, 'keywords', None) or set()
    active = [
        (type_val in (TYPE_ANY, obj_type))
        and (keyword_val == KEYWORD_ANY or keyword_val in keywords)
        for type_val, keyword_val in criteria
        if type_val != TYPE_NONE and keyword_val != KEYWORD_NONE
    ]
    if not active:
        return False
    if match_mode == 'OR':
        return any(active)
    return all(active)


def dynamic_group_members(session, group, criteria, match_mode='AND') -> list:
    """Return the objects of the database *group* selects, sorted by name."""
    members = []
    for cls in _CANDIDATE_CLASSES:
        for obj in session.scalars(sqlalchemy.select(cls)).unique():
            if obj.id == group.id:
                continue
            if is_dynamic_group_member(obj, criteria, match_mode):
                members.append(obj)
    members.sort(key=lambda o: getattr(o, 'name', ''))
    return members
