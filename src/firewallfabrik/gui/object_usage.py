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

"""Which firewalls are affected by a change to an object.

The compile dialog and the bold tree entry both read the
``lastModified`` of a firewall, so whatever is not stamped here is a
firewall the administrator is never offered - it keeps running a script
built against an object that has since changed or gone.

Two hierarchies lead from an object to the firewalls that care about it,
and a rule can reach it through either:

* group membership, transitively - Firewall Builder's
  ``UsageResolver::findWhereUsedRecursively``;
* containment, address -> interface -> parent interfaces -> device,
  because a rule names the host and never the address object under its
  interface (issue #159).
"""

import uuid

import sqlalchemy

from firewallfabrik.core._util import OPTION_REF_KEYS
from firewallfabrik.core.objects import (
    Address,
    Cluster,
    Firewall,
    Host,
    Interface,
    Rule,
    RuleSet,
    group_membership,
    rule_elements,
)


def containment_chain(obj):
    """Return *obj* and every object that contains it, innermost first.

    A rule never names the address under an interface; it names the
    interface, or the host the interface belongs to.  So the question
    "who is affected by this change" cannot be asked of the edited
    object alone - changing the IP of a host changes every rule that
    names *the host*, and nothing at all references the address object
    itself.  The chain is address → interface → parent interfaces →
    device, which is the containment fwbuilder walks in
    ``FWObject::getParent()``.
    """
    chain = []
    seen = set()
    current = obj
    while current is not None and getattr(current, 'id', None) not in seen:
        seen.add(current.id)
        chain.append(current)
        if isinstance(current, Address):
            current = current.interface
        elif isinstance(current, Interface):
            current = current.parent_interface or current.device
        else:
            current = None
    return chain


def find_referencing_firewalls(session, target):
    """Find every Firewall whose rules reference *target*.

    *target* is an ORM object, whose containment chain is followed, or
    an id, or an iterable of ids - the delete path already knows the
    whole subtree it is about to remove and has nothing left to walk.

    Two hierarchies are walked, because a rule can name the object
    through either of them:

    * the group hierarchy (transitively), so editing a member of a
      ServiceGroup also stamps the firewalls using that group - this is
      fwbuilder's ``UsageResolver::findWhereUsedRecursively``;
    * the containment hierarchy, so editing the address under an
      interface also stamps the firewalls whose rules name *the
      interface* or *the host*.  Nothing ever references the address
      object itself, which is why asking about it alone finds nobody
      (#159).
    """
    if isinstance(target, uuid.UUID | str):
        seeds = [target]
    elif isinstance(target, set | frozenset | list | tuple):
        seeds = list(target)
    else:
        seeds = [o.id for o in containment_chain(target)]

    # Collect the seeds plus all groups (transitively) containing them.
    search_ids = set(seeds)
    queue = list(seeds)
    while queue:
        member_id = queue.pop()
        parent_group_ids = set(
            session.scalars(
                sqlalchemy.select(group_membership.c.group_id).where(
                    group_membership.c.member_id == member_id,
                ),
            ).all()
        )
        for gid in parent_group_ids:
            if gid not in search_ids:
                search_ids.add(gid)
                queue.append(gid)

    # Find every Firewall that references any of these IDs in its rules.
    device_ids = set(
        session.scalars(
            sqlalchemy.select(RuleSet.device_id)
            .distinct()
            .join(Rule, Rule.rule_set_id == RuleSet.id)
            .join(rule_elements, rule_elements.c.rule_id == Rule.id)
            .where(rule_elements.c.target_id.in_(search_ids)),
        ).all()
    )
    # A rule also names a rule set it branches into and a Tag Service it
    # tags with, in its options rather than in an element.
    for rule, _key in find_option_references(session, search_ids):
        rule_set = session.get(RuleSet, rule.rule_set_id)
        if rule_set is not None:
            device_ids.add(rule_set.device_id)

    firewalls = []
    for did in device_ids:
        fw = session.get(Host, did)
        if isinstance(fw, Firewall):
            firewalls.append(fw)
    return firewalls


def find_option_references(session, obj_ids):
    """Return ``[(rule, key)]`` for every rule naming one of *obj_ids* in its options.

    Besides its rule elements a rule names the rule set a Branch rule
    jumps into (``branch_id``) and the Tag Service a tagging rule marks
    with (``tagobject_id``).  ``FWObjectDatabase::findWhereObjectIsUsed``
    counts both (fwbuilder5 FWObjectDatabase_search.cpp:186), so changing
    either object concerns the firewall the rule belongs to.
    """
    wanted = {str(i) for i in obj_ids}
    result = []
    for rule in session.scalars(
        sqlalchemy.select(Rule).where(Rule.options.is_not(None))
    ):
        options = rule.options or {}
        for key in OPTION_REF_KEYS:
            if options.get(key) in wanted:
                result.append((rule, key))
    return result


def find_clusters_of(session, fw):
    """Return the clusters *fw* is a member of.

    ``findWhereObjectIsUsed`` lists a cluster as a user of its member
    firewalls (FWObjectDatabase_search.cpp:186).
    """
    if not isinstance(fw, Firewall) or isinstance(fw, Cluster):
        return []
    return [
        cluster
        for cluster in session.scalars(sqlalchemy.select(Cluster))
        if any(member.id == fw.id for member in cluster.get_members_list())
    ]
