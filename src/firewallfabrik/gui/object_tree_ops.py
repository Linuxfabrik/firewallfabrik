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

"""Database-mutating operations (CRUD) for the object tree."""

import contextlib
import copy
import uuid
import weakref
from datetime import UTC, datetime

import sqlalchemy

from firewallfabrik.core._util import OPTION_REF_KEYS
from firewallfabrik.core._validation import (
    group_accepts,
    load_object,
    rule_set_refusal,
    tree_child_refusal,
)
from firewallfabrik.core.objects import (
    NAT,
    STANDARD_LIBRARY_NAME,
    Address,
    Cluster,
    FailoverClusterGroup,
    Firewall,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    Policy,
    Routing,
    Rule,
    RuleSet,
    Service,
    StateSyncClusterGroup,
    group_membership,
    placeholder_kind,
    rule_elements,
)
from firewallfabrik.gui.object_tree_data import (
    MODEL_MAP,
    NEW_TYPES_FOR_FOLDER,
    SYSTEM_GROUP_PATHS,
    find_group_by_path,
    normalize_subfolders,
)
from firewallfabrik.gui.object_usage import find_referencing_firewalls
from firewallfabrik.platforms.linux._automatic_rules import (
    HEARTBEAT_DEFAULT_ADDRESS,
    HEARTBEAT_DEFAULT_PORT,
    OPENAIS_DEFAULT_ADDRESS,
    OPENAIS_DEFAULT_PORT,
)


def _stamp_parent_firewall(obj):
    """Update ``lastModified`` on the Firewall owning *obj* (if any).

    Returns the Firewall instance so the caller can emit tree updates,
    or *None* if *obj* is not under a Firewall.
    """
    fw = None
    if isinstance(obj, Firewall):
        fw = obj
    elif isinstance(obj, Interface):
        iface = obj
        while iface.parent_interface is not None:
            iface = iface.parent_interface
        device = iface.device
        if isinstance(device, Firewall):
            fw = device
    elif isinstance(obj, Address) and obj.interface is not None:
        return _stamp_parent_firewall(obj.interface)
    if fw is not None:
        data = dict(fw.data or {})
        data['lastModified'] = int(datetime.now(tz=UTC).timestamp())
        fw.data = data
    return fw


def _stamp_firewalls(firewalls):
    """Update ``lastModified`` on every firewall in *firewalls*."""
    now = int(datetime.now(tz=UTC).timestamp())
    for fw in firewalls:
        fw.data = {**(fw.data or {}), 'lastModified': now}


# All ORM classes that can own a ``library_id`` column.
_LIB_OWNED_CLASSES = (Address, Group, Host, Interface, Interval, Service)

# Ordered for safe cascade deletion (children before parents).
_ALL_ORM_CLASSES = (
    Address,
    Interval,
    Rule,
    Service,
    Interface,
    RuleSet,
    Host,
    Group,
    Library,
)


def add_device_defaults(session, device, *, rule_sets=True):
    """Give a new firewall or cluster what Firewall Builder creates with it.

    Ports ``Firewall::init``, which adds an empty Policy, NAT and Routing
    rule set, each the top one of its kind, and ``Cluster::init``, which
    adds the state sync group every cluster has.  Without them a new
    firewall has no rule set to put a rule in and a new cluster no group
    to name the link conntrackd replicates over.
    """
    # The children reference the device, which has to be in the table
    # before them; the unit of work does not order a group after a device.
    session.flush()
    for model_cls in (Policy, NAT, Routing) if rule_sets else ():
        session.add(
            model_cls(
                id=uuid.uuid4(),
                device_id=device.id,
                name=model_cls.__name__,
                top=True,
            )
        )
    if isinstance(device, Cluster):
        session.add(
            StateSyncClusterGroup(
                id=uuid.uuid4(),
                data={'type': 'conntrack'},
                device_id=device.id,
                library_id=device.library_id,
                name='State Sync Group',
            )
        )


def failover_group_defaults(protocol):
    """The options a new failover group of *protocol* starts with.

    Ports ``setDefaultFailoverGroupAttributes``: without them a VRRP
    group has no virtual router id, and the heartbeat and OpenAIS groups
    no address and port for the automatic rules to permit.
    """
    if protocol == 'vrrp':
        return {
            'vrrp_over_ipsec_ah': False,
            # An empty VRRP secret the administrator fills in, not a password.
            'vrrp_secret': '',  # nosec B105
            'vrrp_vrid': '1',
        }
    if protocol == 'heartbeat':
        return {
            'heartbeat_address': HEARTBEAT_DEFAULT_ADDRESS,
            'heartbeat_port': str(HEARTBEAT_DEFAULT_PORT),
            'heartbeat_unicast': False,
        }
    if protocol == 'openais':
        return {
            'openais_address': OPENAIS_DEFAULT_ADDRESS,
            'openais_port': str(OPENAIS_DEFAULT_PORT),
        }
    return {}


def _reference_holders(obj):
    """Return what in *obj* holds references: groups and rule sets."""
    if isinstance(obj, RuleSet):
        return [obj]
    if isinstance(obj, Group):
        return [obj]
    holders = []
    if isinstance(obj, Host):
        holders.extend(obj.rule_sets)
        holders.extend(obj.child_groups)
        for iface in obj.interfaces:
            holders.extend(iface.child_groups)
    if isinstance(obj, Interface):
        holders.extend(obj.child_groups)
    return holders


# The copies made into a file from another open file, per source file:
# what ``recursivelyCopySubtree`` finds again through the ".copy_of_<root>"
# attribute it puts on every copy (fwbuilder5
# FWObjectDatabase_tree_ops.cpp:498), so pasting from the same file twice
# copies an object it names once.  Like that attribute, which Firewall
# Builder does not save, it lasts as long as both files are open.
_SESSION_COPIES = weakref.WeakKeyDictionary()


def _earlier_copies(own_db, source_db):
    """Return the ``{source id: copy id}`` of copies from *source_db*."""
    per_source = _SESSION_COPIES.setdefault(own_db, weakref.WeakKeyDictionary())
    return per_source.setdefault(source_db, {})


def _exists(session, obj_id):
    """Whether this database still holds *obj_id* - undo may have removed it."""
    return (
        load_object(session, obj_id) is not None
        or session.get(RuleSet, obj_id) is not None
        or session.get(Rule, obj_id) is not None
    )


def _rule_references(session, rules):
    """Return the ids of the objects *rules* name, in order.

    The rule elements, and the tag object a tagging rule marks with: the
    rule keeps that one in its options (``PolicyRule::setTagObject``), and
    a copy without it marks nothing.  The rule set a branch rule jumps
    into is not followed - it belongs to a firewall, and
    ``recursivelyCopySubtree`` does not follow it either.
    """
    wanted = []
    for rule in rules:
        wanted.extend(
            session.scalars(
                sqlalchemy.select(rule_elements.c.target_id).where(
                    rule_elements.c.rule_id == rule.id
                )
            )
        )
        tag_id = (rule.options or {}).get('tagobject_id')
        if tag_id:
            with contextlib.suppress(ValueError):
                wanted.append(uuid.UUID(str(tag_id)))
    return wanted


def _primary_object(obj):
    """Return the object *obj* is copied with: the host of an interface."""
    while True:
        if isinstance(obj, Address) and obj.interface is not None:
            obj = obj.interface
        elif isinstance(obj, Interface) and (obj.parent_interface or obj.device):
            obj = obj.parent_interface or obj.device
        elif isinstance(obj, Group) and (obj.interface or obj.device):
            obj = obj.interface or obj.device
        else:
            return obj


def _parents(obj):
    """Return the folders and groups *obj* sits in, innermost first."""
    names = []
    parent = getattr(obj, 'group', None) or getattr(obj, 'parent_group', None)
    while parent is not None:
        names.append(parent.name)
        obj = parent
        parent = getattr(obj, 'group', None) or getattr(obj, 'parent_group', None)
    library = getattr(obj, 'library', None)
    folder = (getattr(obj, 'data', None) or {}).get('folder', '')
    return library, tuple(names), folder


def _own_standard_object(session, ref):
    """Return the id of this database's copy of a Standard library object.

    ``recursivelyCopySubtree`` finds an object of the Standard library in
    the target file by its id, which is the same in every file Firewall
    Builder writes, and uses it instead of copying it (fwbuilder5
    FWObjectDatabase_tree_ops.cpp:620).  FirewallFabrik gives every object
    a new id on each load, so it asks for the object of the same type and
    name in the same place of this file's Standard library.  Returns None
    for an object of another library, or one this file's Standard library
    has not got - an older file, or none at all - which is then copied.
    """
    library, names, folder = _parents(ref)
    if library is None or library.name != STANDARD_LIBRARY_NAME:
        return None
    cls = type(ref)
    for candidate in session.scalars(
        sqlalchemy.select(cls).where(cls.name == ref.name)
    ):
        own_library, own_names, own_folder = _parents(candidate)
        if (
            own_library is not None
            and own_library.name == STANDARD_LIBRARY_NAME
            and (own_names, own_folder) == (names, folder)
        ):
            return candidate.id
    return None


def _own_placeholder(session, ref, kind):
    """Return the id of this database's placeholder matching *ref*, or None."""
    cls = type(ref)
    for obj in session.scalars(sqlalchemy.select(cls).where(cls.name == kind)):
        if placeholder_kind(obj) == kind:
            return obj.id
    return None


class TreeOperations:
    """Encapsulates all DB-mutating operations for the object tree."""

    def __init__(self, db_manager=None):
        self._db_manager = db_manager

    # ------------------------------------------------------------------
    # Delete — unified
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_all_ids(session, root_id):
        """Recursively collect ALL descendant IDs from *root_id*.

        Handles: Host -> Interfaces -> Addresses, Host -> RuleSets -> Rules,
        Interface -> Addresses, Group -> members -> sub-groups, and what
        Firewall Builder keeps as XML children and so deletes with the
        subtree: the state sync groups of a cluster, the failover group and
        Attached Networks object of an interface, and its sub-interfaces.

        Returns ``(obj_ids: set, rule_ids: set)``.
        """
        obj_ids = {root_id}
        rule_ids = set()
        queue = [root_id]
        seen = {root_id}

        while queue:
            current_id = queue.pop()

            # Host -> interfaces + rule_sets
            host = session.get(Host, current_id)
            if host is not None:
                for iface in host.interfaces:
                    obj_ids.add(iface.id)
                    if iface.id not in seen:
                        seen.add(iface.id)
                        queue.append(iface.id)
                for rs in host.rule_sets:
                    obj_ids.add(rs.id)
                    for rule in rs.rules:
                        rule_ids.add(rule.id)
                        obj_ids.add(rule.id)
                for child_grp in host.child_groups:
                    obj_ids.add(child_grp.id)

            # Interface -> addresses, groups, sub-interfaces
            iface = session.get(Interface, current_id)
            if iface is not None:
                for addr in iface.addresses:
                    obj_ids.add(addr.id)
                for child_grp in iface.child_groups:
                    obj_ids.add(child_grp.id)
                for sub in iface.sub_interfaces:
                    obj_ids.add(sub.id)
                    if sub.id not in seen:
                        seen.add(sub.id)
                        queue.append(sub.id)

            # Group -> child objects + sub-groups
            group = session.get(Group, current_id)
            if group is not None:
                for addr in group.addresses:
                    obj_ids.add(addr.id)
                for svc in group.services:
                    obj_ids.add(svc.id)
                for itv in group.intervals:
                    obj_ids.add(itv.id)
                for dev in group.devices:
                    if dev.id not in seen:
                        seen.add(dev.id)
                        queue.append(dev.id)
                    obj_ids.add(dev.id)
                for child_grp in group.child_groups:
                    if child_grp.id not in seen:
                        seen.add(child_grp.id)
                        queue.append(child_grp.id)
                    obj_ids.add(child_grp.id)

        return obj_ids, rule_ids

    @staticmethod
    def _disable_rules_left_matching_everything(session, obj_ids, rule_ids):
        """Disable the rules a deletion would otherwise widen.

        A rule element with no objects in it means "any" everywhere in the
        compiler, so removing the last object from one turns "from this
        host" into "from anywhere" - an Accept rule that was written for one
        machine would then admit the whole world, and nothing on screen or
        in the compiled script would say so.

        Firewall Builder cannot end up there: it puts a `dummySource` /
        `dummyDestination` placeholder in the element and `Compiler::Begin`
        skips such a rule with a warning.  FirewallFabrik has no deleted
        objects (see DesignDecisions.md), so it says the same thing the
        other way round - the rule is disabled, stays where
        it is, and the administrator decides whether to repair or remove it.

        Returns the rules that were disabled, as ``(label, slot)`` pairs.
        """
        affected = session.execute(
            sqlalchemy.select(rule_elements.c.rule_id, rule_elements.c.slot).where(
                rule_elements.c.target_id.in_(obj_ids)
            )
        ).all()

        disabled = []
        for rule_id, slot in sorted(set(affected)):
            if rule_id in rule_ids:
                continue  # the rule goes away with the object anyway
            remaining = session.scalar(
                sqlalchemy.select(sqlalchemy.func.count())
                .select_from(rule_elements)
                .where(
                    rule_elements.c.rule_id == rule_id,
                    rule_elements.c.slot == slot,
                    rule_elements.c.target_id.notin_(obj_ids),
                )
            )
            if remaining:
                continue  # something else still matches there
            rule = session.get(Rule, rule_id)
            if rule is None or (rule.options or {}).get('disabled', False):
                continue
            options = dict(rule.options or {})
            options['disabled'] = True
            rule.options = options
            rule_set = session.get(RuleSet, rule.rule_set_id)
            device = session.get(Host, rule_set.device_id) if rule_set else None
            where = f'{device.name}/{rule_set.name}' if device else '?'
            disabled.append((f'{where} rule {rule.position}', slot))
        return disabled

    @staticmethod
    def _cleanup_references_and_delete(session, obj_ids, rule_ids):
        """Single-pass reference cleanup + cascade delete.

        Returns the rules that had to be disabled because the deletion
        emptied one of their match elements.
        """
        disabled = TreeOperations._disable_rules_left_matching_everything(
            session, obj_ids, rule_ids
        )

        # 1. rule_elements by rule_id
        for rid in rule_ids:
            session.execute(
                rule_elements.delete().where(rule_elements.c.rule_id == rid)
            )

        # 2. rule_elements by target_id
        for oid in obj_ids:
            session.execute(
                rule_elements.delete().where(rule_elements.c.target_id == oid)
            )

        # 3. group_membership (both as member and as group)
        for oid in obj_ids:
            session.execute(
                group_membership.delete().where(group_membership.c.member_id == oid)
            )
            session.execute(
                group_membership.delete().where(group_membership.c.group_id == oid)
            )

        # 4. Delete all collected objects in dependency order (children
        #    before parents) to avoid cascade-nullify FK violations.
        #    _ALL_ORM_CLASSES is ordered: Address, Interval, Rule,
        #    Service, Interface, RuleSet, Host, Group, Library.
        #    Use no_autoflush to prevent premature flushing while
        #    session.get() loads objects.
        deleted = set()
        with session.no_autoflush:
            for cls in _ALL_ORM_CLASSES:
                for oid in obj_ids:
                    if oid in deleted:
                        continue
                    obj = session.get(cls, oid)
                    if obj is not None:
                        session.delete(obj)
                        deleted.add(oid)

        return disabled

    def delete_object(self, obj_id, model_cls, obj_name, obj_type, *, prefix=''):
        """Delete *obj_id* and clean up all references.  Returns True on success."""
        if self._db_manager is None:
            return False

        session = self._db_manager.create_session()
        try:
            obj = session.get(model_cls, obj_id)
            if obj is None:
                session.close()
                return False

            # Stamp the parent Firewall's lastModified *before* deleting
            # the child so the relationship is still traversable.
            _stamp_parent_firewall(obj)

            obj_ids, rule_ids = self._collect_all_ids(session, obj_id)
            # The cleanup below takes the object out of every rule that
            # names it, and disables the ones it leaves matching
            # everything - in firewalls the deletion never touched
            # otherwise.  They have to be offered for a recompile too,
            # and the question has to be asked while the references are
            # still there (#159).
            _stamp_firewalls(find_referencing_firewalls(session, obj_ids))
            self._cleanup_references_and_delete(session, obj_ids, rule_ids)

            session.commit()
            self._db_manager.save_state(f'{prefix}Delete {obj_type} {obj_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return True

    def delete_library(self, lib_id, lib_name):
        """Delete a library and all its contents.  Returns True on success."""
        if self._db_manager is None:
            return False

        session = self._db_manager.create_session()
        try:
            lib = session.get(Library, lib_id)
            if lib is None:
                return False

            # Collect IDs of ALL objects in this library.
            obj_ids = set()
            rule_ids = set()

            for cls in _LIB_OWNED_CLASSES:
                if not hasattr(cls, 'library_id'):
                    continue
                for obj in session.scalars(
                    sqlalchemy.select(cls).where(cls.library_id == lib_id)
                ).all():
                    sub_ids, sub_rules = self._collect_all_ids(session, obj.id)
                    obj_ids |= sub_ids
                    rule_ids |= sub_rules

            self._cleanup_references_and_delete(session, obj_ids, rule_ids)
            session.delete(lib)
            session.commit()
            self._db_manager.save_state(f'Delete Library {lib_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return True

    def delete_folder(self, lib_id, folder_name, *, parent_group_id=None):
        """Delete a user-created subfolder and all nested children.

        Moves all child objects to the parent level (removes their
        ``data.folder`` field) and removes the subfolder **and every
        nested child path** from the parent's ``data['subfolders']``.
        The parent is determined by *parent_group_id* (a Group) or
        falls back to the Library.
        """
        if self._db_manager is None:
            return

        child_prefix = folder_name + '/'

        def _folder_matches(folder):
            return folder == folder_name or folder.startswith(child_prefix)

        session = self._db_manager.create_session()
        try:
            if parent_group_id is not None:
                parent = session.get(Group, parent_group_id)
                if parent is not None:
                    for attr in (
                        'addresses',
                        'child_groups',
                        'devices',
                        'intervals',
                        'services',
                    ):
                        for child in getattr(parent, attr, []):
                            obj_data = child.data or {}
                            if _folder_matches(obj_data.get('folder', '')):
                                new_data = {
                                    k: v for k, v in obj_data.items() if k != 'folder'
                                }
                                child.data = new_data or None
            else:
                for cls in _LIB_OWNED_CLASSES:
                    if not hasattr(cls, 'data') or not hasattr(cls, 'library_id'):
                        continue
                    for obj in (
                        session.scalars(
                            sqlalchemy.select(cls).where(cls.library_id == lib_id)
                        )
                        .unique()
                        .all()
                    ):
                        obj_data = obj.data or {}
                        if _folder_matches(obj_data.get('folder', '')):
                            new_data = {
                                k: v for k, v in obj_data.items() if k != 'folder'
                            }
                            obj.data = new_data or None
                parent = session.get(Library, lib_id)

            # Remove folder and all nested child paths from subfolders list.
            if parent is not None:
                parent_data = copy.deepcopy(parent.data or {})
                subfolders = normalize_subfolders(parent_data.get('subfolders', []))
                subfolders = [s for s in subfolders if not _folder_matches(s)]
                if subfolders:
                    parent_data['subfolders'] = subfolders
                else:
                    parent_data.pop('subfolders', None)
                parent.data = parent_data

            session.commit()
            self._db_manager.save_state(f'Delete folder "{folder_name}"')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Duplicate
    # ------------------------------------------------------------------

    def duplicate_object(
        self,
        source_id,
        model_cls,
        target_lib_id,
        *,
        folder=None,
        prefix='',
        target_device_id=None,
        target_group_id=None,
        target_interface_id=None,
    ):
        """Deep-copy *source_id* into *target_lib_id*. Returns new UUID or None.

        Optional *target_interface_id* / *target_group_id* /
        *target_device_id* place the clone under a specific interface,
        group, or device instead of the library root.
        When *folder* is given, the clone's ``data.folder`` is set to that
        value (used when pasting into a user subfolder).
        """
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            source = session.get(model_cls, source_id)
            if source is None:
                session.close()
                return None

            id_map = {}
            new_obj = self._clone_object(source, id_map)

            # Clear all parent references first, then set the target.
            if hasattr(new_obj, 'interface_id'):
                new_obj.interface_id = None
            if hasattr(new_obj, 'group_id'):
                new_obj.group_id = None
            if hasattr(new_obj, 'parent_group_id'):
                new_obj.parent_group_id = None
            if hasattr(new_obj, 'parent_interface_id'):
                new_obj.parent_interface_id = None

            if target_interface_id is not None and isinstance(new_obj, Interface):
                # Pasting an interface onto another interface creates
                # a subinterface, matching fwbuilder behaviour.
                new_obj.parent_interface_id = target_interface_id
                # Inherit device_id from the parent interface.
                parent_iface = session.get(Interface, target_interface_id)
                if parent_iface is not None:
                    new_obj.device_id = parent_iface.device_id
                # Reset type to ethernet and clear management flag
                # to avoid duplicates (fwbuilder #299, #391).
                opts = copy.deepcopy(new_obj.options or {})
                opts['type'] = 'ethernet'
                opts['management'] = False
                new_obj.options = opts
            elif target_device_id is not None and isinstance(new_obj, Interface):
                # Pasting an interface onto a device adds it as a
                # top-level interface of that device.
                new_obj.device_id = target_device_id
                new_obj.library_id = None
            elif isinstance(new_obj, Group) and (
                target_interface_id is not None or target_device_id is not None
            ):
                # A failover group belongs to an interface and a state
                # sync group to a cluster; the group keeps its library.
                new_obj.interface_id = target_interface_id
                new_obj.device_id = (
                    target_device_id if target_interface_id is None else None
                )
                new_obj.library_id = target_lib_id
            elif target_interface_id is not None and hasattr(new_obj, 'interface_id'):
                new_obj.interface_id = target_interface_id
                # Addresses under interfaces don't carry library_id.
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = None
            elif target_group_id is not None:
                if hasattr(new_obj, 'group_id'):
                    new_obj.group_id = target_group_id
                elif hasattr(new_obj, 'parent_group_id'):
                    new_obj.parent_group_id = target_group_id
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = target_lib_id
            else:
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = target_lib_id

            # Place clone in the target user subfolder, or clear folder
            # when pasting to the group root (empty string).
            if folder is not None and hasattr(new_obj, 'data'):
                data = copy.deepcopy(new_obj.data or {})
                if folder:
                    data['folder'] = folder
                else:
                    data.pop('folder', None)
                new_obj.data = data

            # Make name unique within the target scope.
            new_obj.name = self.make_name_unique(session, new_obj)

            session.add(new_obj)

            # Deep-copy children for devices (interfaces, rule sets, rules, rule elements).
            if isinstance(source, Host):
                self._duplicate_device_children(
                    session, session, source, new_obj, id_map
                )
            if isinstance(source, Interface):
                session.flush()
                self._copy_interface_children(session, session, source, new_obj, id_map)

            # Copy group_membership entries for groups.
            if isinstance(source, Group):
                self._duplicate_group_members(session, source, new_obj)

            session.commit()
            self._db_manager.save_state(
                f'{prefix}Duplicate {model_cls.__name__} {source.name}',
            )
            new_id = new_obj.id
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

    @staticmethod
    def _clone_object(source, id_map):
        """Create a detached copy of *source* with a new UUID.

        All scalar/JSON column attributes are deep-copied.
        *id_map* is updated with ``{old_id: new_id}``.
        """
        mapper = sqlalchemy.inspect(type(source))
        new_id = uuid.uuid4()
        id_map[source.id] = new_id
        kwargs = {}
        for attr in mapper.column_attrs:
            key = attr.key
            if key == 'id':
                continue
            val = getattr(source, key)
            if isinstance(val, (dict, list, set)):
                val = copy.deepcopy(val)
            kwargs[key] = val
        return type(source)(id=new_id, **kwargs)

    def _duplicate_device_children(
        self,
        source_session,
        target_session,
        source_device,
        new_device,
        id_map,
    ):
        """Deep-copy the interfaces, groups and rule sets of a device.

        Reads from *source_session* and writes to *target_session*, which
        are the same session unless an object is pasted into another file.
        Everything the copy owns is remapped through *id_map*: a
        sub-interface points at the copy of its parent, a failover group
        or an Attached Networks object sits under the copy of its
        interface, and a rule branching into a rule set of the same device
        branches into the copy of it (``FWObjectDatabase::fixReferences``).
        """
        # Parents before their sub-interfaces: the unique index on
        # (parent interface, name) and the foreign key to the parent both
        # need the parent row first.
        pending = list(source_device.interfaces)
        interfaces = []
        while pending:
            placed = {i.id for i in interfaces}
            ready = [
                i
                for i in pending
                if i.parent_interface_id is None or i.parent_interface_id in placed
            ]
            if not ready:
                # A parent that is not on this device; keep the rest as is.
                ready = pending
            interfaces.extend(ready)
            pending = [i for i in pending if i not in ready]

        group_tasks = []
        for iface in interfaces:
            new_iface = self._clone_object(iface, id_map)
            new_iface.device_id = new_device.id
            new_iface.library_id = new_device.library_id
            if iface.parent_interface_id is not None:
                new_iface.parent_interface_id = id_map.get(
                    iface.parent_interface_id, iface.parent_interface_id
                )
            target_session.add(new_iface)
            target_session.flush()
            for addr in iface.addresses:
                new_addr = self._clone_object(addr, id_map)
                new_addr.interface_id = new_iface.id
                new_addr.library_id = None
                new_addr.group_id = None
                target_session.add(new_addr)
            for group in iface.child_groups:
                new_group = self._clone_object(group, id_map)
                new_group.interface_id = new_iface.id
                new_group.library_id = new_device.library_id
                target_session.add(new_group)
                group_tasks.append((group, new_group))

        for group in source_device.child_groups:
            new_group = self._clone_object(group, id_map)
            new_group.device_id = new_device.id
            new_group.library_id = new_device.library_id
            target_session.add(new_group)
            group_tasks.append((group, new_group))

        self._copy_rule_sets(
            source_session, target_session, source_device, new_device, id_map
        )

        for group, new_group in group_tasks:
            if source_session is target_session:
                self._duplicate_group_members(source_session, group, new_group, id_map)
            else:
                self._duplicate_group_members_cross_db(
                    source_session, target_session, group, new_group, id_map
                )

    def _copy_interface_children(
        self, source_session, target_session, source_iface, new_iface, id_map
    ):
        """Copy what an interface holds onto its copy *new_iface*.

        ``ObjectManipulator::actuallyPasteTo`` copies an interface with
        ``duplicate(obj, true)``, the whole subtree (fwbuilder5
        ObjectManipulator_ops.cpp:386): its addresses and MAC address, its
        failover group and Attached Networks object, and its
        sub-interfaces with theirs.  Without it a pasted interface arrived
        empty.
        """
        for addr in source_iface.addresses:
            new_addr = self._clone_object(addr, id_map)
            new_addr.interface_id = new_iface.id
            new_addr.library_id = None
            new_addr.group_id = None
            target_session.add(new_addr)
        for group in source_iface.child_groups:
            new_group = self._clone_object(group, id_map)
            new_group.interface_id = new_iface.id
            new_group.library_id = new_iface.library_id
            target_session.add(new_group)
            target_session.flush()
            if source_session is target_session:
                self._duplicate_group_members(source_session, group, new_group)
            else:
                self._duplicate_group_members_cross_db(
                    source_session, target_session, group, new_group, id_map
                )
        for sub in source_iface.sub_interfaces:
            new_sub = self._clone_object(sub, id_map)
            new_sub.parent_interface_id = new_iface.id
            new_sub.device_id = new_iface.device_id
            new_sub.library_id = new_iface.library_id
            target_session.add(new_sub)
            target_session.flush()
            self._copy_interface_children(
                source_session, target_session, sub, new_sub, id_map
            )

    @staticmethod
    def _copy_rule_sets(
        source_session,
        target_session,
        source_device,
        new_device,
        id_map,
        *,
        rule_sets=None,
        overrides=None,
    ):
        """Copy the rule sets of *source_device* onto *new_device*.

        Every reference the copied rules hold - a rule element, the rule
        set a Branch rule jumps into, a tag object - is remapped through
        *id_map*, which the rule sets and rules are added to as they are
        cloned.  A caller can seed it to point references somewhere else:
        the New Cluster wizard maps a member firewall and its interfaces
        onto the cluster and its interfaces (``FWObjectDatabase::
        fixReferences``).
        """
        # Collect source rule_element rows and clone rule sets + rules.
        # We must read source rows before flushing the clones (the flush
        # would otherwise trigger lazy loads that might expire the source
        # relationships).
        rule_element_tasks = []
        new_rules = []
        for rs in source_device.rule_sets if rule_sets is None else rule_sets:
            new_rs = TreeOperations._clone_object(rs, id_map)
            new_rs.device_id = new_device.id
            for key, value in (overrides or {}).get(rs.id, {}).items():
                setattr(new_rs, key, value)
            target_session.add(new_rs)
            for rule in rs.rules:
                new_rule = TreeOperations._clone_object(rule, id_map)
                new_rule.rule_set_id = new_rs.id
                target_session.add(new_rule)
                new_rules.append(new_rule)
                rows = source_session.execute(
                    sqlalchemy.select(rule_elements).where(
                        rule_elements.c.rule_id == rule.id
                    )
                ).all()
                if rows:
                    rule_element_tasks.append((new_rule, rows))

        # A branch into a rule set of this device, or a tag object that is
        # one of its interfaces, follows the copy; every other reference
        # stays where it points.
        str_map = {str(old): str(new) for old, new in id_map.items()}
        for new_rule in new_rules:
            options = new_rule.options or {}
            if any(options.get(key) in str_map for key in OPTION_REF_KEYS):
                new_rule.options = {
                    **options,
                    **{
                        key: str_map[options[key]]
                        for key in OPTION_REF_KEYS
                        if options.get(key) in str_map
                    },
                }

        # Flush all ORM objects so that rule and rule_set rows exist in
        # the DB before we insert the raw rule_elements rows (which
        # reference them via FK).
        target_session.flush()

        for new_rule, rows in rule_element_tasks:
            for row in rows:
                target_session.execute(
                    rule_elements.insert().values(
                        rule_id=new_rule.id,
                        slot=row.slot,
                        target_id=id_map.get(row.target_id, row.target_id),
                        position=row.position,
                    )
                )

    @staticmethod
    def _duplicate_group_members(session, source_group, new_group, id_map=None):
        """Copy group_membership entries from *source_group* to *new_group*.

        A member that was copied along with the group (*id_map*) is
        replaced by its copy.
        """
        id_map = id_map or {}
        rows = session.execute(
            sqlalchemy.select(group_membership).where(
                group_membership.c.group_id == source_group.id
            )
        ).all()
        for row in rows:
            session.execute(
                group_membership.insert().values(
                    group_id=new_group.id,
                    member_id=id_map.get(row.member_id, row.member_id),
                    position=row.position,
                )
            )

    def copy_missing_references(
        self, source_db_manager, source_id, target_lib_id, id_map, seen=None
    ):
        """Copy into this database what *source_id* names and it has not got.

        ``FWObjectDatabase::recursivelyCopySubtree`` (fwbuilder5
        FWObjectDatabase_tree_ops.cpp:494) follows every reference of the
        object it copies into another file: an object the target has is
        used, one it has not got is copied with its primary object - a
        whole host for an interface or one of its addresses - into the
        same place in the target library.  Without it a pasted group
        arrived without the members the other file kept, and a pasted
        firewall with rules naming objects that do not exist.  The
        "Any" and "Dummy" placeholders are this file's own.
        """
        seen = set() if seen is None else seen
        if source_id in seen:
            return
        seen.add(source_id)
        with source_db_manager.session() as source, self._db_manager.session() as own:
            obj = load_object(source, source_id) or source.get(RuleSet, source_id)
            if obj is None:
                return
            wanted = []
            for holder in _reference_holders(obj):
                if isinstance(holder, Group):
                    wanted.extend(m.id for m in holder.get_member_objects())
                else:
                    wanted.extend(_rule_references(source, holder.rules))
            to_copy = self._missing_primaries(
                source, own, wanted, target_lib_id, id_map
            )
        self._copy_primaries(source_db_manager, to_copy, target_lib_id, id_map, seen)

    def copy_rule_references(self, source_db_manager, rule_ids, target_lib_id, id_map):
        """Copy into this database what the rules *rule_ids* name and it has not got.

        The rule counterpart of :meth:`copy_missing_references`, for rules
        pasted from another file: ``RuleSetView::createInsertTemplate``
        copies such a rule with ``recursivelyCopySubtree`` into the rule
        set it is pasted into (fwbuilder5 RuleSetView.cpp:1555), so what
        the rule names lands in the library of that firewall.
        """
        self._reuse_earlier_copies(source_db_manager, id_map)
        with source_db_manager.session() as source, self._db_manager.session() as own:
            rules = [r for r in (source.get(Rule, i) for i in rule_ids) if r]
            wanted = _rule_references(source, rules)
            to_copy = self._missing_primaries(
                source, own, wanted, target_lib_id, id_map
            )
        self._copy_primaries(source_db_manager, to_copy, target_lib_id, id_map, set())
        self._fix_references(id_map)
        self._remember_copies(source_db_manager, id_map)

    @staticmethod
    def _missing_primaries(source, own, wanted, target_lib_id, id_map):
        """Return the primary objects of *wanted* this database has not got.

        A placeholder is mapped onto this database's own in *id_map*
        instead.  Each entry is ``(id, class, group id)``: the group is the
        standard folder of the object's type in the target library.
        """
        to_copy = []
        for ref_id in dict.fromkeys(wanted):
            if ref_id in id_map or load_object(own, ref_id) is not None:
                continue
            ref = load_object(source, ref_id)
            if ref is None:
                continue
            kind = placeholder_kind(ref)
            if kind:
                mine = _own_placeholder(own, ref, kind)
                if mine is not None:
                    id_map[ref_id] = mine
                continue
            mine = _own_standard_object(own, ref)
            if mine is not None:
                id_map[ref_id] = mine
                continue
            primary = _primary_object(ref)
            slot = SYSTEM_GROUP_PATHS.get(getattr(primary, 'type', ''))
            group = find_group_by_path(own, target_lib_id, slot) if slot else None
            to_copy.append((primary.id, type(primary), group.id if group else None))
        return to_copy

    def _copy_primaries(self, source_db_manager, to_copy, target_lib_id, id_map, seen):
        """Copy the objects :meth:`_missing_primaries` found, references first."""
        for primary_id, cls, group_id in to_copy:
            if primary_id in id_map:
                continue
            self.copy_missing_references(
                source_db_manager, primary_id, target_lib_id, id_map, seen
            )
            if primary_id in id_map:
                continue
            self.duplicate_object_cross_db(
                source_db_manager,
                primary_id,
                cls,
                target_lib_id,
                target_group_id=group_id,
                id_map=id_map,
                seen=seen,
            )

    def _reuse_earlier_copies(self, source_db_manager, id_map, *, skip=()):
        """Seed *id_map* with what earlier pastes from that file copied.

        *skip* is the object being pasted itself: Firewall Builder copies
        the object it is asked to paste every time, and reuses only the
        copies of what that object names.  Measured with Firewall Builder
        5.3.7 on Fedora 38: the same rules pasted twice from another file
        bring along the address and the firewall they name once.
        """
        copies = _earlier_copies(self._db_manager, source_db_manager)
        with self._db_manager.session() as own:
            for old_id, new_id in list(copies.items()):
                if old_id in skip or old_id in id_map:
                    continue
                if _exists(own, new_id):
                    id_map[old_id] = new_id
                else:
                    del copies[old_id]

    def _remember_copies(self, source_db_manager, id_map):
        """Keep *id_map* for the next paste from the same file."""
        _earlier_copies(self._db_manager, source_db_manager).update(id_map)

    def _fix_references(self, id_map):
        """Point what still names an object of the other file at its copy.

        Two objects that name each other - a firewall whose rules name its
        own interfaces, or a group in a rule of a firewall that is one of
        its members - are copied one before the other, so the first copy
        still names the original of the second.  ``recursivelyCopySubtree``
        makes "one more pass to fix references" for the same reason
        (fwbuilder5 FWObjectDatabase_tree_ops.cpp:509).  The ids of the
        other file exist nowhere in this one, so every row naming one is a
        reference to fix.
        """
        if not id_map:
            return
        with self._db_manager.session('Paste (cross-file)') as session:
            for old_id, new_id in id_map.items():
                session.execute(
                    rule_elements.update()
                    .where(rule_elements.c.target_id == old_id)
                    .values(target_id=new_id)
                )
                session.execute(
                    group_membership.update()
                    .where(group_membership.c.member_id == old_id)
                    .values(member_id=new_id)
                )

    def duplicate_object_cross_db(
        self,
        source_db_manager,
        source_id,
        model_cls,
        target_lib_id,
        *,
        folder=None,
        prefix='',
        target_device_id=None,
        target_group_id=None,
        target_interface_id=None,
        id_map=None,
        seen=None,
    ):
        """Deep-copy an object from *source_db_manager* into *this* database.

        Used for cross-file paste.  Reads the source object from the
        foreign database, serializes all scalar columns, and creates a
        new ORM instance in the local database with a fresh UUID.  What
        the object names and this database has not got is copied first
        (:meth:`copy_missing_references`).  *id_map* collects every
        source id that was copied, with the id of its copy; *seen* holds
        the objects whose references are being copied, so an object that
        names itself, or one that names it, is copied once.

        Returns the new object's UUID, or *None* on failure.
        """
        if self._db_manager is None or source_db_manager is None:
            return None
        id_map = {} if id_map is None else id_map
        outermost = seen is None
        seen = set() if seen is None else seen
        if outermost:
            self._reuse_earlier_copies(source_db_manager, id_map, skip={source_id})
        self.copy_missing_references(
            source_db_manager, source_id, target_lib_id, id_map, seen
        )
        if source_id in id_map:
            if outermost:
                self._fix_references(id_map)
                self._remember_copies(source_db_manager, id_map)
            return id_map[source_id]

        # Read the source object from the foreign database.
        source_session = source_db_manager.create_session()
        target_session = self._db_manager.create_session()
        try:
            source = source_session.get(model_cls, source_id)
            if source is None:
                return None

            new_obj = self._clone_object(source, id_map)

            # Clear all parent references first, then set the target.
            if hasattr(new_obj, 'interface_id'):
                new_obj.interface_id = None
            if hasattr(new_obj, 'group_id'):
                new_obj.group_id = None
            if hasattr(new_obj, 'parent_group_id'):
                new_obj.parent_group_id = None
            if hasattr(new_obj, 'parent_interface_id'):
                new_obj.parent_interface_id = None

            if target_interface_id is not None and isinstance(new_obj, Interface):
                new_obj.parent_interface_id = target_interface_id
                parent_iface = target_session.get(
                    Interface,
                    target_interface_id,
                )
                if parent_iface is not None:
                    new_obj.device_id = parent_iface.device_id
                opts = copy.deepcopy(new_obj.options or {})
                opts['type'] = 'ethernet'
                opts['management'] = False
                new_obj.options = opts
            elif target_device_id is not None and isinstance(new_obj, Interface):
                new_obj.device_id = target_device_id
                new_obj.library_id = None
            elif isinstance(new_obj, Group) and (
                target_interface_id is not None or target_device_id is not None
            ):
                new_obj.interface_id = target_interface_id
                new_obj.device_id = (
                    target_device_id if target_interface_id is None else None
                )
                new_obj.library_id = target_lib_id
            elif target_interface_id is not None and hasattr(new_obj, 'interface_id'):
                new_obj.interface_id = target_interface_id
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = None
            elif target_group_id is not None:
                if hasattr(new_obj, 'group_id'):
                    new_obj.group_id = target_group_id
                elif hasattr(new_obj, 'parent_group_id'):
                    new_obj.parent_group_id = target_group_id
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = target_lib_id
            else:
                if hasattr(new_obj, 'library_id'):
                    new_obj.library_id = target_lib_id

            if folder is not None and hasattr(new_obj, 'data'):
                data = copy.deepcopy(new_obj.data or {})
                if folder:
                    data['folder'] = folder
                else:
                    data.pop('folder', None)
                new_obj.data = data

            # Make name unique in the target database.
            new_obj.name = self.make_name_unique(target_session, new_obj)

            target_session.add(new_obj)

            # Deep-copy children for devices (interfaces, rule sets, etc.).
            if isinstance(source, Host):
                self._duplicate_device_children(
                    source_session,
                    target_session,
                    source,
                    new_obj,
                    id_map,
                )
            if isinstance(source, Interface):
                target_session.flush()
                self._copy_interface_children(
                    source_session, target_session, source, new_obj, id_map
                )

            # Copy group membership for groups.
            if isinstance(source, Group):
                self._duplicate_group_members_cross_db(
                    source_session,
                    target_session,
                    source,
                    new_obj,
                    id_map,
                    pending=seen,
                )

            target_session.commit()
            self._db_manager.save_state(
                f'{prefix}Paste {model_cls.__name__} {source.name} (cross-file)',
            )
            new_id = new_obj.id
        except Exception:
            target_session.rollback()
            raise
        finally:
            source_session.close()
            target_session.close()

        if outermost:
            self._fix_references(id_map)
            self._remember_copies(source_db_manager, id_map)
        return new_id

    @staticmethod
    def _duplicate_group_members_cross_db(
        source_session,
        target_session,
        source_group,
        new_group,
        id_map=None,
        pending=(),
    ):
        """Copy group_membership entries across databases.

        A member copied into this database (*id_map*, see
        :meth:`copy_missing_references`) is replaced by its copy; a member
        that is neither copied nor already here is left out.  A member
        whose copy is still being made - a firewall whose rules name this
        group - is in *pending* and keeps its id until
        :meth:`_fix_references` points it at the copy.
        """
        id_map = id_map or {}
        rows = source_session.execute(
            sqlalchemy.select(group_membership).where(
                group_membership.c.group_id == source_group.id,
            ),
        ).all()
        for row in rows:
            member_id = id_map.get(row.member_id, row.member_id)
            member = load_object(source_session, row.member_id)
            if load_object(target_session, member_id) is not None or (
                member is not None and _primary_object(member).id in pending
            ):
                target_session.execute(
                    group_membership.insert().values(
                        group_id=new_group.id,
                        member_id=member_id,
                        position=row.position,
                    ),
                )

    def paste_rule_set(self, source_db_manager, rule_set_id, target_device_id):
        """Copy a rule set with its rules onto a firewall; return the new id.

        ``Firewall::validateChild`` takes a Policy and a NAT rule set at
        any time and a Routing one only while the firewall has none
        (fwbuilder5 Firewall.cpp:205); ``actuallyPasteTo`` then adds a
        copy (ObjectManipulator_ops.cpp:376, "add ruleset object to a
        firewall").  The copy is not the top rule set when the firewall
        already has one of its kind, because two top rule sets would both
        claim the built-in chains.
        """
        if self._db_manager is None:
            return None
        source_db_manager = source_db_manager or self._db_manager
        same_db = source_db_manager is self._db_manager
        id_map = {}
        if not same_db:
            with self._db_manager.session() as session:
                device = session.get(Host, target_device_id)
                lib_id = device.library_id if device is not None else None
            self._reuse_earlier_copies(source_db_manager, id_map)
            self.copy_missing_references(source_db_manager, rule_set_id, lib_id, id_map)
        source_session = source_db_manager.create_session()
        target_session = (
            source_session if same_db else self._db_manager.create_session()
        )
        try:
            source = source_session.get(RuleSet, rule_set_id)
            device = target_session.get(Host, target_device_id)
            if source is None or device is None:
                return None
            if rule_set_refusal(device, source):
                return None
            siblings = [rs for rs in device.rule_sets if rs.type == source.type]
            taken = {rs.name for rs in siblings}
            name, suffix = source.name, 1
            while name in taken:
                name = f'{source.name}-{suffix}'
                suffix += 1
            overrides = {
                source.id: {
                    'name': name,
                    'top': bool(source.top) and not any(rs.top for rs in siblings),
                }
            }
            self._copy_rule_sets(
                source_session,
                target_session,
                source,
                device,
                id_map,
                rule_sets=[source],
                overrides=overrides,
            )
            new_rs = target_session.get(RuleSet, id_map[source.id])
            new_rs_id = new_rs.id
            target_session.commit()
            self._db_manager.save_state(f'Paste {source.type} {source.name}')
        except Exception:
            target_session.rollback()
            raise
        finally:
            source_session.close()
            if not same_db:
                target_session.close()
        if not same_db:
            self._fix_references(id_map)
            self._remember_copies(source_db_manager, id_map)
        return new_rs_id

    def reparent_object(
        self,
        obj_id,
        model_cls,
        *,
        device_id=None,
        interface_id=None,
        prefix='',
    ):
        """Move an interface, an address or a cluster group to a new parent.

        Cut and paste onto a device or an interface: the object keeps its
        id, so every rule and group that names it still does.  Firewall
        Builder's cut deletes the object and the paste adds a copy, which
        loses those references; fwf has no Deleted Objects library to take
        them back from, so it moves instead.  Returns True on success.
        """
        if self._db_manager is None:
            return False
        session = self._db_manager.create_session()
        try:
            obj = session.get(model_cls, obj_id)
            if obj is None:
                return False
            target = (
                session.get(Interface, interface_id)
                if interface_id is not None
                else session.get(Host, device_id)
            )
            if target is None or tree_child_refusal(target, obj):
                return False
            if isinstance(obj, Interface):
                if interface_id is not None:
                    obj.parent_interface_id = interface_id
                    obj.device_id = target.device_id
                else:
                    obj.parent_interface_id = None
                    obj.device_id = device_id
                obj.library_id = None
                for sub in obj.sub_interfaces:
                    sub.device_id = obj.device_id
            elif isinstance(obj, Group):
                obj.interface_id = interface_id
                obj.device_id = device_id if interface_id is None else None
                obj.parent_group_id = None
            else:
                obj.interface_id = interface_id
                obj.group_id = None
                if hasattr(obj, 'library_id'):
                    obj.library_id = None
            obj.name = self.make_name_unique(session, obj)
            session.commit()
            self._db_manager.save_state(
                f'{prefix}Move {getattr(obj, "type", model_cls.__name__)} {obj.name}'
            )
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    # ------------------------------------------------------------------
    # Move
    # ------------------------------------------------------------------

    def move_object(
        self,
        obj_id,
        model_cls,
        target_lib_id,
        *,
        folder=None,
        prefix='',
        target_group_id=None,
    ):
        """Move *obj_id* to *target_lib_id*. Returns True on success.

        When *target_group_id* and/or *folder* are given, the object is
        placed into that group / user subfolder (used for cut-paste into
        a subfolder).
        """
        if self._db_manager is None:
            return False

        session = self._db_manager.create_session()
        try:
            obj = session.get(model_cls, obj_id)
            if obj is None:
                session.close()
                return False

            obj_name = obj.name
            obj_type = getattr(obj, 'type', type(obj).__name__)
            obj.library_id = target_lib_id

            # Clear group/parent ownership — object lands at the library root.
            if hasattr(obj, 'group_id'):
                obj.group_id = None
            if hasattr(obj, 'parent_group_id'):
                obj.parent_group_id = None

            # Place into the target group when given.
            if target_group_id is not None:
                if hasattr(obj, 'group_id'):
                    obj.group_id = target_group_id
                elif hasattr(obj, 'parent_group_id'):
                    obj.parent_group_id = target_group_id

            # Set/clear user subfolder path.
            if folder is not None and hasattr(obj, 'data'):
                data = copy.deepcopy(obj.data or {})
                if folder:
                    data['folder'] = folder
                else:
                    data.pop('folder', None)
                obj.data = data

            # For devices, also move child interfaces.
            if isinstance(obj, Host):
                for iface in obj.interfaces:
                    iface.library_id = target_lib_id

            session.commit()
            self._db_manager.save_state(f'{prefix}Move {obj_type} {obj_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return True

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_new_object(
        self,
        model_cls,
        type_name,
        lib_id,
        *,
        device_id=None,
        extra_data=None,
        folder=None,
        interface_id=None,
        name=None,
        parent_interface_id=None,
        prefix='',
    ):
        """Create a new object and return its UUID, or None on failure."""
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            new_id = uuid.uuid4()
            kwargs = {'id': new_id}

            # Only set 'type' for STI models that have a type column.
            if hasattr(model_cls, 'type'):
                kwargs['type'] = type_name

            # Library objects use database_id instead of library_id.
            if model_cls is Library:
                existing_lib = session.scalars(
                    sqlalchemy.select(Library).limit(1),
                ).first()
                if existing_lib is not None:
                    kwargs['database_id'] = existing_lib.database_id
                else:
                    session.close()
                    return None
            elif interface_id is not None and hasattr(model_cls, 'interface_id'):
                kwargs['interface_id'] = interface_id
                if issubclass(model_cls, Group) and hasattr(model_cls, 'library_id'):
                    # A cluster group keeps its library, the way the `.fwb`
                    # reader sets it; an address under an interface does
                    # not, and both readers and the writer tell the two
                    # apart by the link to the parent, not by the library.
                    kwargs['library_id'] = lib_id
            elif parent_interface_id is not None and hasattr(
                model_cls, 'parent_interface_id'
            ):
                kwargs['parent_interface_id'] = parent_interface_id
                if device_id is not None and hasattr(model_cls, 'device_id'):
                    kwargs['device_id'] = device_id
                if hasattr(model_cls, 'library_id'):
                    kwargs['library_id'] = lib_id
            elif device_id is not None and hasattr(model_cls, 'device_id'):
                kwargs['device_id'] = device_id
                if hasattr(model_cls, 'library_id'):
                    kwargs['library_id'] = lib_id
            else:
                if hasattr(model_cls, 'library_id'):
                    kwargs['library_id'] = lib_id

            # Use SYSTEM_GROUP_PATHS to resolve the correct (possibly
            # nested) group for this object type.  Falls back to the
            # virtual data.folder mechanism when the group doesn't exist.
            if folder and hasattr(model_cls, 'group_id') and 'group_id' not in kwargs:
                path = SYSTEM_GROUP_PATHS.get(type_name, '')
                target_group = find_group_by_path(session, lib_id, path)
                if target_group is not None:
                    kwargs['group_id'] = target_group.id
                    # System-level folder names (e.g. "Time") are only
                    # used for group resolution; user subfolder paths
                    # (e.g. "test1/test2") must be preserved in
                    # data.folder.
                    if folder in NEW_TYPES_FOR_FOLDER:
                        folder = None

            # Group-type objects use parent_group_id (not group_id) to
            # nest inside a folder group (e.g. ObjectGroup -> Objects/Groups).
            if (
                folder
                and hasattr(model_cls, 'parent_group_id')
                and 'parent_group_id' not in kwargs
            ):
                path = SYSTEM_GROUP_PATHS.get(type_name, '')
                target_group = find_group_by_path(session, lib_id, path)
                if target_group is not None:
                    kwargs['parent_group_id'] = target_group.id
                    if folder in NEW_TYPES_FOR_FOLDER:
                        folder = None

            # Extract options from extra_data (platform defaults for devices).
            options = extra_data.pop('options', None) if extra_data else None

            # Build data dict: merge folder and extra_data.
            data = {}
            if folder:
                data['folder'] = folder
            if extra_data:
                data.update(extra_data)
            if data and hasattr(model_cls, 'data'):
                kwargs['data'] = data

            if options and hasattr(model_cls, 'options'):
                kwargs['options'] = options

            new_obj = model_cls(**kwargs)
            if name is None and type_name in ('NAT', 'Policy') and device_id:
                # ObjectManipulator::newPolicyRuleSet / newNATRuleSet: the
                # type, numbered from the second one on ("Policy_1"), a
                # name the rule set editor accepts.
                count = session.scalar(
                    sqlalchemy.select(sqlalchemy.func.count())
                    .select_from(RuleSet)
                    .where(RuleSet.device_id == device_id, RuleSet.type == type_name)
                )
                name = f'{type_name}_{count}' if count else type_name
            new_obj.name = name or f'New {type_name}'

            # Make name unique.
            new_obj.name = self.make_name_unique(session, new_obj)

            # First RuleSet of a given type on a device is the top ruleset.
            if (
                model_cls is RuleSet
                and hasattr(new_obj, 'device_id')
                and new_obj.device_id is not None
            ):
                existing = session.scalar(
                    sqlalchemy.select(sqlalchemy.func.count())
                    .select_from(RuleSet)
                    .where(
                        RuleSet.device_id == new_obj.device_id,
                        RuleSet.type == type_name,
                    )
                )
                if not existing:
                    new_obj.top = True

            session.add(new_obj)
            if isinstance(new_obj, Firewall):
                add_device_defaults(session, new_obj)
            session.commit()
            self._db_manager.save_state(f'{prefix}New {type_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

    def create_cluster(self, lib_id, spec, *, folder=None, prefix=''):
        """Create a cluster from the New Cluster wizard. Returns its UUID.

        Ports ``newClusterDialog::createNewCluster``.  *spec* is what
        ``NewClusterDialog.get_result()`` returns: the name, platform and
        host OS, the member firewalls, one entry per cluster interface
        (name, label, comment, failover protocol, addresses and the member
        interfaces it stands for) and, optionally, the member whose rules
        the cluster takes over.

        Each cluster interface gets a failover group named
        ``<cluster>:<interface>:members`` that references the member
        interfaces, and the protocol's default options.  Taking over the
        rules of a member first stores a disabled copy of every member as
        ``<member>-bak``, then copies the rule sets with every reference to
        a member firewall or one of its mapped interfaces pointing at the
        cluster instead, and finally leaves each member with empty
        Policy, NAT and Routing rule sets - a member rule set of the same
        name would otherwise override the cluster's.  All of it is one
        undo step.
        """
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            cluster = Cluster(
                id=uuid.uuid4(),
                type='Cluster',
                library_id=lib_id,
                data={'host_OS': spec['host_OS'], 'platform': spec['platform']},
            )
            target_group = find_group_by_path(
                session, lib_id, SYSTEM_GROUP_PATHS.get('Cluster', '')
            )
            if target_group is not None:
                cluster.group_id = target_group.id
            # A user subfolder is kept the way create_new_object keeps it;
            # the system folder is what group_id already says.
            if folder and folder not in NEW_TYPES_FOR_FOLDER:
                cluster.data = {**cluster.data, 'folder': folder}
            cluster.name = spec['name']
            cluster.name = self.make_name_unique(session, cluster)
            session.add(cluster)
            source_id = spec.get('copy_rules_from')
            add_device_defaults(session, cluster, rule_sets=source_id is None)

            # setDefaultStateSyncGroupAttributes names the group after the
            # first state sync protocol of the host OS.
            for group in cluster.child_groups:
                group.name = 'conntrack'

            id_map = {}
            for iface_spec in spec['interfaces']:
                iface = Interface(
                    id=uuid.uuid4(),
                    comment=iface_spec['comment'],
                    data={
                        'dyn': False,
                        'label': iface_spec['label'],
                        'security_level': '0',
                        'unnum': False,
                    },
                    device_id=cluster.id,
                    library_id=lib_id,
                    name=iface_spec['name'],
                    options={'type': 'cluster_interface'},
                )
                session.add(iface)
                for addr_spec in iface_spec['addresses']:
                    is_v4 = addr_spec['ipv4']
                    session.add(
                        Address(
                            id=uuid.uuid4(),
                            inet_addr_mask={
                                'address': addr_spec['address'],
                                'netmask': addr_spec['netmask'],
                            },
                            interface_id=iface.id,
                            name=f'{cluster.name}:{iface.name}:'
                            + ('ip' if is_v4 else 'ip6'),
                            type='IPv4' if is_v4 else 'IPv6',
                        )
                    )
                protocol = iface_spec['protocol']
                group = FailoverClusterGroup(
                    id=uuid.uuid4(),
                    data={'type': protocol},
                    interface_id=iface.id,
                    library_id=lib_id,
                    name=f'{cluster.name}:{iface.name}:members',
                    options=failover_group_defaults(protocol),
                )
                session.add(group)
                session.flush()
                for position, member_iface_id in enumerate(iface_spec['members']):
                    id_map[member_iface_id] = iface.id
                    session.execute(
                        group_membership.insert().values(
                            group_id=group.id,
                            member_id=member_iface_id,
                            position=position,
                        )
                    )

            if source_id is not None:
                self._take_over_member_rules(
                    session, cluster, spec['members'], source_id, id_map
                )

            session.commit()
            self._db_manager.save_state(f'{prefix}New Cluster {cluster.name}')
            new_id = cluster.id
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

    def _take_over_member_rules(self, session, cluster, member_ids, source_id, id_map):
        """Back up the members, copy the rules of one, empty all of them."""
        members = [session.get(Firewall, member_id) for member_id in member_ids]
        for member in members:
            id_map[member.id] = cluster.id

            backup_map = {}
            backup = self._clone_object(member, backup_map)
            backup.name = f'{member.name}-bak'
            backup.name = self.make_name_unique(session, backup)
            backup.data = {**(backup.data or {}), 'inactive': True}
            session.add(backup)
            self._duplicate_device_children(
                session, session, member, backup, backup_map
            )

        source = session.get(Firewall, source_id)
        self._copy_rule_sets(session, session, source, cluster, id_map)

        for member in members:
            obj_ids, rule_ids = set(), set()
            for rule_set in member.rule_sets:
                if rule_set.type not in ('NAT', 'Policy', 'Routing'):
                    continue
                obj_ids.add(rule_set.id)
                for rule in rule_set.rules:
                    obj_ids.add(rule.id)
                    rule_ids.add(rule.id)
            self._cleanup_references_and_delete(session, obj_ids, rule_ids)
            session.flush()
            session.expire(member, ['rule_sets'])
            add_device_defaults(session, member)

    def create_host_with_interfaces(
        self,
        lib_id,
        *,
        folder=None,
        interfaces=None,
        name=None,
        prefix='',
    ):
        """Create a Host with interfaces and addresses in one operation.

        Mirrors fwbuilder's ``newHostDialog::finishClicked()`` which
        creates the Host, its Interface children, and their IPv4/IPv6
        address children as a single undo-able action.

        Returns the new Host UUID, or None on failure.
        """
        if self._db_manager is None:
            return None

        session = self._db_manager.create_session()
        try:
            host_id = uuid.uuid4()
            host_kwargs = {
                'id': host_id,
                'type': 'Host',
                'library_id': lib_id,
            }
            # Place in the nested group (Objects/Hosts) if it exists.
            path = SYSTEM_GROUP_PATHS.get('Host', '')
            target_group = find_group_by_path(session, lib_id, path)
            if target_group is not None:
                host_kwargs['group_id'] = target_group.id
            elif folder:
                host_kwargs['data'] = {'folder': folder}
            host = Host(**host_kwargs)
            host.name = name or 'New Host'
            host.name = self.make_name_unique(session, host)
            session.add(host)

            for iface_data in interfaces or []:
                iface_id = uuid.uuid4()
                iface_name = iface_data.get('name', '')
                if not iface_name:
                    continue
                itype = iface_data.get('type', 0)
                iface = Interface(
                    id=iface_id,
                    device_id=host_id,
                    library_id=lib_id,
                    name=iface_name,
                    comment=iface_data.get('comment', ''),
                    data={
                        'dyn': str(itype == 1),
                        'label': iface_data.get('label', ''),
                        'security_level': '0',
                        'unnum': str(itype == 2),
                    },
                )
                session.add(iface)

                # Create IPv4/IPv6 address children (static interfaces only).
                if itype == 0:
                    for addr_info in iface_data.get('addresses', []):
                        addr_str = addr_info.get('address', '')
                        mask_str = addr_info.get('netmask', '')
                        is_v4 = addr_info.get('ipv4', True)
                        if not addr_str:
                            continue
                        addr_type = 'IPv4' if is_v4 else 'IPv6'
                        suffix = 'ip' if is_v4 else 'ip6'
                        addr_name = f'{host.name}:{iface_name}:{suffix}'
                        addr = Address(
                            id=uuid.uuid4(),
                            type=addr_type,
                            interface_id=iface_id,
                            name=addr_name,
                            inet_addr_mask={
                                'address': addr_str,
                                'netmask': mask_str,
                            },
                        )
                        session.add(addr)

            session.commit()
            self._db_manager.save_state(f'{prefix}New Host {host.name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return host_id

    # ------------------------------------------------------------------
    # Folder move (drag & drop / cut-paste)
    # ------------------------------------------------------------------

    def set_object_folder(self, obj_id, model_cls, folder, *, prefix=''):
        """Set or clear ``data.folder`` on an existing object.

        *folder* is the target subfolder path (e.g. ``'A/B'``) or an
        empty string to move the object back to the group root.
        """
        if self._db_manager is None:
            return False

        session = self._db_manager.create_session()
        try:
            obj = session.get(model_cls, obj_id)
            if obj is None or not hasattr(obj, 'data'):
                session.close()
                return False
            data = copy.deepcopy(obj.data or {})
            old_folder = data.get('folder', '')
            if old_folder == folder:
                session.close()
                return False  # No-op.
            if folder:
                data['folder'] = folder
            else:
                data.pop('folder', None)
            obj.data = data
            session.commit()
            self._db_manager.save_state(
                f'{prefix}Move {getattr(obj, "type", type(obj).__name__)}'
                f' {obj.name} to folder'
            )
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    # ------------------------------------------------------------------
    # Subfolder & Rename
    # ------------------------------------------------------------------

    def create_subfolder(self, lib_id, name, *, parent_group_id=None):
        """Create a user subfolder in the parent's ``data.subfolders`` list.

        Matches fwbuilder's ``addSubfolderSlot()``: the subfolder is stored
        on whichever object the user right-clicked (a Group or a Library).
        """
        if self._db_manager is None:
            return

        session = self._db_manager.create_session()
        try:
            if parent_group_id is not None:
                parent = session.get(Group, parent_group_id)
            else:
                parent = session.get(Library, lib_id)
            if parent is None:
                return
            data = copy.deepcopy(parent.data or {})
            subfolders = normalize_subfolders(data.get('subfolders', []))
            if name in subfolders:
                return  # Already exists.
            subfolders.append(name)
            subfolders.sort(key=str.casefold)
            data['subfolders'] = subfolders
            parent.data = data
            session.commit()
            self._db_manager.save_state(f'New subfolder "{name}"')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def rename_folder(self, lib_id, old_name, new_name, *, parent_group_id=None):
        """Rename a category folder and update all nested child paths.

        Updates ``data.folder`` on every child object whose folder
        matches (or is nested under) *old_name*, and updates the
        parent's ``data['subfolders']`` list accordingly.
        """
        if self._db_manager is None:
            return

        old_prefix = old_name + '/'

        def _rename_folder_value(folder):
            if folder == old_name:
                return new_name
            if folder.startswith(old_prefix):
                return new_name + folder[len(old_name) :]
            return None

        session = self._db_manager.create_session()
        try:
            if parent_group_id is not None:
                parent_grp = session.get(Group, parent_group_id)
                if parent_grp is not None:
                    for attr in (
                        'addresses',
                        'child_groups',
                        'devices',
                        'intervals',
                        'services',
                    ):
                        for child in getattr(parent_grp, attr, []):
                            obj_data = child.data or {}
                            renamed = _rename_folder_value(obj_data.get('folder', ''))
                            if renamed is not None:
                                child.data = {**obj_data, 'folder': renamed}
                parent = parent_grp
            else:
                for cls in _LIB_OWNED_CLASSES:
                    if not hasattr(cls, 'data') or not hasattr(cls, 'library_id'):
                        continue
                    for obj in (
                        session.scalars(
                            sqlalchemy.select(cls).where(cls.library_id == lib_id)
                        )
                        .unique()
                        .all()
                    ):
                        obj_data = obj.data or {}
                        renamed = _rename_folder_value(obj_data.get('folder', ''))
                        if renamed is not None:
                            obj.data = {**obj_data, 'folder': renamed}
                parent = session.get(Library, lib_id)

            # Update parent's data['subfolders'] list — rename exact
            # match and all nested child paths.
            if parent is not None:
                parent_data = copy.deepcopy(parent.data or {})
                subfolders = normalize_subfolders(parent_data.get('subfolders', []))
                new_subfolders = []
                for s in subfolders:
                    renamed = _rename_folder_value(s)
                    new_subfolders.append(renamed if renamed is not None else s)
                new_subfolders.sort(key=str.casefold)
                parent_data['subfolders'] = new_subfolders
                parent.data = parent_data

            session.commit()
            self._db_manager.save_state(
                f'Rename folder \u201c{old_name}\u201d \u2192 \u201c{new_name}\u201d'
            )
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Group
    # ------------------------------------------------------------------

    def group_objects(self, group_type, group_name, lib_id, member_ids):
        """Create a new group containing *member_ids*.  Returns new UUID or None."""
        if self._db_manager is None:
            return None

        # Determine the folder for this group type.
        folder = None
        for f, type_list in NEW_TYPES_FOR_FOLDER.items():
            if any(tn == group_type for tn, _dn in type_list):
                folder = f
                break

        new_id = self.create_new_object(
            MODEL_MAP[group_type],
            group_type,
            lib_id,
            folder=folder,
            name=group_name,
        )
        if new_id is None:
            return None

        # FWObject::addRef asks the group's validateChild and leaves out
        # what it refuses (fwbuilder5 FWObject.cpp:889), so a selection of
        # an address, a service and a rule set makes a group of the
        # address alone.
        self.add_group_members(
            new_id, member_ids, description=f'Group {len(member_ids)} objects'
        )
        return new_id

    def add_group_members(self, group_id, member_ids, *, description=None):
        """Add *member_ids* to the group *group_id*; return how many were added.

        The "regular group" branch of ``ObjectManipulator::actuallyPasteTo``
        (fwbuilder5 ObjectManipulator_ops.cpp:344): a member already in the
        group is not added again, and one the group's ``validateChild``
        refuses is left out (:func:`group_accepts`).
        """
        if self._db_manager is None:
            return 0
        session = self._db_manager.create_session()
        added = 0
        try:
            group = session.get(Group, group_id)
            if group is None:
                return 0
            rows = session.execute(
                sqlalchemy.select(
                    group_membership.c.member_id, group_membership.c.position
                ).where(group_membership.c.group_id == group_id)
            ).all()
            present = {row.member_id for row in rows}
            position = max((row.position for row in rows), default=-1) + 1
            for mid in member_ids:
                mid = uuid.UUID(mid) if isinstance(mid, str) else mid
                if mid in present:
                    continue
                obj = load_object(session, mid)
                if obj is None or not group_accepts(group, obj):
                    continue
                session.execute(
                    group_membership.insert().values(
                        group_id=group_id, member_id=mid, position=position
                    )
                )
                present.add(mid)
                position += 1
                added += 1
            session.commit()
            if added:
                self._db_manager.save_state(
                    description or f'Add {added} objects to {group.name}'
                )
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return added

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def make_name_unique(session, obj):
        """Return a unique name, appending '-1', '-2', ... only if needed.

        Queries the appropriate table for existing names.  If the base
        name is already free it is returned as-is (matching fwbuilder's
        ``makeNameUnique()``).
        """
        base_name = obj.name
        model_cls = type(obj)

        # Collect existing names in the same scope: the parent the object
        # sits in, the way ``makeNameUnique(target, ...)`` asks the
        # children of the paste target.  An interface is unique among the
        # interfaces of its device (or parent interface), an address among
        # those of its interface; everything else within its library.
        stmt = sqlalchemy.select(model_cls.name).where(
            model_cls.name.like(f'{base_name}%'),
            model_cls.id != obj.id,
        )
        if isinstance(obj, Interface) and (
            obj.device_id is not None or obj.parent_interface_id is not None
        ):
            stmt = stmt.where(
                model_cls.device_id == obj.device_id,
                model_cls.parent_interface_id.is_(None)
                if obj.parent_interface_id is None
                else model_cls.parent_interface_id == obj.parent_interface_id,
            )
        elif isinstance(obj, RuleSet):
            stmt = stmt.where(model_cls.device_id == obj.device_id)
        elif getattr(obj, 'interface_id', None) is not None:
            stmt = stmt.where(model_cls.interface_id == obj.interface_id)
        elif hasattr(obj, 'library_id') and obj.library_id is not None:
            stmt = stmt.where(model_cls.library_id == obj.library_id)
        existing = set(session.scalars(stmt).all())

        if base_name not in existing:
            return base_name

        suffix = 1
        while True:
            candidate = f'{base_name}-{suffix}'
            if candidate not in existing:
                return candidate
            suffix += 1

    # ------------------------------------------------------------------
    # Lock / Unlock
    # ------------------------------------------------------------------

    def lock_objects(self, obj_ids_with_types):
        """Set ``ro=True`` on the given objects.  Returns True on success."""
        if self._db_manager is None:
            return False
        session = self._db_manager.create_session()
        try:
            names = []
            for obj_id, obj_type in obj_ids_with_types:
                model_cls = MODEL_MAP.get(obj_type)
                if model_cls is None:
                    continue
                uid = uuid.UUID(obj_id) if isinstance(obj_id, str) else obj_id
                obj = session.get(model_cls, uid)
                if obj is not None and hasattr(obj, 'ro'):
                    obj.ro = True
                    names.append(obj.name)
            session.commit()
            label = ', '.join(names[:3]) + ('...' if len(names) > 3 else '')
            self._db_manager.save_state(f'Lock {label}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    def unlock_objects(self, obj_ids_with_types):
        """Set ``ro=False`` on the given objects.  Returns True on success."""
        if self._db_manager is None:
            return False
        session = self._db_manager.create_session()
        try:
            names = []
            for obj_id, obj_type in obj_ids_with_types:
                model_cls = MODEL_MAP.get(obj_type)
                if model_cls is None:
                    continue
                uid = uuid.UUID(obj_id) if isinstance(obj_id, str) else obj_id
                obj = session.get(model_cls, uid)
                if obj is not None and hasattr(obj, 'ro'):
                    obj.ro = False
                    names.append(obj.name)
            session.commit()
            label = ', '.join(names[:3]) + ('...' if len(names) > 3 else '')
            self._db_manager.save_state(f'Unlock {label}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    # ------------------------------------------------------------------
    # Keywords
    # ------------------------------------------------------------------

    def add_keyword(self, obj_ids_with_types, keyword):
        """Add *keyword* to the given objects.  Returns True on success."""
        if self._db_manager is None:
            return False
        session = self._db_manager.create_session()
        try:
            for obj_id, obj_type in obj_ids_with_types:
                model_cls = MODEL_MAP.get(obj_type)
                if model_cls is None:
                    continue
                uid = uuid.UUID(obj_id) if isinstance(obj_id, str) else obj_id
                obj = session.get(model_cls, uid)
                if obj is not None and hasattr(obj, 'keywords'):
                    kw = set(obj.keywords or set())
                    kw.add(keyword)
                    obj.keywords = kw
            session.commit()
            self._db_manager.save_state(f'Add keyword "{keyword}"')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    def remove_keyword(self, obj_ids_with_types, keyword):
        """Remove *keyword* from the given objects.  Returns True on success."""
        if self._db_manager is None:
            return False
        session = self._db_manager.create_session()
        try:
            for obj_id, obj_type in obj_ids_with_types:
                model_cls = MODEL_MAP.get(obj_type)
                if model_cls is None:
                    continue
                uid = uuid.UUID(obj_id) if isinstance(obj_id, str) else obj_id
                obj = session.get(model_cls, uid)
                if obj is not None and hasattr(obj, 'keywords'):
                    kw = set(obj.keywords or set())
                    kw.discard(keyword)
                    obj.keywords = kw
            session.commit()
            self._db_manager.save_state(f'Remove keyword "{keyword}"')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    # ------------------------------------------------------------------
    # Make subinterface
    # ------------------------------------------------------------------

    def make_subinterface(self, iface_id, target_parent_iface_id, *, prefix=''):
        """Reparent an interface under another interface.  Returns True on success."""
        if self._db_manager is None:
            return False
        session = self._db_manager.create_session()
        try:
            iface = session.get(Interface, iface_id)
            if iface is None:
                return False
            iface.parent_interface_id = target_parent_iface_id
            iface_name = iface.name
            session.commit()
            self._db_manager.save_state(f'{prefix}Make subinterface {iface_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return True

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_all_tags(db_manager):
        """Collect every keyword used across all object tables."""
        if db_manager is None:
            return set()
        all_tags = set()
        with db_manager.session() as session:
            for cls in (Address, Group, Host, Interface, Interval, Service):
                for (tag_set,) in session.execute(sqlalchemy.select(cls.keywords)):
                    if tag_set:
                        all_tags.update(tag_set)
        return all_tags

    @staticmethod
    def get_writable_libraries(db_manager):
        """Return [(lib_id, lib_name), ...] for non-read-only libraries."""
        if db_manager is None:
            return []
        result = []
        with db_manager.session() as session:
            for lib in session.scalars(sqlalchemy.select(Library)).all():
                if not lib.ro:
                    result.append((lib.id, lib.name))
        result.sort(key=lambda t: t[1].lower())
        return result
