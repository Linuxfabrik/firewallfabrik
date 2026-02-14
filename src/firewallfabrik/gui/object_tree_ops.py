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

import copy
import uuid

import sqlalchemy

from firewallfabrik.core.objects import (
    Address,
    Group,
    Host,
    Interface,
    Interval,
    Library,
    Rule,
    RuleSet,
    Service,
    group_membership,
    rule_elements,
)
from firewallfabrik.gui.object_tree_data import (
    MODEL_MAP,
    NEW_TYPES_FOR_FOLDER,
    SYSTEM_GROUP_PATHS,
    find_group_by_path,
    normalize_subfolders,
)

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
        Interface -> Addresses, Group -> members -> sub-groups.

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

            # Interface -> addresses
            iface = session.get(Interface, current_id)
            if iface is not None:
                for addr in iface.addresses:
                    obj_ids.add(addr.id)

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
    def _cleanup_references_and_delete(session, obj_ids, rule_ids):
        """Single-pass reference cleanup + cascade delete."""
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

            obj_ids, rule_ids = self._collect_all_ids(session, obj_id)
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
        """Delete a user-created subfolder.

        Moves all child objects to the parent level (removes their
        ``data.folder`` field) and removes the subfolder from the
        parent's ``data['subfolders']``.  The parent is determined by
        *parent_group_id* (a Group) or falls back to the Library.
        """
        if self._db_manager is None:
            return

        session = self._db_manager.create_session()
        try:
            if parent_group_id is not None:
                # Group-level subfolder: clear data.folder on children
                # of this group that are in the deleted folder.
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
                            if obj_data.get('folder') == folder_name:
                                new_data = {
                                    k: v for k, v in obj_data.items() if k != 'folder'
                                }
                                child.data = new_data or None
            else:
                # Library-level subfolder: clear data.folder on all
                # library-owned objects in this folder.
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
                        if obj_data.get('folder') == folder_name:
                            new_data = {
                                k: v for k, v in obj_data.items() if k != 'folder'
                            }
                            obj.data = new_data or None
                parent = session.get(Library, lib_id)

            # Remove from parent's data['subfolders'].
            if parent is not None:
                parent_data = dict(parent.data or {})
                subfolders = normalize_subfolders(parent_data.get('subfolders', []))
                if folder_name in subfolders:
                    subfolders.remove(folder_name)
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
        prefix='',
        target_group_id=None,
        target_interface_id=None,
    ):
        """Deep-copy *source_id* into *target_lib_id*. Returns new UUID or None.

        Optional *target_interface_id* / *target_group_id* place the clone
        under a specific interface or group instead of the library root.
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

            if target_interface_id is not None and hasattr(new_obj, 'interface_id'):
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

            # Make name unique within the target scope.
            new_obj.name = self.make_name_unique(session, new_obj)

            session.add(new_obj)

            # Deep-copy children for devices (interfaces, rule sets, rules, rule elements).
            if isinstance(source, Host):
                self._duplicate_device_children(session, source, new_obj, id_map)

            # Copy group_membership entries for groups.
            if isinstance(source, Group):
                self._duplicate_group_members(session, source, new_obj)

            session.commit()
            self._db_manager.save_state(
                f'{prefix}Duplicate {source.type} {source.name}',
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

    def _duplicate_device_children(self, session, source_device, new_device, id_map):
        """Recursively duplicate interfaces, addresses, rule sets, rules, and rule elements."""
        # Interfaces + their child addresses.
        for iface in source_device.interfaces:
            new_iface = self._clone_object(iface, id_map)
            new_iface.device_id = new_device.id
            new_iface.library_id = new_device.library_id
            session.add(new_iface)
            for addr in iface.addresses:
                new_addr = self._clone_object(addr, id_map)
                new_addr.interface_id = new_iface.id
                new_addr.library_id = None
                new_addr.group_id = None
                session.add(new_addr)

        # Rule sets + their rules + rule_elements.
        for rs in source_device.rule_sets:
            new_rs = self._clone_object(rs, id_map)
            new_rs.device_id = new_device.id
            session.add(new_rs)
            for rule in rs.rules:
                new_rule = self._clone_object(rule, id_map)
                new_rule.rule_set_id = new_rs.id
                session.add(new_rule)
                # Copy rule_elements, remapping target_id for internal refs.
                rows = session.execute(
                    sqlalchemy.select(rule_elements).where(
                        rule_elements.c.rule_id == rule.id
                    )
                ).all()
                for row in rows:
                    target_id = id_map.get(row.target_id, row.target_id)
                    session.execute(
                        rule_elements.insert().values(
                            rule_id=new_rule.id,
                            slot=row.slot,
                            target_id=target_id,
                            position=row.position,
                        )
                    )

    @staticmethod
    def _duplicate_group_members(session, source_group, new_group):
        """Copy group_membership entries from *source_group* to *new_group*."""
        rows = session.execute(
            sqlalchemy.select(group_membership).where(
                group_membership.c.group_id == source_group.id
            )
        ).all()
        for row in rows:
            session.execute(
                group_membership.insert().values(
                    group_id=new_group.id,
                    member_id=row.member_id,
                    position=row.position,
                )
            )

    # ------------------------------------------------------------------
    # Move
    # ------------------------------------------------------------------

    def move_object(self, obj_id, model_cls, target_lib_id):
        """Move *obj_id* to *target_lib_id*. Returns True on success."""
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

            # For devices, also move child interfaces.
            if isinstance(obj, Host):
                for iface in obj.interfaces:
                    iface.library_id = target_lib_id

            session.commit()
            self._db_manager.save_state(f'Move {obj_type} {obj_name}')
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
                    folder = None  # Don't also set data.folder.

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
                    folder = None  # Don't also set data.folder.

            # Build data dict: merge folder and extra_data.
            data = {}
            if folder:
                data['folder'] = folder
            if extra_data:
                data.update(extra_data)
            if data and hasattr(model_cls, 'data'):
                kwargs['data'] = data

            new_obj = model_cls(**kwargs)
            new_obj.name = name or f'New {type_name}'

            # Make name unique.
            new_obj.name = self.make_name_unique(session, new_obj)

            session.add(new_obj)
            session.commit()
            self._db_manager.save_state(f'{prefix}New {type_name}')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

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
            data = dict(parent.data or {})
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
        """Rename a category folder.

        Updates ``data.folder`` on every child object and the parent's
        ``data['subfolders']`` list.  The parent is determined by
        *parent_group_id* (a Group) or falls back to the Library.
        """
        if self._db_manager is None:
            return

        session = self._db_manager.create_session()
        try:
            if parent_group_id is not None:
                # Group-level subfolder: rename data.folder on children.
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
                            if obj_data.get('folder') == old_name:
                                child.data = {**obj_data, 'folder': new_name}
                parent = parent_grp
            else:
                # Library-level subfolder: rename data.folder on all
                # library-owned objects.
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
                        if obj_data.get('folder') == old_name:
                            obj.data = {**obj_data, 'folder': new_name}
                parent = session.get(Library, lib_id)

            # Update parent's data['subfolders'] list.
            if parent is not None:
                parent_data = dict(parent.data or {})
                subfolders = normalize_subfolders(parent_data.get('subfolders', []))
                if old_name in subfolders:
                    subfolders[subfolders.index(old_name)] = new_name
                    subfolders.sort(key=str.casefold)
                    parent_data['subfolders'] = subfolders
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

        # Add group_membership entries.
        session = self._db_manager.create_session()
        try:
            for pos, mid in enumerate(member_ids):
                session.execute(
                    group_membership.insert().values(
                        group_id=new_id,
                        member_id=uuid.UUID(mid) if isinstance(mid, str) else mid,
                        position=pos,
                    )
                )
            session.commit()
            self._db_manager.save_state(f'Group {len(member_ids)} objects')
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        return new_id

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

        # Collect existing names in the same scope.
        stmt = sqlalchemy.select(model_cls.name).where(
            model_cls.name.like(f'{base_name}%')
        )
        if hasattr(obj, 'library_id') and obj.library_id is not None:
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

    def make_subinterface(self, iface_id, target_parent_iface_id):
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
            self._db_manager.save_state(f'Make subinterface {iface_name}')
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
