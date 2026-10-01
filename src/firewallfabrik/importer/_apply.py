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

"""Put an import plan into an open data file.

The plan holds object descriptions in the shape of the ``.fwf`` file, and
the YAML reader turns them into objects the way it does when a file is
loaded - ``File > Import Library`` merges a library with the same reader
(``gui/library_export.py``).  The reader starts from the reference paths
of everything the data file already has, so a rule that names an object
of the Standard library lands on that object.

Each new object goes into the folder the object tree keeps objects of its
type in.  The folders are passed in (``SYSTEM_GROUP_PATHS`` of the GUI),
so that this module does not need the GUI to run.
"""

import sqlalchemy

from firewallfabrik.compiler.processors._service import icmp_type_and_code
from firewallfabrik.core import objects
from firewallfabrik.core._util import escape_obj_name
from firewallfabrik.core._yaml_reader import YamlReader
from firewallfabrik.core._yaml_writer import YamlWriter
from firewallfabrik.importer._builder import (
    Builder,
    ExistingObjects,
    address_from_object,
    address_signature,
    service_signature,
)

_FLAGS = ('urg', 'ack', 'psh', 'rst', 'syn', 'fin')


def plan_import(
    db_manager,
    library_id,
    rulesets,
    fw_name,
    platform,
    version='',
    group_paths=None,
    deduplicate=True,
    table_filter=None,
    interface_addresses=None,
):
    """Build the plan for importing *rulesets* as firewall *fw_name*."""
    with db_manager.session() as session:
        library = session.get(objects.Library, library_id)
        if library is None:
            raise ValueError('The library to import into does not exist.')
        ids_to_paths = _paths(session)
        groups = _group_paths(session, library, ids_to_paths, group_paths or {})
        library_path = f'Library:{escape_obj_name(library.name)}'

        def path_for(type_name, name):
            parent = groups.get(type_name, library_path)
            return f'{parent}/{type_name}:{escape_obj_name(name)}'

        existing = _existing_objects(session, ids_to_paths, library, deduplicate)
    if not version:
        version = _version_for(platform, rulesets)
    builder = Builder(
        fw_name,
        platform,
        version,
        library_path,
        path_for,
        existing,
        interface_addresses=interface_addresses,
    )
    return builder.build(rulesets, table_filter=table_filter)


def apply_plan(db_manager, library_id, plan, group_paths=None):
    """Create the objects and the firewall of *plan*; return the firewall's id."""
    with db_manager.session() as session:
        library = session.get(objects.Library, library_id)
        ids_to_paths = _paths(session)
        library_path = f'Library:{escape_obj_name(library.name)}'
        groups = _group_objects(session, library, group_paths or {})

        reader = YamlReader()
        reader._ref_index.update({path: id_ for id_, path in ids_to_paths.items()})
        # The reader hangs each new object on its library and folder, and
        # SQLAlchemy 2 no longer carries an object into the session along
        # such a back reference; each one is added here, before anything
        # flushes.
        created = []
        with session.no_autoflush:
            for obj in [*plan.objects, plan.firewall]:
                group = groups.get(obj['type'])
                parent_path = (
                    ids_to_paths[group.id] if group is not None else library_path
                )
                created.append(_parse(reader, obj, library, parent_path, group))
            reader._resolve_deferred()
            session.add_all(created)
        session.flush()
        if reader._memberships:
            session.execute(objects.group_membership.insert(), reader._memberships)
        if reader._rule_element_rows:
            session.execute(objects.rule_elements.insert(), reader._rule_element_rows)

        firewall = session.scalars(
            sqlalchemy.select(objects.Firewall).where(
                objects.Firewall.library_id == library.id,
                objects.Firewall.name == plan.firewall['name'],
            )
        ).first()
        db_manager.ref_index.update(reader._ref_index)
        unresolved = sorted(set(reader.unresolved_refs))
        return firewall.id, unresolved


def _version_for(platform, rulesets):
    """The entry of the version list for the release that wrote the input.

    The release of the tool that wrote the listing is the release of the
    packet filter only if that is the platform the firewall is imported
    for; otherwise, and where the input names none, the newest entry.
    """
    from firewallfabrik.platforms import _versions

    source = {'iptables': 'iptables', 'nftables': 'nftables'}
    for ruleset in rulesets:
        if source.get(ruleset.source) == platform and ruleset.version:
            entry = _versions.entry_for(platform, ruleset.version, {})
            if entry:
                return entry
    return _versions.newest(platform)[0]


def _parse(reader, data, library, parent_path, group):
    """Read one object description the way ``YamlReader._dispatch_child`` does.

    The reader's dispatcher returns nothing, and the object it built is
    what has to be added to the session.
    """
    type_name = data['type']
    if type_name in ('ObjectGroup', 'ServiceGroup'):
        obj = reader._parse_group(data, library, parent_path, parent_group=group)
    elif type_name in ('Firewall', 'Host', 'Cluster'):
        obj = reader._parse_device(data, library, parent_path)
    elif type_name.endswith('Service'):
        obj = reader._parse_service(data, library, parent_path)
    else:
        obj = reader._parse_address(data, parent_path, library=library)
    if group is not None and type_name not in ('ObjectGroup', 'ServiceGroup'):
        obj.group = group
    return obj


def _paths(session):
    """Every object's reference path, the way a save would write it."""
    writer = YamlWriter()
    libraries = session.scalars(sqlalchemy.select(objects.Library)).all()
    writer._build_ref_index(session, libraries)
    return writer._ref_index


def _group_objects(session, library, group_paths):
    groups = {}
    for type_name, path in group_paths.items():
        group = _find_group(session, library.id, path)
        if group is not None:
            groups[type_name] = group
    return groups


def _group_paths(session, library, ids_to_paths, group_paths):
    return {
        type_name: ids_to_paths[group.id]
        for type_name, group in _group_objects(session, library, group_paths).items()
        if group.id in ids_to_paths
    }


def _find_group(session, library_id, path):
    parent_id = None
    group = None
    for part in path.split('/'):
        stmt = sqlalchemy.select(objects.Group).where(
            objects.Group.library_id == library_id,
            objects.Group.name == part,
        )
        if parent_id is None:
            stmt = stmt.where(objects.Group.parent_group_id.is_(None))
        else:
            stmt = stmt.where(objects.Group.parent_group_id == parent_id)
        group = session.scalars(stmt).first()
        if group is None:
            return None
        parent_id = group.id
    return group


def _existing_objects(session, ids_to_paths, library, deduplicate):
    existing = ExistingObjects()
    existing.taken_names = {
        name
        for model in (objects.Address, objects.Service, objects.Group, objects.Host)
        for name in session.scalars(
            sqlalchemy.select(model.name).where(model.library_id == library.id)
        )
    }
    if not deduplicate:
        return existing

    for obj in session.scalars(
        sqlalchemy.select(objects.Address).where(
            objects.Address.interface_id.is_(None),
            objects.Address.library_id.is_not(None),
        )
    ):
        if obj.id not in ids_to_paths or obj.run_time:
            continue
        if obj.name in ('Any', 'Dummy') and ids_to_paths[obj.id].startswith(
            'Library:Standard/'
        ):
            # Placeholders, not addresses: "Any" is 0.0.0.0/0 inside but a
            # rule element holding it matches both address families, and
            # "Dummy" (255.255.255.255) stands for an emptied rule element.
            continue
        address = address_from_object(obj)
        if address is None:
            continue
        try:
            signature = address_signature(address)
        except ValueError:
            continue
        existing.by_signature.setdefault(signature, ids_to_paths[obj.id])

    for obj in session.scalars(sqlalchemy.select(objects.Service)):
        if obj.id not in ids_to_paths:
            continue
        if obj.name in ('Any', 'Dummy') and ids_to_paths[obj.id].startswith(
            'Library:Standard/'
        ):
            continue
        signature = _service_signature_of(obj)
        if signature is not None:
            existing.by_signature.setdefault(signature, ids_to_paths[obj.id])
        if isinstance(obj, objects.CustomService) and obj.name in (
            'ESTABLISHED',
            'ESTABLISHED ipv6',
        ):
            family = 6 if obj.name.endswith('ipv6') else 4
            codes = obj.codes or {}
            if 'ESTABLISHED,RELATED' in codes.get('iptables', ''):
                existing.established.setdefault(family, ids_to_paths[obj.id])
    return existing


def _service_signature_of(obj):
    """What a service object of the data file matches, or None.

    A service that does more than match - one that assigns a connection
    tracking helper, or asks for the "established" flag - is never used in
    place of a plain one, or the imported rule would do more than the rule
    it came from.
    """
    data = obj.data or {}
    if isinstance(obj, (objects.TCPService, objects.UDPService)):
        if data.get('conntrack_helper') or str(data.get('established', '')).lower() in (
            'true',
            '1',
        ):
            return None
        protocol = 'tcp' if isinstance(obj, objects.TCPService) else 'udp'
        src = (obj.src_range_start or 0, obj.src_range_end or 0)
        dst = (obj.dst_range_start or 0, obj.dst_range_end or 0)
        flags = obj.tcp_flags or {}
        masks = obj.tcp_flags_masks or {}
        return service_signature(
            protocol,
            src,
            dst,
            frozenset(f for f in _FLAGS if flags.get(f)),
            frozenset(f for f in _FLAGS if masks.get(f)),
        )
    if isinstance(obj, objects.ICMPService):
        protocol = 'icmpv6' if isinstance(obj, objects.ICMP6Service) else 'icmp'
        # Read the way the print rules read it - from "codes", where the
        # Standard library keeps it, or from "data" - or the import would
        # stand an object for a type the compiler then writes differently.
        icmp = icmp_type_and_code(obj)
        return service_signature(protocol, icmp=icmp)
    if type(obj) is objects.IPService:
        if any(
            value not in (None, '', False, 'False', 'false', '0')
            for value in data.values()
        ):
            return None
        number = (obj.named_protocols or {}).get('protocol_num')
        if number in (None, '', '0'):
            return None
        return service_signature(str(number))
    return None
