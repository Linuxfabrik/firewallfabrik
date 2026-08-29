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

"""Creating and editing an "Attached Networks" object.

The object type was in the tree data, in the icon map, in the main
window's editor stack and in the rule element's list of valid types, and
none of the three things that make it usable existed: no menu entry to
create one, no panel to look at it in, and Delete was turned off so one
created by accident could not be taken away ([#85]).

[#85]: https://github.com/Linuxfabrik/firewallfabrik/issues/85
"""

import os
import uuid

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import firewallfabrik.core
from firewallfabrik.core.objects import (
    Firewall,
    FWObjectDatabase,
    Group,
    Interface,
    IPv4,
    IPv6,
    Library,
)
from firewallfabrik.gui.object_tree_data import NO_DELETE_TYPES
from firewallfabrik.gui.object_tree_menu import _get_interface_new_types
from firewallfabrik.gui.object_tree_ops import TreeOperations


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def panel():
    """The real editor panel, reached the way the loader registers it."""
    from firewallfabrik.gui import ui_loader

    return ui_loader.CUSTOM_WIDGET_MAP['AttachedNetworksDialog']()


def _firewall_with_interface():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        session.flush()
        fw = Firewall(
            id=uuid.uuid4(), type='Firewall', name='fw1', library_id=library.id
        )
        session.add(fw)
        session.flush()
        iface = Interface(id=uuid.uuid4(), name='eth0', device_id=fw.id)
        session.add(iface)
        session.flush()
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='fw1:eth0:ip',
                interface_id=iface.id,
                inet_addr_mask={'address': '192.0.2.5', 'netmask': '255.255.255.0'},
            )
        )
        session.add(
            IPv6(
                id=uuid.uuid4(),
                type='IPv6',
                name='fw1:eth0:ip6',
                interface_id=iface.id,
                inet_addr_mask={'address': '2001:db8::5', 'netmask': '64'},
            )
        )
        session.commit()
        return dm, library.id, iface.id


def _tree_item(child_types=()):
    """A tree node for an interface under a firewall, with *child_types*."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

    tree = QTreeWidget()
    firewall = QTreeWidgetItem(tree)
    firewall.setData(0, Qt.ItemDataRole.UserRole + 1, 'Firewall')
    item = QTreeWidgetItem(firewall)
    item.setData(0, Qt.ItemDataRole.UserRole + 1, 'Interface')
    for type_name in child_types:
        child = QTreeWidgetItem(item)
        child.setData(0, Qt.ItemDataRole.UserRole + 1, type_name)
    # The widget owns the items, so it has to outlive the caller.
    item.tree = tree
    return item


def test_the_menu_offers_one_per_interface():
    item = _tree_item()

    entries = {entry[0]: entry for entry in _get_interface_new_types(item)}

    assert 'AttachedNetworks' in entries
    assert entries['AttachedNetworks'][1] == 'Attached Networks'
    assert entries['AttachedNetworks'][2] is True


def test_the_menu_greys_it_out_once_the_interface_has_one():
    item = _tree_item(child_types=('AttachedNetworks',))

    entries = {entry[0]: entry for entry in _get_interface_new_types(item)}

    assert entries['AttachedNetworks'][2] is False


def test_one_created_that_way_hangs_under_its_interface():
    dm, lib_id, iface_id = _firewall_with_interface()
    ops = TreeOperations(dm)

    new_id = ops.create_new_object(
        Group,
        'AttachedNetworks',
        lib_id,
        interface_id=iface_id,
        name='fw1:eth0:attached',
    )

    with dm.session() as session:
        obj = session.get(Group, new_id)
        assert obj.interface_id == iface_id
        assert obj.device_id is None
        assert obj.library_id == lib_id


def test_it_can_be_deleted_again():
    """Otherwise the menu entry stays greyed out for good."""
    assert 'AttachedNetworks' not in NO_DELETE_TYPES


def test_the_panel_lists_the_subnets_of_the_interface(panel):
    dm, lib_id, iface_id = _firewall_with_interface()
    ops = TreeOperations(dm)
    new_id = ops.create_new_object(
        Group,
        'AttachedNetworks',
        lib_id,
        interface_id=iface_id,
        name='fw1:eth0:attached',
    )

    with dm.session() as session:
        panel.load_object(session.get(Group, new_id))
        listed = [
            panel.addresses.item(row).text() for row in range(panel.addresses.count())
        ]

    assert listed == ['192.0.2.0/255.255.255.0', '2001:db8::/64']
    assert panel.obj_name.text() == 'fw1:eth0:attached'
    # The list is what the compiler works out, not something to type into.
    assert not panel.addresses.isEnabled()
