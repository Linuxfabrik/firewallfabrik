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

"""What a new address object or interface starts out with, and that it
can be edited.

The editor validates and saves on every field that is left, and reloads
the stored values when it refuses (``ObjectEditor::changed``).  A new
network created with an empty address and netmask was refused on the
first field, so the name was lost, and once an address was typed the
empty netmask was refused and the address was lost: the object could
not be filled in at all ([#209]).  Firewall Builder never gets there,
because its constructors give every address object values the editor
accepts.  A new interface was called "New Interface", a name the
interface editor refuses for its white space.

[#209]: https://github.com/Linuxfabrik/firewallfabrik/issues/209
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
    Address,
    Firewall,
    FWObjectDatabase,
    Interface,
    Library,
)
from firewallfabrik.gui.object_tree_data import MODEL_MAP
from firewallfabrik.gui.object_tree_ops import TreeOperations

# An address the object stores, nothing binds to it.
ANY_IPV4 = '0.0.0.0'  # nosec B104


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _dialog(class_name):
    from firewallfabrik.gui import ui_loader

    ui_loader.register_custom_widgets()
    return ui_loader.CUSTOM_WIDGET_MAP[class_name]()


def _create(type_name):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        lib_id = library.id
    new_id = TreeOperations(dm).create_new_object(
        MODEL_MAP[type_name], type_name, lib_id, folder='Objects'
    )
    return dm, new_id


@pytest.mark.parametrize(
    ('type_name', 'dialog', 'expected'),
    [
        # libfwbuilder's constructors: InetAddrMask() is all zeroes,
        # Network() sets the length 32, NetworkIPv6() the length 64.
        ('IPv4', 'IPv4Dialog', {'address': ANY_IPV4, 'netmask': ANY_IPV4}),
        ('IPv6', 'IPv6Dialog', {'address': '::', 'netmask': '0'}),
        (
            'Network',
            'NetworkDialog',
            {'address': ANY_IPV4, 'netmask': '255.255.255.255'},
        ),
        ('NetworkIPv6', 'NetworkDialogIPv6', {'address': '::', 'netmask': '64'}),
    ],
)
def test_a_new_address_object_passes_its_editor(type_name, dialog, expected):
    dm, new_id = _create(type_name)
    editor = _dialog(dialog)
    with dm.session() as session:
        obj = session.get(Address, new_id)
        assert obj.inet_addr_mask == expected
        editor.load_object(obj)
        assert editor.validate() == ''


def test_a_new_address_range_passes_its_editor():
    dm, new_id = _create('AddressRange')
    editor = _dialog('AddressRangeDialog')
    with dm.session() as session:
        obj = session.get(Address, new_id)
        assert obj.start_address == {'address': ANY_IPV4}
        assert obj.end_address == {'address': ANY_IPV4}
        editor.load_object(obj)
        assert editor.validate() == ''


@pytest.mark.parametrize(
    ('type_name', 'dialog', 'address', 'netmask'),
    [
        ('Network', 'NetworkDialog', '192.0.2.0', '255.255.255.0'),
        ('NetworkIPv6', 'NetworkDialogIPv6', '2001:db8::', '32'),
    ],
)
def test_a_new_network_can_be_filled_in_one_field_at_a_time(
    type_name, dialog, address, netmask
):
    """The steps of #209: name, then address, then netmask, each one saved."""
    dm, new_id = _create(type_name)
    editor = _dialog(dialog)
    with dm.session() as session:
        editor.load_object(session.get(Address, new_id))
        for field, value in (
            (editor.obj_name, 'lan'),
            (editor.address, address),
            (editor.netmask, netmask),
        ):
            field.setText(value)
            assert editor.validate() == ''
            editor.apply_all()
        obj = session.get(Address, new_id)
        assert obj.name == 'lan'
        assert obj.inet_addr_mask == {'address': address, 'netmask': netmask}


def _firewall_with_interfaces(*names):
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
        for name in names:
            session.add(Interface(id=uuid.uuid4(), device_id=fw.id, name=name))
        lib_id, fw_id = library.id, fw.id
    return dm, lib_id, fw_id


@pytest.mark.parametrize(
    ('siblings', 'expected'),
    [
        # ObjectManipulator::findNewestInterfaceName and the interface
        # branch of makeNameUnique: the number of the prototype counts up.
        ((), 'Interface'),
        (('eth0',), 'eth1'),
        (('eth0', 'eth1'), 'eth2'),
        (('eth0', 'eth2'), 'eth1'),
        (('lo',), 'lo1'),
    ],
)
def test_a_new_interface_is_named_after_its_siblings(siblings, expected):
    dm, lib_id, fw_id = _firewall_with_interfaces(*siblings)
    new_id = TreeOperations(dm).create_new_object(
        Interface, 'Interface', lib_id, device_id=fw_id
    )
    editor = _dialog('InterfaceDialog')
    with dm.session() as session:
        obj = session.get(Interface, new_id)
        assert obj.name == expected
        editor.load_object(obj)
        assert editor.validate() == ''
