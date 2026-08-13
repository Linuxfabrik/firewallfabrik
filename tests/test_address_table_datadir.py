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

"""Which directory an address table read on the firewall is looked for in.

``%DATADIR%`` in the file name of an address table stands for the
directory the data files live in.  Which directory that is depends on who
opens the file: the compiler resolves a compile-time table against its own
source directory, while a run-time table is opened by the generated script
on the firewall and belongs to the firewall's own "Data directory"
setting.  fwbuilder splits it the same way (AddressTable::getFilename).
"""

from firewallfabrik.core.objects import AddressTable, get_address_table_source


class _Firewall:
    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir

    def get_option(self, key, default=None):
        return self._data_dir if key == 'linux24_data_dir' else ''


def _table(filename: str) -> AddressTable:
    at = AddressTable()
    at.name = 'blocked'
    at.data = {'filename': filename, 'run_time': True}
    return at


def test_the_token_is_replaced_by_the_firewalls_data_directory():
    source = get_address_table_source(
        _table('%DATADIR%/blocked.txt'), _Firewall('/etc/fw')
    )
    assert source == '/etc/fw/blocked.txt'


def test_a_trailing_slash_does_not_double_up():
    source = get_address_table_source(
        _table('%DATADIR%/blocked.txt'), _Firewall('/etc/fw/')
    )
    assert source == '/etc/fw/blocked.txt'


def test_a_name_without_the_token_is_used_as_it_stands():
    source = get_address_table_source(
        _table('/var/lib/fw/blocked.txt'), _Firewall('/etc/fw')
    )
    assert source == '/var/lib/fw/blocked.txt'


def test_an_unset_data_directory_leaves_the_token_alone():
    """Better a name the administrator recognises than a path built from
    nothing, which would silently become an absolute /blocked.txt."""
    source = get_address_table_source(_table('%DATADIR%/blocked.txt'), _Firewall(''))
    assert source == '%DATADIR%/blocked.txt'


def test_without_a_firewall_the_token_is_left_alone():
    source = get_address_table_source(_table('%DATADIR%/blocked.txt'))
    assert source == '%DATADIR%/blocked.txt'
