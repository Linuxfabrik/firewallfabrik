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

"""The "Lookup Version ..." button: what it asks and what it concludes.

The answers below are what the machines printed when the lookup was run
against linked clones of the distributions, both as the templates came and
fully updated.  The one that needed more than the release: Rocky Linux 8.3
names no point release (`VERSION_ID="8"`), and RHEL 8 is placed by its
kernel build anyway, because the set element expressions arrived with
4.18.0-359.
"""

import pytest

from firewallfabrik.gui import version_lookup
from firewallfabrik.platforms import _versions

ROCKY_83 = """\
@@NFT
nftables v0.9.3 (Topsy)
@@IPT
iptables v1.8.4 (nf_tables)
@@KERNEL
4.18.0-240.22.1.el8.x86_64
@@OS
NAME="Rocky Linux"
VERSION="8.3 (Green Obsidian)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="8"
PRETTY_NAME="Rocky Linux 8"
@@END
"""


def test_the_answer_is_read_section_by_section():
    result = version_lookup.parse(ROCKY_83)
    assert result.nftables == '0.9.3'
    assert result.iptables == '1.8.4'
    assert result.iptables_backend == 'nf_tables'
    assert result.kernel == '4.18.0-240.22.1.el8.x86_64'
    assert result.distribution == 'Rocky Linux 8'


def test_rhel_8_is_placed_by_its_kernel_when_it_names_no_point_release():
    result = version_lookup.parse(ROCKY_83)
    assert result.entry('nftables') == '0.9.0'
    assert result.entry('iptables') == '1.6.2'


@pytest.mark.parametrize(
    ('release', 'os_release', 'kernel', 'expected'),
    [
        ('1.0.4', {'ID': 'rocky', 'VERSION_ID': '8.10'}, '4.18.0-553.el8_10', '0.9.1'),
        (
            '0.9.3',
            {'ID': 'rocky', 'VERSION_ID': '8.6'},
            '4.18.0-372.32.1.el8_6',
            '0.9.1',
        ),
        ('0.9.3', {'ID': 'rhel', 'VERSION_ID': '8.5'}, '4.18.0-348.el8', '0.9.0'),
        ('0.9.3', {'ID': 'almalinux', 'VERSION_ID': '8.5'}, '', '0.9.0'),
        ('0.9.8', {'ID': 'rocky', 'VERSION_ID': '9.0'}, '5.14.0-70.el9_0', '0.9.5'),
        ('1.0.4', {'ID': 'rocky', 'VERSION_ID': '9.2'}, '5.14.0-284.el9_2', '1.0.0'),
        (
            '1.0.9',
            {'ID': 'ubuntu', 'VERSION_ID': '24.04'},
            '6.8.0-142-generic',
            '1.0.9',
        ),
        ('0.9.8', {'ID': 'debian', 'VERSION_ID': '11'}, '5.10.0-28-amd64', '0.9.5'),
        ('1.0.2', {'ID': 'ubuntu', 'VERSION_ID': '22.04'}, '5.15.0-194', '1.0.0'),
        ('1.1.6', {'ID': 'fedora', 'VERSION_ID': '44'}, '7.2.7-200.fc44', '1.0.9'),
        ('', {'ID': 'ubuntu', 'VERSION_ID': '26.04'}, '7.0.0-34-generic', ''),
    ],
)
def test_the_nftables_entry(release, os_release, kernel, expected):
    assert _versions.entry_for('nftables', release, os_release, kernel) == expected


@pytest.mark.parametrize(
    ('release', 'expected'),
    [
        ('1.8.11', '1.6.2'),
        ('1.4.7', '1.4.4'),
        ('1.4.21', '1.4.20'),
        ('1.2.3', 'lt_1.2.6'),
    ],
)
def test_the_iptables_entry(release, expected):
    assert _versions.entry_for('iptables', release, {}) == expected


def test_an_incomplete_answer_is_an_error():
    with pytest.raises(version_lookup.LookupFailed):
        version_lookup.parse('@@NFT\nnftables v1.1.6\n')


def test_the_login_is_the_installers_and_needs_no_shell():
    args = version_lookup.ssh_args('192.0.2.1', 'admin', '-p 2222 -i key', 'ssh', 5)
    assert args[:3] == ['ssh', '-o', 'ConnectTimeout=5']
    assert args[3:7] == ['-p', '2222', '-i', 'key']
    assert args[7:10] == ['-l', 'admin', '192.0.2.1']
    # The remote command is one argument, and only reads.
    assert len(args) == 11
    assert 'nft --version' in args[10]
    assert 'iptables --version' in args[10]


def test_no_management_address_is_said_before_ssh_is_tried():
    with pytest.raises(version_lookup.LookupFailed, match='management address'):
        version_lookup.run('', 'root')
