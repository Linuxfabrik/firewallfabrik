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

"""The icon names the editors ask for exist in the resource bundle.

A `QIcon` for an alias the bundle does not carry is empty and raises
nothing, so the member list of a cluster group showed no icons at all
until somebody looked.  Firewall Builder names three variants per type in
its `MainRes.qrc`: `icon-tree` (16 px), `icon-ref` (25 px, for lists of
references) and `icon-big` (64 px, for the editor header).
"""

import re
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parent.parent / 'src' / 'firewallfabrik' / 'gui' / 'ui'
ALIASES = set(
    re.findall(
        r'alias="Icons/([^"]+)"', (UI / 'MainRes.qrc').read_text(encoding='utf-8')
    )
)

# Types an object list or a group member list can show.
REFERENCED_TYPES = [
    'AddressRange',
    'AddressTable',
    'AttachedNetworks',
    'Cluster',
    'CustomService',
    'DNSName',
    'DynamicGroup',
    'FailoverClusterGroup',
    'Firewall',
    'Host',
    'ICMP6Service',
    'ICMPService',
    'IPService',
    'IPv4',
    'IPv6',
    'Interface',
    'Interval',
    'IntervalGroup',
    'Library',
    'Network',
    'NetworkIPv6',
    'ObjectGroup',
    'PhysAddress',
    'ServiceGroup',
    'StateSyncClusterGroup',
    'TCPService',
    'TagService',
    'UDPService',
    'UserService',
]

# Types that have an editor panel, whose header shows the big icon.
EDITOR_TYPES = [*REFERENCED_TYPES, 'NAT', 'Policy', 'Routing']


def test_every_file_of_the_bundle_exists():
    qrc = (UI / 'MainRes.qrc').read_text(encoding='utf-8')
    missing = [
        path for path in re.findall(r'>(Icons/[^<]+)<', qrc) if not (UI / path).exists()
    ]
    assert missing == []


@pytest.mark.parametrize('kind', ['icon-ref', 'icon-tree'])
def test_referenced_types_have_the_icon(kind):
    assert [t for t in REFERENCED_TYPES if f'{t}/{kind}' not in ALIASES] == []


def test_editor_types_have_a_big_icon():
    assert [t for t in EDITOR_TYPES if f'{t}/icon-big' not in ALIASES] == []
