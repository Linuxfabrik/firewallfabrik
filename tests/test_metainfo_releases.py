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

"""The AppStream metainfo lists the same releases as the CHANGELOG.

Software centers show the <releases> block as the version history, so a
release that is missing there looks like FirewallFabrik was never updated.
Pre-releases (rc, beta) stay out of the metainfo.
"""

import pathlib
import re

import defusedxml.ElementTree

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / 'CHANGELOG.md'
METAINFO = REPO_ROOT / 'assets' / 'ch.linuxfabrik.firewallfabrik.metainfo.xml'


def _changelog_releases():
    pattern = re.compile(r'^## \[v(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$')
    releases = []
    for line in CHANGELOG.read_text().splitlines():
        match = pattern.match(line)
        if match:
            releases.append((match.group(1), match.group(2)))
    return releases


def _metainfo_releases():
    root = defusedxml.ElementTree.parse(METAINFO).getroot()
    return [
        (release.get('version'), release.get('date'))
        for release in root.iterfind('releases/release')
    ]


def test_metainfo_lists_every_changelog_release():
    assert _metainfo_releases() == _changelog_releases()
