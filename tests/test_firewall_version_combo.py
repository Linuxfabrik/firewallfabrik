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

"""The firewall panel offers the releases its platform can be compiled for.

Both compilers gate matches and targets on the release the firewall names
- the extrapositioned negation from 1.4.3, `-m conntrack` from 1.4.4,
`meta hour` from nftables 0.9.3, `snat prefix to` from 0.9.5 - and a
release that is too old refuses the command or, on nftables, the whole
ruleset.  The combo was empty, so nothing but a `.fwb` import could put a
value there and a firewall created here always compiled for the newest.

Firewall Builder fills the same combo from a hard-coded list per platform
(`getVersionsForPlatform`, libgui/platforms.cpp:418), and stores the value
while it shows the label: "1.2.5 or earlier" is stored as `lt_1.2.6`.
"""

import os

import pytest

pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from firewallfabrik.gui.platform_settings import (  # noqa: E402
    PLATFORM_VERSIONS,
    get_versions_for_platform,
)


@pytest.fixture(scope='module')
def panel():
    """The real editor panel, reached the way the loader registers it."""
    from PySide6.QtWidgets import QApplication

    from firewallfabrik.gui import ui_loader

    QApplication.instance() or QApplication([])
    return ui_loader.CUSTOM_WIDGET_MAP['FirewallDialog']()


def _fill(panel, platform, stored, keep_unlisted=True):
    panel.platform.clear()
    panel.platform.addItem(platform)
    panel.platform.setCurrentIndex(0)
    panel._fill_versions(stored, keep_unlisted=keep_unlisted)
    return panel


def test_every_platform_offers_the_any_entry_first():
    """The empty value is what both compilers read as "the newest"."""
    for versions in PLATFORM_VERSIONS.values():
        assert versions[0][0] == ''


def test_the_iptables_list_is_the_one_firewall_builder_offers():
    values = [value for value, _label in get_versions_for_platform('iptables')]
    assert values == [
        '',
        'lt_1.2.6',
        'ge_1.2.6',
        '1.2.9',
        '1.3.0',
        '1.4.0',
        '1.4.1.1',
        '1.4.3',
        '1.4.4',
        '1.4.11',
        '1.4.20',
    ]


def test_the_nftables_list_names_the_releases_the_output_changes_at():
    values = [value for value, _label in get_versions_for_platform('nftables')]
    assert '0.9.3' in values  # meta hour / meta day / meta time
    assert '0.9.5' in values  # snat prefix to / dnat prefix to


def test_a_platform_without_a_list_offers_nothing():
    assert get_versions_for_platform('pf') == []


def test_the_combo_shows_the_label_and_carries_the_value(panel):
    _fill(panel, 'iptables', 'lt_1.2.6')
    assert panel.version.currentText() == '1.2.5 or earlier'
    assert panel.version.currentData() == 'lt_1.2.6'


def test_a_release_the_list_does_not_offer_is_kept(panel):
    """A data file written elsewhere may name any release; showing the
    object the way it is beats editing it for looking at it."""
    _fill(panel, 'iptables', '1.4.7')
    assert panel.version.currentData() == '1.4.7'
    assert panel.version.currentText() == '1.4.7'


def test_switching_the_platform_does_not_carry_the_release_over(panel):
    """An iptables release means nothing to nftables."""
    _fill(panel, 'nftables', '1.4.3', keep_unlisted=False)
    assert panel.version.currentData() == ''


def test_the_nftables_list_replaces_the_iptables_one(panel):
    _fill(panel, 'nftables', '0.9.5')
    assert panel.version.currentData() == '0.9.5'
    values = [panel.version.itemData(i) for i in range(panel.version.count())]
    assert 'lt_1.2.6' not in values
