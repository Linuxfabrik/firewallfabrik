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

"""One packet, one count, however many lines a rule becomes.

An accounting rule counts into a named counter, which is the whole reason
it exists, and a firewall that caps how often a rule logs turns a logged
rule into a rate-limited log line and a line carrying the verdict.  A
packet crosses both, so a counter left on each counts it twice - and the
log line is rate-limited on top of that, so the total is "every packet"
plus "up to the log rate", which is neither number anybody asked for.

firewall17 is the fixture with accounting rules; its own log rate is 0,
which is why nothing caught this until the option was forced.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = (
    pathlib.Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
)


@pytest.fixture
def ruleset(tmp_path):
    """firewall17 compiled with the firewall's log rate limit turned on."""
    tree = firewallfabrik.core.DatabaseManager('sqlite://')
    tree.load(str(FIXTURE))
    with tree.session() as session:
        firewall = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == 'firewall17'),
        ).one()
        firewall.options = {
            **(firewall.options or {}),
            'limit_value': 5,
            'limit_suffix': '/second',
        }
        fw_id = str(firewall.id)
    driver = CompilerDriver_nft(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw.fw').read_text()


def test_a_logged_accounting_rule_counts_each_packet_once(ruleset):
    """The counter sits on the line carrying the verdict, not on the log line."""
    logged = [
        line.strip()
        for line in ruleset.splitlines()
        if 'counter name' in line and ' log ' in f' {line} '
    ]
    assert logged == [], logged


def test_the_accounting_rules_still_count(ruleset):
    """Every counter the ruleset declares is named by a rule."""
    declared = {
        line.strip().split()[1]
        for line in ruleset.splitlines()
        if line.strip().startswith('counter ') and line.strip().endswith('{')
    }
    assert declared
    for name in declared:
        assert f'counter name "{name}"' in ruleset, name


def test_the_log_line_is_still_written(ruleset):
    """Splitting the rule is what the log rate limit is for."""
    assert 'limit rate 5/second' in ruleset
    assert 'ACCOUNTING on interface' in ruleset
