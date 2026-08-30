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

"""A negated time nftables cannot invert is said with a chain instead.

nftables writes a window of the day as ``meta hour`` or ``meta time`` and
a set of weekdays as ``meta day``, and inverts either with ``!=``.  An
interval naming both reaches the rule as two conditions, and the opposite
of "in those hours *and* on those days" is "outside those hours *or* on
another day" - a disjunction one nftables rule cannot hold.

Such a rule is expanded into the jump / return / action chain
``PolicyCompiler_ipt::TimeNegation`` builds for every negated interval,
which says the same thing by excluding the window instead of negating it.
Before that it was reported and left out, so a rule the iptables compiler
had always compiled was simply missing from the ruleset.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._interval_helpers import interval_is_a_conjunction
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = (
    pathlib.Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
)


@pytest.fixture(scope='module')
def tree():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    return dm


def _compile(tree, name, tmp_path):
    with tree.session() as session:
        fw_id = str(
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == name),
            )
            .one()
            .id
        )
    driver = CompilerDriver_nft(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw.fw').read_text(), driver


def test_a_negated_hour_and_weekday_is_compiled(tree, tmp_path):
    """firewall31 rules 4 and 5 negate a weekday-only time and log.

    The reference writes ``-m time ... --days Sat,Sun -j RETURN`` for
    rule 4 and one RETURN per weekday for rule 5 (`firewall31.fw.orig`).
    """
    script, driver = _compile(tree, 'firewall31', tmp_path)

    assert not [error for error in driver.all_errors if 'negated time' in error]

    # One chain per rule, holding the exclusion and then the action.
    assert 'meta day { "Sunday", "Saturday" } counter return' in script
    assert 'meta day { "Saturday" } counter return' in script
    assert 'meta day { "Sunday" } counter return' in script

    # The log belongs to the rule that carries the action; the jump and
    # the return must not repeat it.
    logged = [line for line in script.splitlines() if 'RULE 4 -- ACCEPT' in line]
    assert logged, 'the action rule lost its log'
    for line in logged:
        assert 'return' not in line
        assert 'jump ' not in line


def test_the_conjunction_test_matches_what_the_print_rule_writes():
    """The processor and the printer have to agree on "two conditions"."""
    all_week = '0,1,2,3,4,5,6'
    # Hours only: one condition.
    assert not interval_is_a_conjunction(
        {'from_time': '09:00', 'to_time': '17:00', 'days_of_week': all_week}
    )
    # A window whose two ends meet leaves nothing to exclude, so
    # `_print_hour_range` writes nothing and the weekday stands alone.
    assert not interval_is_a_conjunction(
        {'from_time': '00:00', 'to_time': '00:00', 'days_of_week': '6'}
    )
    # 00:00-23:59 is the spelling Firewall Builder writes for "all day",
    # and both back ends match it as a window, so it is a condition of its
    # own beside the weekday.
    assert interval_is_a_conjunction(
        {'from_time': '00:00', 'to_time': '23:59', 'days_of_week': '6'}
    )
    # Both: two.
    assert interval_is_a_conjunction(
        {'from_time': '09:00', 'to_time': '17:00', 'days_of_week': '1,2,3,4,5'}
    )
