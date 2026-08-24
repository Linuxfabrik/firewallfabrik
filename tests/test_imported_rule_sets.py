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

"""A Branch rule whose target belongs to another firewall object.

Firewall Builder compiles that rule set into the script of the firewall
that jumps to it (``CompilerDriver::findImportedRuleSets``,
CompilerDriver.cpp:688, called from ``CompilerDriver_ipt_run.cpp:238``
for the policies and ``:240`` for the NAT rule sets).  Without it the
jump names a chain nothing ever fills: iptables takes both the ``-N``
and the ``-j``, the packet returns, the rule does nothing and the
activation reports success.  Issue #156.

``firewall51`` of the reference corpus is Firewall Builder's own fixture
for it - five Branch rules into the rule sets of ``firewall-base-rulesets``
- and the gold has the chains *and their rules*
(``firewall51.fw.orig:333``).

The second thing the C++ does is easy to miss: it clears the ``top`` flag
of every imported rule set, and the comment above the function says why.
A top rule set is compiled into the built-in chains, so there would be no
chain for the branching rule to name.  ``firewall61-1.2.6`` imports
``fw61-Policy``, which *is* marked top on the firewall that owns it, and
the gold compiles it as the named chain ``fw61-Policy``
(``firewall61-1.2.6.fw.orig:339``).
"""

import pathlib

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager, objects
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = 'tests/fixtures/objects-for-regression-tests.fwb'


@pytest.fixture(scope='module')
def database():
    """One load for every case: the ids are new on each one."""
    dm = DatabaseManager('sqlite://')
    dm.load(FIXTURE)
    return dm


def _compile(dm, driver_class, firewall_name, tmp_path):
    with dm.session() as session:
        firewall = session.scalars(
            sqlalchemy.select(objects.Firewall).where(
                objects.Firewall.name == firewall_name
            ),
        ).one()
        firewall_id = str(firewall.id)
    driver = driver_class(dm)
    driver.verbose = False
    driver.wdir = str(tmp_path)
    driver.source_dir = 'tests/fixtures'
    driver.file_name_setting = f'{firewall_name}.fw'
    driver.run(cluster_id='', fw_id=firewall_id, single_rule_id='')
    script = pathlib.Path(driver.file_names[firewall_id]).read_text()
    return driver, script


@pytest.mark.parametrize('driver_class', (CompilerDriver_ipt, CompilerDriver_nft))
def test_the_branch_into_another_firewalls_rule_set_is_compiled(
    database, driver_class, tmp_path
):
    driver, script = _compile(database, driver_class, 'firewall51', tmp_path)
    assert driver.all_errors == []
    # The chain the rule jumps into now carries the rules of the rule set
    # it names, not just its own declaration.
    assert 'mail_server_inbound' in script
    assert 'Rule mail_server_inbound 0 (global)' in script
    assert 'Rule base-ruleset 0 (global)' in script


@pytest.mark.parametrize('driver_class', (CompilerDriver_ipt, CompilerDriver_nft))
def test_an_imported_rule_set_is_never_the_top_one_here(
    database, driver_class, tmp_path
):
    """It would go into the built-in chains and leave the jump nowhere to go."""
    driver, script = _compile(database, driver_class, 'firewall61-1.2.6', tmp_path)
    assert 'Rule fw61-Policy 0 (global)' in script
    assert not any('fw61-Policy' in message for message in driver.all_errors)


def test_a_branch_loop_is_reported(database, tmp_path):
    """firewall82* is Firewall Builder's own recursive-branching fixture."""
    driver, _ = _compile(database, CompilerDriver_ipt, 'firewall82_A', tmp_path)
    assert any('creating a loop' in message for message in driver.all_warnings)


def test_the_firewalls_own_top_rule_set_is_still_refused(database, tmp_path):
    """The other shape stays reported: its chains are the built-in ones.

    Firewall Builder emits the same empty chain there, which is why the
    reference output never showed it.
    """
    driver, _ = _compile(database, CompilerDriver_nft, 'firewall82', tmp_path)
    assert any('branches to "Policy"' in message for message in driver.all_errors), (
        driver.all_errors
    )


def test_a_nat_branch_is_imported_too(database, tmp_path):
    """The C++ calls the same pass a second time for the NAT rule sets.

    firewall81's `NAT_2` branches into `NAT_1` of firewall80.
    """
    _, script = _compile(database, CompilerDriver_nft, 'firewall81', tmp_path)
    assert 'Rule NAT_1 0 (NAT)' in script
