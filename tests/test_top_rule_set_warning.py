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

"""A firewall whose rule sets are all branches installs no rules at all.

Only the top rule set goes into the built-in chains; every other one
becomes a chain that runs where a rule with the Branch action jumps to
it.  So a firewall whose only Policy rule set is not marked "top"
compiles into a chain nothing reaches - no filtering, and a compile that
reports success.  fwbuilder says "Missing top level Policy ruleset"
(``CompilerDriver::commonChecks2``); this said nothing.
"""

import uuid

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import NAT, Firewall, Policy
from firewallfabrik.driver._compiler_driver import CompilerDriver


def _driver():
    return CompilerDriver(DatabaseManager())


def _rule_set(cls, name, top):
    rs = cls()
    rs.id = uuid.uuid4()
    rs.name = name
    rs.top = top
    return rs


def _firewall():
    fw = Firewall()
    fw.id = uuid.uuid4()
    fw.name = 'fw'
    return fw


def test_a_firewall_with_only_branch_rule_sets_is_reported():
    driver = _driver()
    driver.warn_about_missing_top_rule_sets(
        _firewall(),
        [_rule_set(Policy, 'Policy', False), _rule_set(Policy, 'Policy_ipv6', False)],
        [],
    )

    assert len(driver.all_warnings) == 1
    assert 'Policy' in driver.all_warnings[0]
    assert 'Policy_ipv6' in driver.all_warnings[0]


def test_a_top_rule_set_next_to_branches_is_fine():
    driver = _driver()
    driver.warn_about_missing_top_rule_sets(
        _firewall(),
        [_rule_set(Policy, 'Policy', True), _rule_set(Policy, 'mail_in', False)],
        [],
    )

    assert driver.all_warnings == []


def test_the_nat_rule_sets_are_asked_separately():
    driver = _driver()
    driver.warn_about_missing_top_rule_sets(
        _firewall(),
        [_rule_set(Policy, 'Policy', True)],
        [_rule_set(NAT, 'NAT_1', False)],
    )

    assert len(driver.all_warnings) == 1
    assert 'NAT' in driver.all_warnings[0]


def test_a_firewall_without_rule_sets_is_left_alone():
    """Nothing was configured, so there is nothing to say about it."""
    driver = _driver()
    driver.warn_about_missing_top_rule_sets(_firewall(), [], [])

    assert driver.all_warnings == []
