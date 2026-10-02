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


_FILE = """\
name: 'top flags'
libraries:
  - name: 'User'
    children:
      - type: 'Firewall'
        name: 'old'
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
            ipv4: true
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
          - type: 'Policy'
            name: 'mail_in'
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
          - type: 'NAT'
            name: 'NAT'
            rules:
              - type: 'NATRule'
          - type: 'Routing'
            name: 'Routing'
      - type: 'Firewall'
        name: 'new'
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
          - type: 'NAT'
            name: 'NAT'
            top: true
"""


def _top_flags(tmp_path):
    path = tmp_path / 'top.fwf'
    path.write_text(_FILE)
    db = DatabaseManager()
    db.load(path)
    with db.session() as session:
        return {
            (fw.name, rs.name): rs.top
            for fw in session.query(Firewall)
            for rs in fw.rule_sets
        }


def test_a_data_file_from_before_the_flag_gets_its_top_rule_sets(tmp_path):
    """FirewallFabrik 1.x wrote no "top"; 2.0 compiled such a file to nothing.

    The rule sets named after their type are the top ones, the way Firewall
    Builder upgraded its files when it introduced the flag.
    """
    flags = _top_flags(tmp_path)
    assert flags[('old', 'Policy')] is True
    assert flags[('old', 'NAT')] is True
    assert flags[('old', 'mail_in')] is False
    # An empty one compiles the same either way, and a Firewall Builder
    # cluster member keeps its own empty ones out of the top on purpose.
    assert flags[('old', 'Routing')] is False


def test_a_data_file_that_has_the_flag_is_read_as_it_says(tmp_path):
    """One top rule set shows the file knows the flag; the others stay."""
    flags = _top_flags(tmp_path)
    assert flags[('new', 'Policy')] is False
    assert flags[('new', 'NAT')] is True
