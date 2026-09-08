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

"""What number a rule of a `.fwf` file gets when it names none.

The writer omits a position of 0 the way it omits every other default, so
the first rule of every rule set it writes carries none and the rest carry
theirs.  A hand-written file - the shape the developer guide asks for when
a fixture is added, and the only way to edit a data file outside the
editor until `fwf-edit` lands (#146) - usually names no position at all,
and every rule then had 0: the rules compiled in the order they were
written, but each was labelled "0 (global)", every message named the wrong
rule and the shadowing pass reported a rule as shadowing itself.

The `.fwb` reader needs none of this: `position` is `#REQUIRED` on every
rule element of Firewall Builder's own DTD
(libfwbuilder/etc/fwbuilder.dtd.in) and all 1325 rules of the regression
suite carry one.
"""

from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall, PolicyRule, RuleSet

DATA_FILE = """\
name: 'Test: rule positions'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'Firewall'
        name: 'fw-test'
        data:
          platform: 'iptables'
          host_OS: 'linux24'
        interfaces:
          - name: 'eth0'
            data:
              label: 'outside'
            addresses:
              - type: 'IPv4'
                name: 'eth0-addr'
                inet_addr_mask:
                  address: '192.0.2.1'
                  netmask: '24'
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
            top: true
            rules:
{rules}
"""

WITHOUT_POSITIONS = """\
              - type: 'PolicyRule'
                action: 'Accept'
              - type: 'PolicyRule'
                action: 'Deny'
              - type: 'PolicyRule'
                action: 'Reject'
"""

WITH_POSITIONS = """\
              - type: 'PolicyRule'
                action: 'Accept'
              - type: 'PolicyRule'
                position: 4
                action: 'Deny'
              - type: 'PolicyRule'
                position: 9
                action: 'Reject'
"""


def _positions(tmp_path: Path, rules: str) -> list[int]:
    data_file = tmp_path / 'positions.fwf'
    data_file.write_text(DATA_FILE.format(rules=rules))
    db = DatabaseManager()
    db.load(str(data_file))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test'),
        ).scalar_one()
        rule_set = session.execute(
            sqlalchemy.select(RuleSet).where(RuleSet.device_id == fw.id),
        ).scalar_one()
        return [
            rule.position
            for rule in session.execute(
                sqlalchemy.select(PolicyRule)
                .where(PolicyRule.rule_set_id == rule_set.id)
                .order_by(PolicyRule.id),
            )
            .scalars()
            .all()
        ]


def test_a_rule_that_names_no_position_takes_its_place_in_the_file(tmp_path):
    assert sorted(_positions(tmp_path, WITHOUT_POSITIONS)) == [0, 1, 2]


def test_a_position_that_is_written_is_kept(tmp_path):
    """A file the writer produced omits only the leading zero."""
    assert sorted(_positions(tmp_path, WITH_POSITIONS)) == [0, 4, 9]


@pytest.mark.parametrize('rules', [WITHOUT_POSITIONS, WITH_POSITIONS])
def test_no_two_rules_of_one_set_share_a_position(tmp_path, rules):
    positions = _positions(tmp_path, rules)
    assert len(set(positions)) == len(positions), positions
