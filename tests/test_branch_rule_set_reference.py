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

"""What a Branch rule has to remember about the rule set it jumps into.

Its name does not identify it.  Almost every firewall object owns a rule
set called "Policy", and a branch may point at a rule set of *another*
firewall or cluster - which is the case Firewall Builder compiles into
the script (``CompilerDriver::findImportedRuleSets``) and the one issue
#156 reports.  Firewall Builder resolves the branch by id
(``PolicyRule::getBranch()``), so the port has to keep the object, not
the string.

The reference has to survive the data file as well.  Object ids are
assigned per load - both readers call ``uuid.uuid4()`` for every object -
so a raw id in a `.fwf` is worth nothing the moment the file is read
back; it goes out as a tree path, like every rule element and like
``tagobject_id`` before it.
"""

import uuid

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager, objects
from firewallfabrik.core._util import OPTION_REF_KEYS

FIXTURE = 'tests/fixtures/objects-for-regression-tests.fwb'


def _branch_targets(session):
    """Return {(firewall, rule set, position): (target firewall, target set)}."""
    found = {}
    for rule in session.scalars(sqlalchemy.select(objects.PolicyRule)).all():
        ref = (rule.options or {}).get('branch_id')
        if not ref:
            continue
        target = session.get(objects.RuleSet, uuid.UUID(str(ref)))
        assert target is not None, f'branch_id does not resolve: {ref}'
        key = (rule.rule_set.device.name, rule.rule_set.name, rule.position)
        found[key] = (target.device.name, target.name)
    return found


def test_the_branch_key_is_a_reference_like_the_tag_service_one():
    assert 'branch_id' in OPTION_REF_KEYS
    assert 'tagobject_id' in OPTION_REF_KEYS


def test_the_xml_reader_resolves_the_branch_to_its_rule_set():
    dm = DatabaseManager('sqlite://')
    dm.load(FIXTURE)
    with dm.session() as session:
        targets = _branch_targets(session)
    assert targets, 'the reference corpus has branch rules'
    # firewall51 is Firewall Builder's own fixture for a branch into the
    # rule sets of another firewall object.
    assert targets[('firewall51', 'Policy', 4)] == (
        'firewall-base-rulesets',
        'base-ruleset',
    )


def test_the_name_alone_would_not_have_been_enough():
    """Two firewalls of the corpus branch into a rule set called "Policy"."""
    dm = DatabaseManager('sqlite://')
    dm.load(FIXTURE)
    with dm.session() as session:
        by_name = {}
        for rs in session.scalars(sqlalchemy.select(objects.Policy)).all():
            by_name.setdefault(rs.name, set()).add(rs.device.name)
    assert len(by_name.get('Policy', ())) > 1


@pytest.mark.parametrize('key', ('firewall51', 'firewall82_A', 'firewall33-1'))
def test_the_reference_survives_a_save_and_a_reload(tmp_path, key):
    """The ids are new on every load, so the file has to carry a path."""
    dm = DatabaseManager('sqlite://')
    dm.load(FIXTURE)
    with dm.session() as session:
        before = _branch_targets(session)

    out = tmp_path / 'roundtrip.fwf'
    dm.save(str(out))

    dm2 = DatabaseManager('sqlite://')
    dm2.load(str(out))
    with dm2.session() as session:
        after = _branch_targets(session)

    mine_before = {k: v for k, v in before.items() if k[0] == key}
    mine_after = {k: v for k, v in after.items() if k[0] == key}
    assert mine_before
    assert mine_after == mine_before
