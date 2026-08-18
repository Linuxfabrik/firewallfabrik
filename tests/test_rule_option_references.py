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

"""A rule option that names another object has to survive being saved.

Object ids are assigned per load - a `.fwb` import calls `uuid.uuid4()` for
every object it reads, and so does the YAML reader - so an id is worth
nothing in a data file.  Every reference the format carries is therefore a
tree path (`Library:User/ServiceGroup:Services/TagService:tag16`), which is
what the rule elements use.

`tagobject_id` is the one rule *option* that is a reference, and the writer
wrote it out as the raw UUID of the run that produced the file.  So saving
a policy and opening it again left every tagging rule pointing at nothing:
the compilers report "tagging rule has no Tag Service to take the mark
from" and leave the rule out, which is every packet mark of the policy
gone, and with it every routing decision and traffic class keyed on one.
"""

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import PolicyRule, TagService
from tests.conftest import FIXTURES_DIR


def _tagging_rules(db):
    with db.session() as session:
        tag_ids = {
            str(tag.id)
            for tag in session.execute(sqlalchemy.select(TagService)).scalars()
        }
        rules = [
            rule
            for rule in session.execute(sqlalchemy.select(PolicyRule)).scalars()
            if (rule.options or {}).get('tagobject_id')
        ]
        return [(rule.options['tagobject_id'] in tag_ids) for rule in rules]


def test_a_tagging_rule_still_names_its_tag_service_after_a_save(tmp_path):
    source = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

    original = firewallfabrik.core.DatabaseManager()
    original.load(str(source))
    before = _tagging_rules(original)
    # Guard the premise: a fixture without tagging rules proves nothing.
    assert before and all(before)

    saved = tmp_path / 'round-trip.fwf'
    original.save(str(saved))
    reloaded = firewallfabrik.core.DatabaseManager()
    reloaded.load(str(saved))

    after = _tagging_rules(reloaded)

    assert len(after) == len(before)
    assert all(after)


def test_the_reference_is_written_as_a_tree_path(tmp_path):
    """A UUID in the file would be the id of the run that wrote it."""
    source = FIXTURES_DIR / 'objects-for-regression-tests.fwb'
    saved = tmp_path / 'round-trip.fwf'

    db = firewallfabrik.core.DatabaseManager()
    db.load(str(source))
    db.save(str(saved))

    references = [
        line.split(':', 1)[1].strip().strip("'")
        for line in saved.read_text().splitlines()
        if 'tagobject_id:' in line
    ]
    # A rule that names no Tag Service stores an empty string; only a
    # reference that is there has to be a path.
    named = [ref for ref in references if ref]

    assert named
    assert all(ref.startswith('Library:') for ref in named)


def test_a_file_written_before_this_keeps_working_as_it_did(tmp_path):
    """Its raw UUID resolves to nothing, which is what it did before too."""
    saved = tmp_path / 'legacy.fwf'
    source = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

    db = firewallfabrik.core.DatabaseManager()
    db.load(str(source))
    db.save(str(saved))
    saved.write_text(
        saved.read_text().replace(
            "tagobject_id: 'Library:", "tagobject_id: 'not-a-path-Library:"
        )
    )

    reloaded = firewallfabrik.core.DatabaseManager()
    reloaded.load(str(saved))

    assert not any(_tagging_rules(reloaded))
