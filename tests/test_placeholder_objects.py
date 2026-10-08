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

"""The "Any" and "Dummy" placeholders are objects, not names.

Firewall Builder recognises its placeholders by their fixed ids.  The
compiler here once recognised them by name and dropped every object called
"Any" or "Dummy" from a rule - a user host of that name included, which
turned "from this host" into "from anywhere".  And it dropped the real
"Dummy" placeholder the same way, although that one stands for an element
the administrator still has to fill in: Firewall Builder leaves such a rule
out with a warning (fwbuilder5 Compiler.cpp:744).
"""

import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.compiler._comp_rule import CompRule, load_rules
from firewallfabrik.compiler.processors._generic import Begin
from firewallfabrik.core.objects import (
    Address,
    Host,
    Interface,
    Interval,
    Library,
    PolicyAction,
    Rule,
    RuleSet,
    Service,
    placeholder_kind,
    rule_elements,
)

from .conftest import FIXTURES_DIR


def _load():
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / 'compiler-tests.fwf'))
    return db


def _standard(session, cls, name):
    return next(
        obj
        for obj in session.scalars(sqlalchemy.select(cls).where(cls.name == name))
        if placeholder_kind(obj) == name
    )


def test_the_standard_library_placeholders_are_recognised():
    db = _load()
    with db.session() as session:
        for cls in (Address, Service, Interval):
            assert placeholder_kind(_standard(session, cls, 'Any')) == 'Any'
        for cls in (Address, Service, Interface):
            assert placeholder_kind(_standard(session, cls, 'Dummy')) == 'Dummy'


def _rule_naming_a_host(session):
    """Return (rule, host) for a policy rule whose source names a host."""
    for row in session.execute(
        sqlalchemy.select(rule_elements).where(rule_elements.c.slot == 'src')
    ):
        host = session.get(Host, row.target_id)
        rule = session.get(Rule, row.rule_id)
        if host is not None and rule.type == 'PolicyRule':
            return rule, host
    raise AssertionError('the fixture names no host in a source element')


def test_a_user_object_called_any_or_dummy_stays_in_the_rule():
    db = _load()
    for name in ('Any', 'Dummy'):
        with db.session() as session:
            rule, host = _rule_naming_a_host(session)
            host.name = name
            session.flush()
            assert placeholder_kind(host) == ''
            rule_set = session.get(RuleSet, rule.rule_set_id)
            comp = next(r for r in load_rules(session, rule_set) if r.id == rule.id)
            assert host in comp.src, (
                f'a host called "{name}" is a host, and dropping it turns the '
                'source into "any"'
            )
            assert comp.has_dummy is False


def test_the_dummy_placeholder_marks_the_rule():
    db = _load()
    with db.session() as session:
        rule, _host = _rule_naming_a_host(session)
        dummy = _standard(session, Address, 'Dummy')
        session.execute(
            rule_elements.insert().values(
                rule_id=rule.id, slot='dst', target_id=dummy.id, position=99
            )
        )
        session.flush()
        rule_set = session.get(RuleSet, rule.rule_set_id)
        comp = next(r for r in load_rules(session, rule_set) if r.id == rule.id)
        assert comp.has_dummy is True
        assert dummy not in comp.dst


def test_the_any_placeholder_is_an_empty_element():
    db = _load()
    with db.session() as session:
        rule, _host = _rule_naming_a_host(session)
        session.execute(
            rule_elements.delete().where(
                rule_elements.c.rule_id == rule.id, rule_elements.c.slot == 'dst'
            )
        )
        any_net = _standard(session, Address, 'Any')
        session.execute(
            rule_elements.insert().values(
                rule_id=rule.id, slot='dst', target_id=any_net.id, position=0
            )
        )
        session.flush()
        rule_set = session.get(RuleSet, rule.rule_set_id)
        comp = next(r for r in load_rules(session, rule_set) if r.id == rule.id)
        assert comp.dst == []
        assert comp.has_dummy is False


class _Recorder:
    def __init__(self, rules):
        self.rules = rules
        self.warnings = []

    def warning(self, rule, msg):
        self.warnings.append((rule.label, msg))


def _comp_rule(label, has_dummy):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label=label,
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
        has_dummy=has_dummy,
    )


def test_begin_leaves_a_rule_with_a_dummy_out_and_says_so():
    compiler = _Recorder([_comp_rule('0', True), _comp_rule('1', False)])
    begin = Begin()
    begin.compiler = compiler

    assert begin.process_next() is True
    assert [r.label for r in begin.tmp_queue] == ['1']
    assert compiler.warnings == [('0', 'Rule contains dummy object and is not parsed.')]


def test_a_library_called_otherwise_holds_no_placeholders():
    db = _load()
    with db.session() as session:
        any_net = _standard(session, Address, 'Any')
        user_lib = session.scalars(
            sqlalchemy.select(Library).where(Library.name != 'Standard')
        ).first()
        any_net.library = user_lib
        session.flush()
        assert placeholder_kind(any_net) == ''


def test_an_imported_library_names_this_files_placeholders():
    """File > Import Library copies the other Standard library along.

    Its rules name that copy's "Any", which in Firewall Builder would be
    the very same object - the placeholders have one fixed id in every
    file.  After the import they name this file's own.
    """
    pytest.importorskip('PySide6')
    from firewallfabrik.gui.library_export import _do_import_library

    db = _load()
    _do_import_library(db, FIXTURES_DIR / 'reject_actions.fwf')
    with db.session() as session:
        referenced = {
            row.target_id for row in session.execute(sqlalchemy.select(rule_elements))
        }
        for cls in (Address, Service, Interval, Interface):
            for obj in session.scalars(
                sqlalchemy.select(cls).where(cls.name.in_(('Any', 'Dummy')))
            ):
                if obj.id in referenced:
                    assert placeholder_kind(obj), (
                        f'a rule names the "{obj.name}" of {obj.library.name}'
                    )
