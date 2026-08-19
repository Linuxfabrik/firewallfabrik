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

"""File > Import Library, without the dialogs around it.

The workflow had never run: it built its temporary database with an
argument the constructor does not take, then called two methods that do
not exist and a third with the wrong signature.  Nothing in the suite
touched it, because everything above it is Qt (issue #150 was the first
of the four to reach a user).

It also skipped a library whose name is already taken, which meant
importing one data file into another did nothing at all - two files of
the same house both call their library "User".  Firewall Builder renames
instead (`makeNameUnique` in `ProjectPanel::loadLibrary`).

The file's own Standard library comes across the same way, under a free
name and editable.  Two data files can carry two generations of it - one
with `HTTP 80` where the other has `http` - and leaving it behind means
every rule of the imported firewalls that names one of its services loses
that service and matches every service instead.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall, Library, rule_elements

from .conftest import FIXTURES_DIR

pytest.importorskip('PySide6')

from firewallfabrik.gui.library_export import (
    _do_import_library,
    _unique_library_name,
)


def test_a_free_name_is_left_alone():
    assert _unique_library_name('User', set()) == 'User'


def test_a_taken_name_gets_the_first_free_suffix():
    assert _unique_library_name('User', {'User'}) == 'User-1'
    assert _unique_library_name('User', {'User', 'User-1'}) == 'User-2'


def _open(name):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURES_DIR / name))
    return db


def _libraries(db):
    with db.session() as session:
        return sorted(lib.name for lib in session.scalars(sqlalchemy.select(Library)))


def _firewalls(db):
    with db.session() as session:
        return sorted(fw.name for fw in session.scalars(sqlalchemy.select(Firewall)))


def test_a_library_is_imported_under_a_free_name():
    target = _open('compiler-tests.fwf')
    before = _firewalls(target)

    imported, unresolved = _do_import_library(
        target, FIXTURES_DIR / 'reject_actions.fwf'
    )

    assert imported == 2
    assert unresolved == []
    assert _libraries(target) == ['Standard', 'Standard-1', 'User', 'User-1']
    assert len(_firewalls(target)) > len(before)


def test_the_imported_standard_library_is_editable():
    """It is no longer the Standard library of anything, only a copy."""
    target = _open('compiler-tests.fwf')
    _do_import_library(target, FIXTURES_DIR / 'reject_actions.fwf')

    with target.session() as session:
        libraries = {
            lib.name: lib for lib in session.scalars(sqlalchemy.select(Library))
        }
        assert libraries['Standard'].ro is True
        assert libraries['Standard-1'].ro is False
        assert libraries['Standard-1'].services, 'and it brought its objects'


def test_the_imported_firewalls_keep_their_rules():
    target = _open('compiler-tests.fwf')
    _do_import_library(target, FIXTURES_DIR / 'reject_actions.fwf')

    with target.session() as session:
        lib = session.scalars(
            sqlalchemy.select(Library).where(Library.name == 'User-1')
        ).one()
        firewalls = [dev for dev in lib.devices if isinstance(dev, Firewall)]
        assert firewalls
        rule_ids = {
            rule.id for fw in firewalls for rs in fw.rule_sets for rule in rs.rules
        }
        assert rule_ids, 'the rules came across with the firewalls'

        rows = session.execute(
            sqlalchemy.select(rule_elements).where(
                rule_elements.c.rule_id.in_(rule_ids)
            )
        ).all()
        assert rows, 'and their rule elements still point at objects'
        assert {row.slot for row in rows} >= {'srv'}


def test_the_result_survives_a_save_and_a_reload(tmp_path):
    target = _open('compiler-tests.fwf')
    _do_import_library(target, FIXTURES_DIR / 'reject_actions.fwf')
    expected = _firewalls(target)

    out = tmp_path / 'merged.fwf'
    target.save(str(out))

    again = firewallfabrik.core.DatabaseManager()
    again.load(str(out))
    assert _firewalls(again) == expected
    assert _libraries(again) == ['Standard', 'Standard-1', 'User', 'User-1']


def test_a_target_without_a_standard_library_resolves_too():
    """The one the file brings answers for the one this tree has not got."""
    target = _open('basic_accept_deny.fwf')
    imported, unresolved = _do_import_library(
        target, FIXTURES_DIR / 'reject_actions.fwf'
    )
    assert imported == 2
    assert unresolved == []
    assert _libraries(target) == ['Standard', 'Test Objects', 'User']


def test_an_imported_firewall_compiles_to_the_same_rules(tmp_path):
    """The strongest check there is: same rules as in the file it came from."""
    from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

    def _compile(db, fw_name, wdir):
        with db.session() as session:
            fw = session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == fw_name)
            ).one()
            fw_id = str(fw.id)
        driver = CompilerDriver_ipt(db)
        wdir.mkdir(parents=True, exist_ok=True)
        driver.wdir = str(wdir)
        driver.source_dir = str(FIXTURES_DIR)
        driver.file_name_setting = f'{fw_name}.fw'
        driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
        text = pathlib.Path(driver.file_names[fw_id]).read_text(encoding='utf-8')
        return [
            line.strip()
            for line in text.splitlines()
            if '$IPTABLES' in line and ' -A ' in line
        ]

    source = _open('reject_actions.fwf')
    with source.session() as session:
        fw_name = sorted(
            fw.name for fw in session.scalars(sqlalchemy.select(Firewall))
        )[0]
    expected = _compile(source, fw_name, tmp_path / 'source')
    assert expected

    target = _open('compiler-tests.fwf')
    _do_import_library(target, FIXTURES_DIR / 'reject_actions.fwf')
    assert _compile(target, fw_name, tmp_path / 'imported') == expected
