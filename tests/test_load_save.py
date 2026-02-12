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

"""Load-save tests: load a .fwf file, save it, and verify the output is identical."""

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Host, Library, Rule, RuleSet, Service

from .conftest import FIXTURES_DIR

_FWF_FILES = sorted(FIXTURES_DIR.glob('*.fwf'))
_FWB_FILES = sorted(FIXTURES_DIR.glob('*.fwb'))


@pytest.mark.parametrize(
    'fixture_path',
    _FWF_FILES,
    ids=[p.stem for p in _FWF_FILES],
)
def test_load_save(fixture_path, tmp_path):
    """Load a .fwf fixture, save it, and assert the output is byte-identical."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    output_path = tmp_path / fixture_path.name
    db.save(str(output_path))

    expected = fixture_path.read_text(encoding='utf-8')
    actual = output_path.read_text(encoding='utf-8')

    assert actual == expected, (
        f'Load-save output differs from original.\n'
        f'  Original: {fixture_path}\n'
        f'  Output:   {output_path}\n'
    )


def _assert_no_string_bools(d, context):
    """Assert no value in *d* (or nested dicts) is a string 'true'/'false'."""
    if not isinstance(d, dict):
        return
    for key, value in d.items():
        if isinstance(value, dict):
            _assert_no_string_bools(value, f'{context}.{key}')
        elif isinstance(value, str) and value.lower() in ('true', 'false'):
            pytest.fail(
                f'{context}.{key} is a string {value!r}, expected a Python bool',
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_rule_options_are_booleans(fixture_path):
    """XML rule options must be coerced from strings to Python bools."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        for rule in session.execute(sqlalchemy.select(Rule)).scalars():
            _assert_no_string_bools(
                rule.options,
                f'Rule({rule.id}).options',
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_rule_negations_are_booleans(fixture_path):
    """XML rule negation flags must be Python bools, not strings."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        for rule in session.execute(sqlalchemy.select(Rule)).scalars():
            _assert_no_string_bools(
                rule.negations,
                f'Rule({rule.id}).negations',
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_service_tcp_flags_are_booleans(fixture_path):
    """XML TCP flag dicts must contain Python bools, not strings."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        for svc in session.execute(sqlalchemy.select(Service)).scalars():
            _assert_no_string_bools(
                svc.tcp_flags,
                f'Service({svc.name}).tcp_flags',
            )
            _assert_no_string_bools(
                svc.tcp_flags_masks,
                f'Service({svc.name}).tcp_flags_masks',
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_device_management_are_booleans(fixture_path):
    """XML management dict ``enabled`` fields must be Python bools, not strings."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        for host in session.execute(sqlalchemy.select(Host)).scalars():
            _assert_no_string_bools(
                host.management,
                f'Host({host.name}).management',
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_ruleset_options_are_booleans(fixture_path):
    """XML RuleSet options must not contain string booleans after loading."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        for rs in session.execute(sqlalchemy.select(RuleSet)).scalars():
            _assert_no_string_bools(
                rs.options,
                f'RuleSet({rs.name}).options',
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_library_and_host_ro_are_booleans(fixture_path):
    """XML ``ro`` fields on Libraries and Hosts must be Python bools."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        for lib in session.execute(sqlalchemy.select(Library)).scalars():
            assert isinstance(lib.ro, bool), (
                f'Library({lib.name}).ro is {type(lib.ro).__name__} {lib.ro!r}, '
                f'expected bool'
            )
        for host in session.execute(sqlalchemy.select(Host)).scalars():
            assert isinstance(host.ro, bool), (
                f'Host({host.name}).ro is {type(host.ro).__name__} {host.ro!r}, '
                f'expected bool'
            )
