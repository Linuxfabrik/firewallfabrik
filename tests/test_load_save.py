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

from .conftest import FIXTURES_DIR, _get_db

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
def test_fwb_rule_options_are_typed(fixture_path):
    """Rule option typed columns must have correct Python types, not strings."""
    from firewallfabrik.core.options._metadata import RULE_OPTIONS

    db = _get_db(fixture_path)

    with db.session() as session:
        for rule in session.execute(sqlalchemy.select(Rule)).scalars():
            for meta in RULE_OPTIONS.values():
                value = getattr(rule, meta.column_name)
                if meta.col_type is bool and isinstance(value, str):
                    pytest.fail(
                        f'Rule({rule.id}).{meta.column_name} is a string '
                        f'{value!r}, expected a Python bool',
                    )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_rule_negations_are_booleans(fixture_path):
    """XML rule negation flags must be Python bools, not strings."""
    db = _get_db(fixture_path)

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
    """TCP flag typed columns must contain Python bools, not strings."""
    db = _get_db(fixture_path)
    flag_attrs = [
        f'tcp_{prefix}_{f}'
        for prefix in ('flag', 'mask')
        for f in ('urg', 'ack', 'psh', 'rst', 'syn', 'fin')
    ]

    with db.session() as session:
        for svc in session.execute(sqlalchemy.select(Service)).scalars():
            for attr in flag_attrs:
                val = getattr(svc, attr, None)
                if val is not None:
                    assert isinstance(val, bool), (
                        f'Service({svc.name}).{attr} is {type(val).__name__} '
                        f'{val!r}, expected bool or None'
                    )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_device_management_are_booleans(fixture_path):
    """XML management dict ``enabled`` fields must be Python bools, not strings."""
    db = _get_db(fixture_path)

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
    """RuleSet typed option columns must contain Python bools, not strings."""
    db = _get_db(fixture_path)

    with db.session() as session:
        for rs in session.execute(sqlalchemy.select(RuleSet)).scalars():
            val = rs.opt_mangle_only_rule_set
            assert isinstance(val, bool), (
                f'RuleSet({rs.name}).opt_mangle_only_rule_set is '
                f'{type(val).__name__} {val!r}, expected bool'
            )


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_fwb_library_and_host_ro_are_booleans(fixture_path):
    """XML ``ro`` fields on Libraries and Hosts must be Python bools."""
    db = _get_db(fixture_path)

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
