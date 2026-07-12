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

"""Tests for the headless ``fwf-upgrade`` CLI."""

import pytest

from firewallfabrik.cli.fwf_upgrade import main

from .conftest import FIXTURES_DIR

_FWB_FILES = sorted(FIXTURES_DIR.glob('*.fwb'))


@pytest.mark.parametrize(
    'fixture_path',
    _FWB_FILES,
    ids=[p.stem for p in _FWB_FILES],
)
def test_upgrade_fwb_to_fwf(fixture_path, tmp_path):
    """Convert a .fwb fixture and assert a non-empty .fwf file is produced."""
    output_path = tmp_path / 'out.fwf'
    rc = main([str(fixture_path), '--output', str(output_path)])

    assert rc == 0
    assert output_path.is_file()
    assert output_path.read_text(encoding='utf-8').strip()


def test_upgrade_is_deterministic(tmp_path):
    """Converting the same .fwb twice yields byte-identical output.

    This is the property the git-history rewrite use case relies on:
    UUIDs regenerated on import must not leak into the .fwf output.
    """
    fixture_path = _FWB_FILES[0]
    first = tmp_path / 'first.fwf'
    second = tmp_path / 'second.fwf'

    assert main([str(fixture_path), '--output', str(first)]) == 0
    assert main([str(fixture_path), '--output', str(second)]) == 0

    assert first.read_text(encoding='utf-8') == second.read_text(encoding='utf-8')


def test_upgrade_default_output_path(tmp_path):
    """Without --output the target is the input path with a .fwf suffix."""
    src = tmp_path / 'firewall.fwb'
    src.write_bytes(_FWB_FILES[0].read_bytes())

    rc = main([str(src)])

    assert rc == 0
    assert (tmp_path / 'firewall.fwf').is_file()


def test_upgrade_explicit_output_overwrites(tmp_path):
    """An explicit --output target is a deliberate choice and is overwritten."""
    output_path = tmp_path / 'out.fwf'
    output_path.write_text('overwrite me', encoding='utf-8')

    rc = main([str(_FWB_FILES[0]), '--output', str(output_path)])

    assert rc == 0
    assert output_path.read_text(encoding='utf-8') != 'overwrite me'


def test_upgrade_refuses_default_sibling_collision(tmp_path):
    """Converting a .fwb refuses to clobber an existing default .fwf sibling."""
    src = tmp_path / 'firewall.fwb'
    src.write_bytes(_FWB_FILES[0].read_bytes())
    sibling = tmp_path / 'firewall.fwf'
    sibling.write_text('keep me', encoding='utf-8')

    rc = main([str(src)])

    assert rc == 1
    assert sibling.read_text(encoding='utf-8') == 'keep me'


def test_upgrade_in_place_fwf(tmp_path):
    """A .fwf file is upgraded in place with no flags (batch use case)."""
    # Produce a .fwf to upgrade in place.
    src = tmp_path / 'fw.fwf'
    assert main([str(_FWB_FILES[0]), '--output', str(src)]) == 0
    before = src.read_text(encoding='utf-8')

    # Default output for a .fwf input is the input path itself.
    rc = main([str(src)])

    assert rc == 0
    assert src.read_text(encoding='utf-8') == before


def test_upgrade_missing_input(tmp_path):
    """A missing input file is reported as an error."""
    rc = main([str(tmp_path / 'does-not-exist.fwb')])

    assert rc == 1


def test_upgrade_rejects_non_fwf_output(tmp_path):
    """The output path must carry a .fwf suffix."""
    rc = main([str(_FWB_FILES[0]), '--output', str(tmp_path / 'out.txt')])

    assert rc == 1


def test_upgrade_directory_recursive(tmp_path):
    """A directory is scanned recursively: .fwb converted, .fwf upgraded."""
    # A .fwb in a nested directory (no .fwf sibling -> converted).
    nested = tmp_path / 'sub'
    nested.mkdir()
    (nested / 'a.fwb').write_bytes(_FWB_FILES[0].read_bytes())

    # A standalone .fwf at the top level (upgraded in place).
    fwf_file = tmp_path / 'b.fwf'
    assert main([str(_FWB_FILES[0]), '--output', str(fwf_file)]) == 0
    before = fwf_file.read_text(encoding='utf-8')

    rc = main([str(tmp_path)])

    assert rc == 0
    assert (nested / 'a.fwf').is_file()
    assert fwf_file.read_text(encoding='utf-8') == before


def test_upgrade_directory_skips_fwb_with_fwf_sibling(tmp_path):
    """A .fwb is not converted when a .fwf sibling already exists.

    The .fwf sibling here is an invalid stub, so upgrading it fails and leaves
    it untouched. Because the .fwb branch is skipped for a file that has a
    .fwf sibling, the stub content must survive: the .fwb never clobbers it.
    """
    (tmp_path / 'fw.fwb').write_bytes(_FWB_FILES[0].read_bytes())
    sibling = tmp_path / 'fw.fwf'
    sibling.write_text('do not overwrite me', encoding='utf-8')

    main([str(tmp_path)])

    assert sibling.read_text(encoding='utf-8') == 'do not overwrite me'


def test_upgrade_dry_run_single_file_writes_nothing(tmp_path):
    """--dry-run on a single .fwb reports the plan but creates no file."""
    rc = main([str(_FWB_FILES[0]), '--output', str(tmp_path / 'out.fwf'), '--dry-run'])

    assert rc == 0
    assert not (tmp_path / 'out.fwf').exists()


def test_upgrade_dry_run_directory_writes_nothing(tmp_path):
    """--dry-run on a directory converts/upgrades nothing on disk."""
    (tmp_path / 'a.fwb').write_bytes(_FWB_FILES[0].read_bytes())
    fwf_file = tmp_path / 'b.fwf'
    assert main([str(_FWB_FILES[0]), '--output', str(fwf_file)]) == 0
    before = fwf_file.read_text(encoding='utf-8')

    rc = main([str(tmp_path), '--dry-run'])

    assert rc == 0
    # No .fwf produced for the .fwb, and the existing .fwf is untouched.
    assert not (tmp_path / 'a.fwf').exists()
    assert fwf_file.read_text(encoding='utf-8') == before


def test_upgrade_directory_empty(tmp_path):
    """An empty directory is reported but not an error."""
    rc = main([str(tmp_path)])

    assert rc == 0


def test_upgrade_directory_rejects_output(tmp_path):
    """--output is not allowed together with a directory input."""
    (tmp_path / 'a.fwb').write_bytes(_FWB_FILES[0].read_bytes())

    rc = main([str(tmp_path), '--output', str(tmp_path / 'x.fwf')])

    assert rc == 1
