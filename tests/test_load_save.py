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

import firewallfabrik.core

from .conftest import FIXTURES_DIR

_FWF_FILES = sorted(FIXTURES_DIR.glob('*.fwf'))


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
