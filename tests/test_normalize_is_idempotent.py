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

"""Normalizing an already-normalized script has to change nothing.

Two paths write the expected output files.  `update_expected_output.py`
compiles a fixture and normalizes what the compiler produced; its
`--normalize-only` mode normalizes a file that is already on disk, which
is how the Firewall Builder reference is imported.  A normalizer that is
not idempotent makes the two disagree: the file the first path writes is
changed by the second, so re-importing the reference silently moves it
away from what the C++ compiler produced - which is the one thing the
reference must not do.

The pair that broke it: a line of nothing but spaces is not yet a blank
line, so it survived the blank-line collapse and became one right after
it, leaving a run the collapse would have removed.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from normalize import normalize_ipt, normalize_nft

EXPECTED_OUTPUT_DIR = pathlib.Path(__file__).parent / 'expected-output'


def _scripts(platform):
    return sorted((EXPECTED_OUTPUT_DIR / platform).rglob('*.fw'))


@pytest.mark.parametrize(
    'normalize',
    [normalize_ipt, normalize_nft],
    ids=['ipt', 'nft'],
)
def test_a_line_of_spaces_between_two_blank_lines_leaves_one(normalize):
    text = 'a\n\n    \n\nb\n'
    once = normalize(text)
    assert once == normalize(once)
    assert once == 'a\n\nb\n'


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
def test_every_checked_in_expected_output_is_already_normalized(platform):
    """A file the harness would change is a file that has drifted."""
    normalize = normalize_ipt if platform == 'ipt' else normalize_nft
    drifted = [
        str(path.relative_to(EXPECTED_OUTPUT_DIR))
        for path in _scripts(platform)
        if normalize(path.read_text()) != path.read_text()
    ]
    assert drifted == []
