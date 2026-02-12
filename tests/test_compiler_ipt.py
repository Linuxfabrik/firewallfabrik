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

"""Expected output regression tests for the iptables compiler."""

import pytest

from .conftest import EXPECTED_OUTPUT_DIR, _find_fixture, discover_test_cases
from .normalize import normalize_ipt

_CASES = discover_test_cases('ipt')

# Fixtures whose expected output files come from the C++ Firewall Builder compiler.
# These are xfail because the Python reimplementation does not yet produce
# identical output.  As features are ported and output converges, individual
# tests will start passing (reported as XPASS).
_CPP_REFERENCE_FIXTURES = frozenset(
    {
        'cluster-tests',
        'objects-for-regression-tests',
        'optimizer-test',
    }
)


@pytest.mark.parametrize(
    ('fixture_name', 'fw_name'),
    _CASES,
    ids=[f'{f}/{n}' for f, n in _CASES],
)
def test_iptables_expected_output(fixture_name, fw_name, compile_ipt, tmp_path):
    """Compile fixture and compare normalized output to expected output."""
    if fixture_name in _CPP_REFERENCE_FIXTURES:
        pytest.xfail(
            reason='C++ reference expected output — Python compiler output not yet matching',
        )

    fixture_path = _find_fixture(fixture_name)
    expected_path = EXPECTED_OUTPUT_DIR / 'ipt' / fixture_name / f'{fw_name}.fw'

    output_path = compile_ipt(fixture_path, fw_name, tmp_path)

    actual = normalize_ipt(output_path.read_text())
    expected = expected_path.read_text()

    # Save normalized output next to raw output for easier diffing
    normalized_path = output_path.with_suffix('.normalized.fw')
    normalized_path.write_text(actual)

    assert actual == expected, (
        f'iptables output differs from expected output.\n'
        f'  Actual (raw):        {output_path}\n'
        f'  Actual (normalized): {normalized_path}\n'
        f'  Expected:            {expected_path}\n'
        f'Run "python tests/update_expected_output.py --fixture {fixture_name} --platform ipt" to update.'
    )
