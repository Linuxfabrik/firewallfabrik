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

"""Private fixture compiler tests (compile-only + optional expected output regression).

Place .fwb/.fwf files in tests/private/fixtures/.  Tests auto-discover
all firewalls and compile each for both ipt and nft.

If an expected output file exists in tests/private/expected-output/{ipt,nft}/<fixture>/<fw>.fw,
output is compared.  Otherwise, the test passes on successful compilation.

Generate expected output files:  python tests/update_expected_output.py --private
"""

import pytest

from .conftest import (
    EXPECTED_OUTPUT_PRIVATE_DIR,
    FIXTURES_PRIVATE_DIR,
    _find_fixture,
    discover_private_test_cases,
)
from .normalize import normalize_ipt, normalize_nft

_CASES = discover_private_test_cases()


@pytest.mark.parametrize(
    ('fixture_name', 'fw_name'),
    _CASES,
    ids=[f'{f}/{n}' for f, n in _CASES],
)
def test_iptables_private(fixture_name, fw_name, compile_ipt, tmp_path):
    """Compile private fixture with iptables; compare expected output if available."""
    fixture_path = _find_fixture(fixture_name, fixtures_dir=FIXTURES_PRIVATE_DIR)
    assert fixture_path is not None, f'Fixture not found: {fixture_name}'

    output_path = compile_ipt(fixture_path, fw_name, tmp_path)

    expected_path = EXPECTED_OUTPUT_PRIVATE_DIR / 'ipt' / fixture_name / f'{fw_name}.fw'
    if not expected_path.exists():
        return

    actual = normalize_ipt(output_path.read_text())
    expected = expected_path.read_text()

    normalized_path = output_path.with_suffix('.normalized.fw')
    normalized_path.write_text(actual)

    assert actual == expected, (
        f'iptables output differs from expected output.\n'
        f'  Actual (raw):        {output_path}\n'
        f'  Actual (normalized): {normalized_path}\n'
        f'  Expected:            {expected_path}\n'
        f'Run "python tests/update_expected_output.py --private --fixture {fixture_name} --platform ipt" to update.'
    )


@pytest.mark.parametrize(
    ('fixture_name', 'fw_name'),
    _CASES,
    ids=[f'{f}/{n}' for f, n in _CASES],
)
def test_nftables_private(fixture_name, fw_name, compile_nft, tmp_path):
    """Compile private fixture with nftables; compare expected output if available."""
    fixture_path = _find_fixture(fixture_name, fixtures_dir=FIXTURES_PRIVATE_DIR)
    assert fixture_path is not None, f'Fixture not found: {fixture_name}'

    output_path = compile_nft(fixture_path, fw_name, tmp_path)

    expected_path = EXPECTED_OUTPUT_PRIVATE_DIR / 'nft' / fixture_name / f'{fw_name}.fw'
    if not expected_path.exists():
        return

    actual = normalize_nft(output_path.read_text())
    expected = expected_path.read_text()

    normalized_path = output_path.with_suffix('.normalized.fw')
    normalized_path.write_text(actual)

    assert actual == expected, (
        f'nftables output differs from expected output.\n'
        f'  Actual (raw):        {output_path}\n'
        f'  Actual (normalized): {normalized_path}\n'
        f'  Expected:            {expected_path}\n'
        f'Run "python tests/update_expected_output.py --private --fixture {fixture_name} --platform nft" to update.'
    )
