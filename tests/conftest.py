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

"""Shared pytest fixtures for compiler golden file tests."""

from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

FIXTURES_DIR = Path(__file__).parent / 'fixtures'
GOLDEN_DIR = Path(__file__).parent / 'golden'


FIXTURE_EXTENSIONS = ('.fwf', '.fwb')


def _find_fixture(fixture_name: str) -> Path | None:
    """Find a fixture file by name, trying .fwf then .fwb extensions."""
    for ext in FIXTURE_EXTENSIONS:
        path = FIXTURES_DIR / f'{fixture_name}{ext}'
        if path.exists():
            return path
    return None


def _find_firewalls(fixture_path: Path) -> list[str]:
    """Return all firewall names in a .fwf or .fwb file."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))
    with db.session() as session:
        firewalls = session.execute(sqlalchemy.select(Firewall)).scalars().all()
        return [fw.name for fw in firewalls]


def _compile(fixture_path: Path, fw_name: str, tmp_path: Path, platform: str) -> Path:
    """Compile a firewall from a .fwf/.fwb fixture and return the output file path.

    Args:
        fixture_path: Path to the .fwf or .fwb fixture file.
        fw_name: Name of the firewall object to compile.
        tmp_path: Temporary directory for output.
        platform: 'ipt' or 'nft'.

    Returns:
        Path to the generated output file.
    """
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fixture_path))

    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == fw_name),
        ).scalar_one()
        fw_id = str(fw.id)

    if platform == 'ipt':
        from firewallfabrik.platforms.iptables._compiler_driver import (
            CompilerDriver_ipt,
        )

        driver = CompilerDriver_ipt(db)
    elif platform == 'nft':
        from firewallfabrik.platforms.nftables._compiler_driver import (
            CompilerDriver_nft,
        )

        driver = CompilerDriver_nft(db)
    else:
        msg = f'Unknown platform: {platform}'
        raise ValueError(msg)

    driver.wdir = str(tmp_path)
    driver.file_name_setting = f'{fw_name}.fw'

    result = driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')

    if result:
        pytest.fail(f'Compilation error for {fw_name} ({platform}): {result}')
    if driver.all_errors:
        pytest.fail(
            f'Compilation errors for {fw_name} ({platform}): '
            + '; '.join(driver.all_errors),
        )

    output_path = Path(driver.file_names[fw_id])
    assert output_path.exists(), f'Output file not created: {output_path}'
    return output_path


@pytest.fixture()
def compile_ipt():
    """Return a helper that compiles a .fwf fixture with the iptables driver."""

    def _inner(fixture_path: Path, fw_name: str, tmp_path: Path) -> Path:
        return _compile(fixture_path, fw_name, tmp_path, 'ipt')

    return _inner


@pytest.fixture()
def compile_nft():
    """Return a helper that compiles a .fwf/.fwb fixture with the nftables driver."""

    def _inner(fixture_path: Path, fw_name: str, tmp_path: Path) -> Path:
        return _compile(fixture_path, fw_name, tmp_path, 'nft')

    return _inner


def discover_test_cases(platform: str) -> list[tuple[str, str]]:
    """Discover (fixture_name, fw_name) pairs from golden directory.

    Returns a list of tuples suitable for pytest parametrize.
    """
    golden_platform_dir = GOLDEN_DIR / platform
    if not golden_platform_dir.exists():
        return []

    cases = []
    for fixture_dir in sorted(golden_platform_dir.iterdir()):
        if not fixture_dir.is_dir():
            continue
        fixture_name = fixture_dir.name
        if _find_fixture(fixture_name) is None:
            continue
        for golden_file in sorted(fixture_dir.glob('*.fw')):
            fw_name = golden_file.stem
            cases.append((fixture_name, fw_name))
    return cases
