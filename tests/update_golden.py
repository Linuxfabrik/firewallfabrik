#!/usr/bin/env python
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

"""Recompile fixtures and update golden files with normalized output.

Usage:
    python tests/update_golden.py                              # recompile all
    python tests/update_golden.py --fixture basic_accept_deny  # recompile one fixture
    python tests/update_golden.py --platform nft               # recompile only nftables
    python tests/update_golden.py --normalize-only             # normalize existing golden files in-place
    python tests/update_golden.py --normalize-only --platform ipt  # normalize only iptables golden files
"""

import argparse
import sys
import tempfile
from pathlib import Path

# Allow running from the repo root without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

import sqlalchemy
from normalize import normalize_ipt, normalize_nft

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

TESTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = TESTS_DIR / 'fixtures'
GOLDEN_DIR = TESTS_DIR / 'golden'

PLATFORMS = {
    'ipt': {
        'normalize': normalize_ipt,
        'driver_path': 'firewallfabrik.platforms.iptables._compiler_driver',
        'driver_class': 'CompilerDriver_ipt',
    },
    'nft': {
        'normalize': normalize_nft,
        'driver_path': 'firewallfabrik.platforms.nftables._compiler_driver',
        'driver_class': 'CompilerDriver_nft',
    },
}


def normalize_existing(platform: str, fixture: str | None = None) -> list[str]:
    """Normalize existing golden files in-place.

    Reads each .fw file under tests/golden/<platform>/, applies the
    platform normalizer, and writes the result back.

    Returns a list of normalized file paths (relative to repo root).
    """
    normalize = PLATFORMS[platform]['normalize']
    golden_platform_dir = GOLDEN_DIR / platform

    if not golden_platform_dir.exists():
        print(f'  No golden directory: {golden_platform_dir}', file=sys.stderr)
        return []

    if fixture:
        dirs = [golden_platform_dir / fixture]
        if not dirs[0].exists():
            print(f'  No golden directory: {dirs[0]}', file=sys.stderr)
            return []
    else:
        dirs = sorted(d for d in golden_platform_dir.iterdir() if d.is_dir())

    updated = []
    for fixture_dir in dirs:
        for golden_path in sorted(fixture_dir.glob('*.fw')):
            raw = golden_path.read_text()
            normalized = normalize(raw)
            if raw != normalized:
                golden_path.write_text(normalized)
                rel = golden_path.relative_to(TESTS_DIR.parent)
                updated.append(str(rel))
                print(f'  Normalized: {rel}')
    return updated


def compile_and_update(fwf_path: Path, platform: str) -> list[str]:
    """Compile all firewalls in a fixture and update golden files.

    Returns a list of updated file paths (relative to repo root).
    """
    import importlib

    cfg = PLATFORMS[platform]
    mod = importlib.import_module(cfg['driver_path'])
    driver_cls = getattr(mod, cfg['driver_class'])
    normalize = cfg['normalize']

    fixture_name = fwf_path.stem
    golden_dir = GOLDEN_DIR / platform / fixture_name
    golden_dir.mkdir(parents=True, exist_ok=True)

    db = firewallfabrik.core.DatabaseManager()
    db.load(str(fwf_path))

    updated = []

    with db.session() as session:
        firewalls = session.execute(sqlalchemy.select(Firewall)).scalars().all()

        for fw in firewalls:
            fw_id = str(fw.id)
            fw_name = fw.name

            with tempfile.TemporaryDirectory() as tmp_dir:
                driver = driver_cls(db)
                driver.wdir = tmp_dir
                driver.file_name_setting = f'{fw_name}.fw'

                result = driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')

                if result:
                    print(
                        f'  ERROR compiling {fw_name} ({platform}): {result}',
                        file=sys.stderr,
                    )
                    continue
                if driver.all_errors:
                    print(
                        f'  ERROR compiling {fw_name} ({platform}): '
                        + '; '.join(driver.all_errors),
                        file=sys.stderr,
                    )
                    continue

                output_path = Path(driver.file_names[fw_id])
                raw_output = output_path.read_text()

            normalized = normalize(raw_output)
            golden_path = golden_dir / f'{fw_name}.fw'
            golden_path.write_text(normalized)
            updated.append(str(golden_path.relative_to(TESTS_DIR.parent)))
            print(f'  Updated: {golden_path.relative_to(TESTS_DIR.parent)}')

    return updated


def main():
    parser = argparse.ArgumentParser(
        description='Update golden files for compiler regression tests.',
    )
    parser.add_argument(
        '--fixture',
        default=None,
        help='Update only the named fixture (without extension).',
    )
    parser.add_argument(
        '--platform',
        choices=['ipt', 'nft'],
        default=None,
        help='Update only the specified platform.',
    )
    parser.add_argument(
        '--normalize-only',
        action='store_true',
        default=False,
        help='Normalize existing golden files in-place instead of recompiling.',
    )
    args = parser.parse_args()

    platforms = [args.platform] if args.platform else list(PLATFORMS.keys())

    if args.normalize_only:
        total_updated = 0
        for platform in platforms:
            print(f'Normalizing golden files ({platform}):')
            updated = normalize_existing(platform, fixture=args.fixture)
            total_updated += len(updated)
        if total_updated == 0:
            print('\nAll golden files are already normalized.')
        else:
            print(f'\n{total_updated} golden file(s) normalized.')
        return 0

    if args.fixture:
        # Try .fwf first, then .fwb
        fixture = None
        for ext in ('.fwf', '.fwb'):
            candidate = FIXTURES_DIR / f'{args.fixture}{ext}'
            if candidate.exists():
                fixture = candidate
                break
        if fixture is None:
            print(f'Fixture not found: {args.fixture}(.fwf/.fwb)', file=sys.stderr)
            return 1
        fixtures = [fixture]
    else:
        fixtures = sorted(
            [*FIXTURES_DIR.glob('*.fwf'), *FIXTURES_DIR.glob('*.fwb')],
            key=lambda p: p.stem,
        )
        if not fixtures:
            print('No fixtures found in tests/fixtures/', file=sys.stderr)
            return 1

    total_updated = 0
    for fwf_path in fixtures:
        for platform in platforms:
            print(f'{fwf_path.stem} ({platform}):')
            updated = compile_and_update(fwf_path, platform)
            total_updated += len(updated)

    print(f'\n{total_updated} golden file(s) updated.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
