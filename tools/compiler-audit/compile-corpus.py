#!/usr/bin/env python3
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

"""Compile every firewall of a corpus with both compilers.

This is the first step of the compiler audit: it produces the scripts the
other checks in this directory then run through the real tools.  See
README.md for what each check proves.

The report it writes next to the output holds the errors and warnings each
firewall produced, which is what tells you where to look:

    python tools/compiler-audit/compile-corpus.py /tmp/audit
    python - <<'EOF'
    import collections, json, re
    r = json.load(open('/tmp/audit/report.json'))
    c = collections.Counter()
    for key, run in r.items():
        for err in run.get('errors', []):
            c[re.sub(r'\\d+', 'N', err)] += 1
    for msg, n in c.most_common(20):
        print(n, msg)
    EOF

A `.fwb` import assigns fresh UUIDs on every load, so the database is
reloaded for each firewall instead of being shared.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO_ROOT / 'tests' / 'fixtures'


def firewall_names(path: Path) -> list[str]:
    """Return the name of every firewall in the data file *path*."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(path))
    with db.session() as session:
        return [
            fw.name for fw in session.execute(sqlalchemy.select(Firewall)).scalars()
        ]


def compile_one(path: Path, fw_name: str, outdir: Path, platform: str) -> dict:
    """Compile one firewall and return what the driver reported."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(path))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == fw_name)
        ).scalar_one()
        fw_id = str(fw.id)

    if platform == 'ipt':
        from firewallfabrik.platforms.iptables._compiler_driver import (
            CompilerDriver_ipt,
        )

        driver = CompilerDriver_ipt(db)
    else:
        from firewallfabrik.platforms.nftables._compiler_driver import (
            CompilerDriver_nft,
        )

        driver = CompilerDriver_nft(db)

    driver.wdir = str(outdir)
    # An address table names its file relative to the data file.
    driver.source_dir = str(path.parent)
    driver.file_name_setting = f'{fw_name}.fw'

    try:
        result = driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    except Exception as exc:
        return {'crash': f'{type(exc).__name__}: {exc}'}

    return {
        'result': result,
        'errors': list(driver.all_errors),
        'warnings': list(driver.all_warnings),
    }


def corpus_files(corpus: Path) -> list[Path]:
    """Return the data files of *corpus*, which may be a file or a directory.

    A file listing one path per line lets the corpus live outside the
    repository without naming it here.
    """
    if corpus.is_dir():
        return sorted(p for p in corpus.iterdir() if p.suffix in ('.fwf', '.fwb'))
    if corpus.suffix in ('.fwf', '.fwb'):
        return [corpus]
    return [
        Path(line.strip()).expanduser()
        for line in corpus.read_text().splitlines()
        if line.strip() and not line.startswith('#')
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('outdir', type=Path, help='where to write the scripts')
    parser.add_argument(
        '--corpus',
        type=Path,
        default=DEFAULT_CORPUS,
        help='a data file, a directory of them, or a file listing their paths '
        f'(default: {DEFAULT_CORPUS})',
    )
    parser.add_argument(
        '--platform',
        choices=('ipt', 'nft'),
        action='append',
        help='compile for this platform only (repeatable)',
    )
    args = parser.parse_args()

    platforms = args.platform or ['ipt', 'nft']
    files = [p for p in corpus_files(args.corpus) if p.exists()]
    if not files:
        print(f'no data files found in {args.corpus}', file=sys.stderr)
        return 1

    report: dict[str, dict] = {}
    for platform in platforms:
        for src in files:
            outdir = args.outdir / platform / src.stem
            outdir.mkdir(parents=True, exist_ok=True)
            try:
                names = firewall_names(src)
            except Exception as exc:
                report[f'{platform}/{src.stem}'] = {'load_crash': str(exc)[:500]}
                continue
            for fw_name in names:
                key = f'{platform}/{src.stem}/{fw_name}'
                report[key] = compile_one(src, fw_name, outdir, platform)
                print(key, flush=True)

    args.outdir.mkdir(parents=True, exist_ok=True)
    (args.outdir / 'report.json').write_text(json.dumps(report, indent=1))

    crashed = [k for k, v in report.items() if 'crash' in v or 'load_crash' in v]
    errored = [k for k, v in report.items() if v.get('errors')]
    print(
        f'\n{len(report)} firewalls compiled, {len(errored)} with errors, '
        f'{len(crashed)} crashed'
    )
    return 1 if crashed else 0


if __name__ == '__main__':
    sys.exit(main())
