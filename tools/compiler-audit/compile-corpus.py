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
from firewallfabrik.core.objects import Cluster, Firewall

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO_ROOT / 'tests' / 'fixtures'


def compile_targets(path: Path) -> list[tuple[str, str, str]]:
    """Return what compiling the data file *path* means, one run per entry.

    ``(cluster name, firewall name, output name)``.  A cluster is not a
    machine: it is compiled by compiling each of its members with the
    cluster named alongside, and Firewall Builder writes the result as
    `<cluster>_<member>.fw`, which is how its reference output is named.
    The cluster object itself is compiled too, because fwf allows it and
    the expected-output tests cover it.
    """
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(path))
    targets: list[tuple[str, str, str]] = []
    with db.session() as session:
        for fw in session.execute(sqlalchemy.select(Firewall)).scalars():
            targets.append(('', fw.name, fw.name))
            if isinstance(fw, Cluster):
                targets.extend(
                    (fw.name, member.name, f'{fw.name}_{member.name}')
                    for member in fw.get_members_list()
                )
    return targets


def compile_one(
    path: Path, target: tuple[str, str, str], outdir: Path, platform: str
) -> dict:
    """Compile one firewall and return what the driver reported."""
    cluster_name, fw_name, out_name = target
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(path))
    with db.session() as session:
        cluster_id = ''
        if cluster_name:
            cluster = session.execute(
                sqlalchemy.select(Cluster).where(Cluster.name == cluster_name)
            ).scalar_one()
            cluster_id = str(cluster.id)
        fw = session.execute(
            sqlalchemy.select(Firewall)
            .where(Firewall.name == fw_name)
            .where(Firewall.type != 'Cluster' if cluster_name else sqlalchemy.true())
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
    driver.file_name_setting = f'{out_name}.fw'

    try:
        result = driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')
    except Exception as exc:
        return {'crash': f'{type(exc).__name__}: {exc}'}

    return {
        'result': result,
        'errors': list(driver.all_errors),
        'warnings': list(driver.all_warnings),
    }


def force_address_family(family: str) -> None:
    """Compile one address family alone, the way `fwf-ipt -4` does.

    A property beats the instance attribute the driver sets for itself,
    which is what this has to do: the driver clears `ipv6_run` on its own
    whenever no rule set of the firewall names IPv6, so an attribute
    written before the run is gone by the time the run reads it.
    """
    from firewallfabrik.driver._compiler_driver import CompilerDriver

    CompilerDriver.ipv4_run = property(
        lambda self: family == '4', lambda self, value: None
    )
    CompilerDriver.ipv6_run = property(
        lambda self: family == '6', lambda self, value: None
    )


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
    parser.add_argument(
        '--address-family',
        choices=('4', '6'),
        help='compile this address family alone, the way the `-4` / `-6` '
        'switch of the compiler does; see README.md for what comparing the '
        'two halves against a dual-stack run proves',
    )
    args = parser.parse_args()

    if args.address_family:
        force_address_family(args.address_family)

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
                targets = compile_targets(src)
            except Exception as exc:
                report[f'{platform}/{src.stem}'] = {'load_crash': str(exc)[:500]}
                continue
            for target in targets:
                key = f'{platform}/{src.stem}/{target[2]}'
                report[key] = compile_one(src, target, outdir, platform)
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
