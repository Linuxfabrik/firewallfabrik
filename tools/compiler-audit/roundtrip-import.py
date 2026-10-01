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

"""Does an imported ruleset decide packets the way the original did?

Each nftables ruleset of a compiled corpus is loaded into a private network
namespace and read back with ``nft -j list ruleset``; the listing goes
through the importer into a fresh data file, and the firewall that comes
out is compiled again.  The result is written in the layout
``compile-corpus.py`` writes, so ``compare-verdicts.py`` can send the same
packets through the original and the round-tripped ruleset:

    python tools/compiler-audit/compile-corpus.py /tmp/rt-before
    python tools/compiler-audit/roundtrip-import.py /tmp/rt-before /tmp/rt-after
    python tools/compiler-audit/compare-verdicts.py /tmp/rt-before /tmp/rt-after

With ``--from iptables`` the iptables scripts of the corpus are run in the
namespace instead, read back with ``iptables-save`` and imported, and the
firewall is compiled for nftables - so the comparison is against the
nftables compile of the same firewall, which tells whether the iptables
importer says the same as the nftables one.

A rule the importer cannot carry over is imported disabled, so a
difference can be a gap of the importer that it reports, or one it does
not report - the second kind is the one to look for.  The report
``roundtrip.json`` beside the output lists every rule imported disabled.
"""

from __future__ import annotations

import argparse
import importlib.resources
import json
import re
import subprocess  # nosec B404
import sys
import tempfile
import uuid
from pathlib import Path

import sqlalchemy

from firewallfabrik.core._database import DatabaseManager
from firewallfabrik.core.objects import FWObjectDatabase, Library
from firewallfabrik.gui.object_tree_data import (
    SYSTEM_GROUP_PATHS,
    create_library_folder_structure,
)
from firewallfabrik.importer import (
    apply_plan,
    parse_iptables_save,
    parse_nft_json,
    plan_import,
)

RULESET_RE = re.compile(r"<<\s*'?NFT_RULES'?\n(.*?)^NFT_RULES$", re.M | re.S)


def new_database():
    """A data file the way File > New makes one: Standard plus an empty User."""
    db_manager = DatabaseManager()
    std = (
        Path(str(importlib.resources.files('firewallfabrik') / 'resources'))
        / 'libraries'
        / 'standard.fwf'
    )
    db_manager._load_yaml(std)
    with db_manager.session() as session:
        db = session.scalars(sqlalchemy.select(FWObjectDatabase)).first()
        library = Library(id=uuid.uuid4(), name='User', database=db)
        session.add(library)
        session.flush()
        create_library_folder_structure(session, library.id)
        library_id = library.id
    return db_manager, library_id


def listing_nft(script: Path) -> str | None:
    match = RULESET_RE.search(script.read_text())
    if match is None:
        return None
    with tempfile.NamedTemporaryFile('w', suffix='.nft', delete=False) as handle:
        handle.write(match.group(1))
        rules = handle.name
    result = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', f'nft -f {rules} && nft -j list ruleset'],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    Path(rules).unlink()
    if result.returncode != 0:
        return None
    return result.stdout


def listing_ipt(script: Path) -> tuple[str, str] | None:
    """Run an iptables script in a namespace; return its two save outputs."""
    interfaces = sorted(set(re.findall(r'-[io] ([A-Za-z0-9_.-]+)', script.read_text())))
    setup = ' '.join(
        f'ip link add {name} type dummy 2>/dev/null; ip link set {name} up;'
        for name in interfaces
        if name not in ('lo',) and len(name) < 16
    )
    result = subprocess.run(  # nosec B603 B607
        [
            'unshare',
            '-rn',
            'sh',
            '-c',
            f'{setup} FWF_LOCK_FILE=$(mktemp) sh {script} start >/dev/null 2>&1; '
            'iptables-save; echo ===FWF===; ip6tables-save',
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if '===FWF===' not in result.stdout:
        return None
    v4, v6 = result.stdout.split('===FWF===', 1)
    return v4, v6


def compile_nft(db_manager, fw_name: str, outdir: Path) -> None:
    from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

    with tempfile.TemporaryDirectory() as tmp:
        data_file = Path(tmp) / 'imported.fwf'
        db_manager.save(data_file)
        db = DatabaseManager()
        db.load(data_file)
        with db.session() as session:
            from firewallfabrik.core.objects import Firewall

            fw = session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == fw_name)
            ).first()
            fw_id = fw.id
        driver = CompilerDriver_nft(db)
        driver.wdir = str(outdir)
        driver.file_name_setting = f'{fw_name}.fw'
        driver.run(cluster_id='', fw_id=str(fw_id), single_rule_id='')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('before', type=Path, help='a tree compile-corpus.py wrote')
    parser.add_argument('after', type=Path, help='where to write the round trip')
    parser.add_argument(
        '--from', dest='source', choices=('nftables', 'iptables'), default='nftables'
    )
    parser.add_argument('--only', default='', help='only paths containing this')
    args = parser.parse_args()

    subtree = 'nft' if args.source == 'nftables' else 'ipt'
    report = {}
    for script in sorted((args.before / subtree).rglob('*.fw')):
        relative = script.relative_to(args.before / subtree)
        if args.only not in str(relative):
            continue
        fw_name = script.stem
        print(f'... {relative}', flush=True)
        if args.source == 'nftables':
            listing = listing_nft(script)
            rulesets = [parse_nft_json(listing)] if listing else None
        else:
            saved = listing_ipt(script)
            rulesets = (
                [parse_iptables_save(saved[0], 4), parse_iptables_save(saved[1], 6)]
                if saved
                else None
            )
        if not rulesets:
            report[str(relative)] = {'status': 'not loaded'}
            continue
        db_manager, library_id = new_database()
        try:
            plan = plan_import(
                db_manager,
                library_id,
                rulesets,
                fw_name,
                'nftables',
                group_paths=SYSTEM_GROUP_PATHS,
            )
            apply_plan(db_manager, library_id, plan, group_paths=SYSTEM_GROUP_PATHS)
            outdir = args.after / 'nft' / relative.parent
            outdir.mkdir(parents=True, exist_ok=True)
            compile_nft(db_manager, fw_name, outdir)
        except Exception as exc:
            report[str(relative)] = {'status': 'failed', 'error': repr(exc)}
            print(f'=== {relative}: {exc!r}')
            continue
        report[str(relative)] = {
            'status': 'imported',
            'rules': plan.imported_rules,
            'disabled': plan.unsupported_rules,
            'messages': plan.messages,
        }
    (args.after).mkdir(parents=True, exist_ok=True)
    (args.after / 'roundtrip.json').write_text(json.dumps(report, indent=1))
    counts = {}
    for entry in report.values():
        counts[entry['status']] = counts.get(entry['status'], 0) + 1
    disabled = sum(e.get('disabled', 0) for e in report.values())
    print(f'---\n{counts}; {disabled} rules imported disabled')
    return 0


if __name__ == '__main__':
    sys.exit(main())
