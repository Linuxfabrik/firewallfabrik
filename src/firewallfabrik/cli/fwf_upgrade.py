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

"""CLI entry point for headless .fwf upgrades and .fwb -> .fwf conversion.

Loads a Firewall Builder (.fwb) or FirewallFabrik (.fwf) database and writes
it out as a FirewallFabrik (.fwf) file, without launching the GUI.

Two use cases:

* Upgrade an existing .fwf file to the current on-disk format. Loading applies
  the current defaults and schema, so re-saving normalizes formatting and
  migrates a .fwf written by an older FirewallFabrik version. This makes it
  possible to batch-upgrade many .fwf files at once.
* Convert a legacy Firewall Builder .fwb file to the .fwf format.

INPUT may be a single file or a directory. Given a directory, the tool scans it
recursively and processes every .fwf (upgraded in place) and every .fwb
(converted to a .fwf sibling). A .fwb whose .fwf sibling already exists is left
untouched, so an already-migrated .fwf is never overwritten by a stale .fwb.

Use --dry-run to list which files would be upgraded or converted, without
writing anything.

The output is deterministic, so the same input always produces byte-identical
output.
"""

import argparse
import sys
from pathlib import Path

import sqlalchemy.exc

import firewallfabrik
import firewallfabrik.core

__author__ = 'Linuxfabrik GmbH, Zurich/Switzerland'

DESCRIPTION = """FirewallFabrik file upgrader. Reads a FirewallFabrik (.fwf) or Firewall Builder
(.fwb) database and writes it as a .fwf file in the current format, without launching the GUI.
Upgrades older .fwf files to the current schema and converts legacy .fwb files. INPUT may be a
single file or a directory that is scanned recursively."""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='fwf-upgrade',
        description=DESCRIPTION,
    )

    parser.add_argument(
        'input',
        metavar='INPUT',
        help='path to a source .fwb / .fwf file, or a directory to scan recursively',
    )

    parser.add_argument(
        '-o',
        '--output',
        default='',
        dest='OUTPUT',
        help='path to the target .fwf file (single-file input only). '
        'Default: INPUT with a .fwf suffix',
    )

    parser.add_argument(
        '-n',
        '--dry-run',
        action='store_true',
        dest='DRY_RUN',
        help='list which files would be upgraded or converted, without writing anything',
    )

    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version=f'%(prog)s: v{firewallfabrik.__version__} by {__author__}',
    )

    return parser.parse_args(argv)


def _convert(input_path, output_path):
    """Load *input_path* and write *output_path* as a .fwf file.

    Returns ``None`` on success or a human-readable error message on failure.
    """
    db = firewallfabrik.core.DatabaseManager()
    try:
        db.load(input_path)
    except sqlalchemy.exc.IntegrityError as e:
        if 'UNIQUE constraint failed' in str(e):
            dup = firewallfabrik.core.duplicate_object_name(
                e,
                library_names=getattr(db, '_library_names', None),
                parent_names=getattr(db, '_parent_names', None),
            )
            detail = f': {dup}' if dup else ''
            return (
                f'failed to load {input_path}: duplicate names are not '
                f'allowed{detail}. Open the database in Firewall Builder, '
                'rename the affected objects and retry.'
            )
        return f'failed to load {input_path}: {e}'
    except Exception as e:
        return f'failed to load {input_path}: {e}'

    try:
        db.save(output_path)
    except Exception as e:
        return f'failed to write {output_path}: {e}'

    return None


def _run_file(input_path, output, dry_run):
    """Upgrade / convert a single file. Returns a process exit code."""
    output_path = Path(output) if output else input_path.with_suffix('.fwf')

    if output_path.suffix != '.fwf':
        print(
            f'Error: output file must have a .fwf suffix: {output_path}',
            file=sys.stderr,
        )
        return 1

    in_place = output_path.resolve() == input_path.resolve()

    # Guard: converting a .fwb to its default .fwf sibling would clobber an
    # existing .fwf the user did not explicitly target. That .fwf may be the
    # already-migrated working copy, so refuse and let the user decide.
    # An explicit --output is treated as a deliberate choice and overwrites.
    if not in_place and not output and output_path.exists():
        if dry_run:
            print(
                f'Would skip {input_path}: {output_path.name} already exists',
                file=sys.stderr,
            )
            return 0
        print(
            f'Error: {output_path} already exists. Pass --output to write '
            'elsewhere, or remove it to convert over it.',
            file=sys.stderr,
        )
        return 1

    if dry_run:
        if in_place:
            print(f'Would upgrade {input_path} in place', file=sys.stderr)
        else:
            print(f'Would convert {input_path} -> {output_path}', file=sys.stderr)
        return 0

    print(f'Loading database from {input_path} ...', file=sys.stderr)
    err = _convert(input_path, output_path)
    if err:
        print(f'Error: {err}', file=sys.stderr)
        return 1
    print(f'Wrote {output_path}', file=sys.stderr)
    print('Done.', file=sys.stderr)
    return 0


def _run_directory(root, dry_run):
    """Recursively upgrade / convert every .fwf and .fwb file under *root*.

    Every .fwf is upgraded in place. Every .fwb is converted to a .fwf sibling,
    unless that sibling already exists, in which case the .fwb is skipped so an
    already-migrated .fwf is never overwritten by a stale .fwb.

    Returns a process exit code (non-zero if any file failed).
    """
    fwf_files = sorted(root.rglob('*.fwf'))
    fwb_files = sorted(root.rglob('*.fwb'))

    if not fwf_files and not fwb_files:
        print(f'No .fwb or .fwf files found under {root}', file=sys.stderr)
        return 0

    upgraded = converted = skipped = failed = 0

    for path in fwf_files:
        if dry_run:
            print(f'Would upgrade {path} in place', file=sys.stderr)
            upgraded += 1
            continue
        print(f'Upgrading {path} ...', file=sys.stderr)
        err = _convert(path, path)
        if err:
            print(f'Error: {err}', file=sys.stderr)
            failed += 1
        else:
            upgraded += 1

    for path in fwb_files:
        target = path.with_suffix('.fwf')
        if target.exists():
            print(
                f'Skipping {path}: {target.name} already exists '
                '(converting would overwrite the migrated file)',
                file=sys.stderr,
            )
            skipped += 1
            continue
        if dry_run:
            print(f'Would convert {path} -> {target}', file=sys.stderr)
            converted += 1
            continue
        print(f'Converting {path} -> {target} ...', file=sys.stderr)
        err = _convert(path, target)
        if err:
            print(f'Error: {err}', file=sys.stderr)
            failed += 1
        else:
            converted += 1

    prefix = 'Dry run. Would upgrade' if dry_run else 'Done. Upgraded'
    print(
        f'{prefix} {upgraded}, converted {converted}, '
        f'skipped {skipped}, failed {failed}.',
        file=sys.stderr,
    )
    return 1 if failed else 0


def main(argv=None):
    args = parse_args(argv)

    input_path = Path(args.input)

    if input_path.is_dir():
        if args.OUTPUT:
            print(
                'Error: --output cannot be combined with a directory input',
                file=sys.stderr,
            )
            return 1
        return _run_directory(input_path, args.DRY_RUN)

    if not input_path.is_file():
        print(f'Error: input not found: {input_path}', file=sys.stderr)
        return 1

    return _run_file(input_path, args.OUTPUT, args.DRY_RUN)


if __name__ == '__main__':
    sys.exit(main())
