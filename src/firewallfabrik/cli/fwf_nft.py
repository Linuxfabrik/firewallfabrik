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

"""CLI entry point for the nftables compiler."""

import argparse
import sys
import time
from pathlib import Path

import sqlalchemy
import sqlalchemy.exc

import firewallfabrik
import firewallfabrik.core
import firewallfabrik.core.objects

__author__ = 'Linuxfabrik GmbH, Zurich/Switzerland'

DESCRIPTION = """FirewallFabrik policy compiler for nftables. Loads a firewall object database and
compiles nftables rules for the specified firewall."""

DEFAULT_DESTDIR = '.'


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='fwf-nft',
        description=DESCRIPTION,
    )

    parser.add_argument(
        'firewall_names',
        nargs='*',
        help='name(s) (or IDs if -i / paths if -p) of firewall objects to compile',
    )

    parser.add_argument(
        '-a',
        '--all',
        action='store_true',
        dest='COMPILE_ALL',
        help='compile all nftables firewalls in the database',
    )

    parser.add_argument(
        '-f',
        '--file',
        required=True,
        dest='FILE',
        help='path to the .fwb / .fwf database file',
    )

    parser.add_argument(
        '-d',
        '--destdir',
        default=DEFAULT_DESTDIR,
        dest='DESTDIR',
        help='output directory for generated scripts. Default: %(default)s',
    )

    fw_lookup = parser.add_mutually_exclusive_group()
    fw_lookup.add_argument(
        '-i',
        '--id',
        action='store_true',
        dest='FW_BY_ID',
        help='look up firewall by object ID instead of name',
    )
    fw_lookup.add_argument(
        '-p',
        '--path',
        action='store_true',
        dest='FW_BY_PATH',
        help='look up firewall by tree-path identifier instead of name',
    )

    parser.add_argument(
        '-o',
        '--output',
        default='',
        dest='OUTPUT',
        help='output file name override',
    )

    parser.add_argument(
        '-s',
        '--single-rule',
        default='',
        dest='SINGLE_RULE',
        help='compile a single rule by ID',
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        dest='VERBOSE',
        help='verbose output (repeat for higher verbosity)',
    )

    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version=f'%(prog)s: v{firewallfabrik.__version__} by {__author__}',
    )

    parser.add_argument(
        '--xn',
        type=int,
        default=None,
        dest='DEBUG_NAT_RULE',
        help='debug NAT rule number',
    )

    parser.add_argument(
        '--xp',
        type=int,
        default=None,
        dest='DEBUG_POLICY_RULE',
        help='debug policy rule number',
    )

    parser.add_argument(
        '--xr',
        type=int,
        default=None,
        dest='DEBUG_ROUTING_RULE',
        help='debug routing rule number',
    )

    ip_version = parser.add_mutually_exclusive_group()
    ip_version.add_argument(
        '-4',
        '--ipv4',
        action='store_true',
        dest='IPV4',
        help='compile IPv4 rules only',
    )
    ip_version.add_argument(
        '-6',
        '--ipv6',
        action='store_true',
        dest='IPV6',
        help='compile IPv6 rules only',
    )

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if not args.firewall_names and not args.COMPILE_ALL:
        print('Error: specify firewall name(s) or use --all', file=sys.stderr)
        return 1

    t_start = time.monotonic()

    print(f'Loading database from {args.FILE} ...', file=sys.stderr)

    db = firewallfabrik.core.DatabaseManager()
    try:
        db.load(args.FILE)
    except sqlalchemy.exc.IntegrityError as e:
        msg = f'Error: failed to load database from {args.FILE}: '
        if 'UNIQUE constraint failed' in str(e):
            lib_names = getattr(db, '_library_names', None)
            parent_names = getattr(db, '_parent_names', None)
            dup = firewallfabrik.core.duplicate_object_name(
                e,
                library_names=lib_names,
                parent_names=parent_names,
            )
            detail = f': {dup}' if dup else ''
            if args.FILE.endswith('.fwb'):
                msg += (
                    f'Duplicate names are not allowed{detail}. Open the '
                    'database in Firewall Builder, rename the affected '
                    'objects and retry the import.'
                )
            else:
                msg += (
                    f'Duplicate names are not allowed{detail}. This should '
                    'not happen during normal operations. If you edited the '
                    'YAML manually, double-check your changes.'
                )
        else:
            msg += str(e)
        print(msg, file=sys.stderr)
        return 1
    except Exception as e:
        print(f'Error: failed to load database from {args.FILE}: {e}', file=sys.stderr)
        return 1

    # Resolve firewalls to compile
    Firewall = firewallfabrik.core.objects.Firewall
    fw_list = []
    with db.session() as session:
        if args.COMPILE_ALL:
            all_fws = (
                session.execute(
                    sqlalchemy.select(Firewall).order_by(Firewall.name),
                )
                .scalars()
                .all()
            )
            for fw in all_fws:
                if (fw.data or {}).get('platform', '') == 'nftables':
                    fw_list.append((str(fw.id), fw.name))
            print(
                f'Found {len(fw_list)} nftables firewall(s) to compile',
                file=sys.stderr,
            )
        else:
            for name in args.firewall_names:
                if args.FW_BY_PATH:
                    fw_uuid = db.ref_index.get(name)
                    if fw_uuid is None:
                        print(
                            f"Error: tree-path '{name}' not found in {args.FILE}",
                            file=sys.stderr,
                        )
                        continue
                    fw = session.get(Firewall, fw_uuid)
                elif args.FW_BY_ID:
                    fw = session.execute(
                        sqlalchemy.select(Firewall).where(Firewall.id == name),
                    ).scalar_one_or_none()
                else:
                    fw = session.execute(
                        sqlalchemy.select(Firewall).where(Firewall.name == name),
                    ).scalar_one_or_none()

                if fw is None:
                    label = (
                        'tree-path'
                        if args.FW_BY_PATH
                        else 'id'
                        if args.FW_BY_ID
                        else 'name'
                    )
                    print(
                        f"Error: firewall with {label} '{name}' "
                        f'not found in {args.FILE}',
                        file=sys.stderr,
                    )
                    continue
                fw_list.append((str(fw.id), fw.name))

    if not fw_list:
        print('Error: no firewalls found to compile', file=sys.stderr)
        return 1

    # Compile each firewall (single DB load, sequential compilation)
    from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

    compiled_ok = 0
    compiled_err = 0
    for fw_id, fw_name in fw_list:
        if len(fw_list) > 1:
            print(f'\n--- {fw_name} ---', file=sys.stderr)
        print(f"Compiling '{fw_name}' (id: {fw_id}) ...", file=sys.stderr)

        driver = CompilerDriver_nft(db)
        driver.wdir = args.DESTDIR
        driver.source_dir = str(Path(args.FILE).parent)
        driver.verbose = args.VERBOSE

        if args.OUTPUT:
            driver.file_name_setting = args.OUTPUT
        if args.IPV4:
            driver.ipv6_run = False
        elif args.IPV6:
            driver.ipv4_run = False
        if args.SINGLE_RULE:
            driver.single_rule_compile_on = True
            driver.single_rule_id = args.SINGLE_RULE
        if args.DEBUG_POLICY_RULE is not None:
            driver.debug_rule_policy = args.DEBUG_POLICY_RULE
        if args.DEBUG_NAT_RULE is not None:
            driver.debug_rule_nat = args.DEBUG_NAT_RULE
        if args.DEBUG_ROUTING_RULE is not None:
            driver.debug_rule_routing = args.DEBUG_ROUTING_RULE

        result = driver.run(cluster_id='', fw_id=fw_id, single_rule_id=args.SINGLE_RULE)

        if result:
            print(f'Compiler returned: {result}', file=sys.stderr)

        if driver.all_errors:
            compiled_err += 1
            for err in driver.all_errors:
                print(f'Error: {err}', file=sys.stderr)
        else:
            compiled_ok += 1

    elapsed = time.monotonic() - t_start
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)
    frac = elapsed - int(elapsed)
    print(
        f'Compile time: {hours:02d}:{minutes:02d}:{seconds:02d}.{int(frac * 1000):03d}',
        file=sys.stderr,
    )
    if len(fw_list) > 1:
        print(
            f'Result: {compiled_ok} succeeded, {compiled_err} failed '
            f'(out of {len(fw_list)})',
            file=sys.stderr,
        )

    return 1 if compiled_err else 0


if __name__ == '__main__':
    sys.exit(main())
