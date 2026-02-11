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

"""CLI entry point for the iptables compiler (port of C++ ipt.cpp)."""

import argparse
import sys
import time

import sqlalchemy

import firewallfabrik
import firewallfabrik.core
import firewallfabrik.core.objects

__author__ = 'Linuxfabrik GmbH, Zurich/Switzerland'

DESCRIPTION = """FirewallFabrik policy compiler for iptables. Loads a firewall object database and
compiles iptables rules for the specified firewall."""

DEFAULT_DESTDIR = '.'


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='fwf-ipt',
        description=DESCRIPTION,
    )

    parser.add_argument(
        'firewall_name',
        help='name (or ID if -i is given) of the firewall object to compile',
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

    parser.add_argument(
        '-D',
        '--datadir',
        default='',
        dest='DATADIR',
        help='data directory (resources/templates)',
    )

    parser.add_argument(
        '-i',
        '--id',
        action='store_true',
        dest='FW_BY_ID',
        help='look up firewall by object ID instead of name',
    )

    parser.add_argument(
        '-o',
        '--output',
        default='',
        dest='OUTPUT',
        help='output file name override',
    )

    parser.add_argument(
        '-O',
        '--member-files',
        default='',
        dest='MEMBER_FILES',
        help='comma-separated list of member_id,filename pairs '
        'for cluster member output files',
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
        '--xc',
        action='store_true',
        dest='DEBUG_CLUSTER_NAME',
        help='prepend cluster name to output file',
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

    parser.add_argument(
        '--xt',
        action='store_true',
        dest='TEST_MODE',
        help='test mode (fatal errors treated as warnings)',
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
    t_start = time.monotonic()

    print(f'Loading database from {args.FILE} ...', file=sys.stderr)

    try:
        db = firewallfabrik.core.DatabaseManager()
        db.load(args.FILE)
    except Exception as e:
        print(f'Error: failed to load database from {args.FILE}: {e}', file=sys.stderr)
        return 1

    # Verify firewall exists
    with db.session() as session:
        if args.FW_BY_ID:
            firewall = session.execute(
                sqlalchemy.select(firewallfabrik.core.objects.Firewall).where(
                    firewallfabrik.core.objects.Firewall.id == args.firewall_name
                ),
            ).scalar_one_or_none()
        else:
            firewall = session.execute(
                sqlalchemy.select(firewallfabrik.core.objects.Firewall).where(
                    firewallfabrik.core.objects.Firewall.name == args.firewall_name
                ),
            ).scalar_one_or_none()

        if firewall is None:
            label = 'id' if args.FW_BY_ID else 'name'
            print(
                f"Error: firewall with {label} '{args.firewall_name}' not found in {args.FILE}",
                file=sys.stderr,
            )
            return 1

        fw_id = str(firewall.id)
        print(f"Found firewall '{firewall.name}' (id: {fw_id})", file=sys.stderr)

    # Create compiler driver and run compilation
    from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

    driver = CompilerDriver_ipt(db)
    driver.wdir = args.DESTDIR
    driver.verbose = args.VERBOSE
    driver.prepend_cluster_name = args.DEBUG_CLUSTER_NAME
    driver.test_mode = args.TEST_MODE

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

    print('Compiling ...', file=sys.stderr)
    result = driver.run(cluster_id='', fw_id=fw_id, single_rule_id=args.SINGLE_RULE)

    if result:
        print(f'Compiler returned: {result}', file=sys.stderr)

    if driver.all_errors:
        for err in driver.all_errors:
            print(err, file=sys.stderr)

    elapsed = time.monotonic() - t_start
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f'Compile time: {hours:02d}:{minutes:02d}:{seconds:02d}', file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
