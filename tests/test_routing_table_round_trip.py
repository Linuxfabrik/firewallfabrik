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

"""Does the routing table the script saves come back the way it went in?

`route_command_error` exists to keep a firewall reachable when a route
fails to install: it puts back the table the script found.  The table is
saved by reading `ip route show` line by line, and a route with several
next hops is not one line there - it is `default` followed by one
indented `nexthop ...` line per hop.  Read that way it becomes three
commands: a default route with no next hop at all, which iproute2
refuses, and two fragments that are no route.

So the rollback of a box carrying an equal-cost default route left it
with no default route, and the delete loop in front of the rules answered
each fragment with a forty-line usage dump in the activation output.
`ip -o` puts each route on one line, which is what both loops read.

This compiler installs such routes itself - `ClassifyRoutingRules` turns
two rules with the same destination and metric into one `nexthop ...`
command - so the shape is not hypothetical.
"""

import subprocess  # nosec B404
import textwrap
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import CAN_ASK_IPROUTE2, SKIP_REASON_IPROUTE2

FIXTURES = Path(__file__).parent / 'fixtures'


def _compile(tmp_path, fw_name, driver_class):
    db = DatabaseManager()
    db.load(str(FIXTURES / 'objects-for-regression-tests.fwb'))
    with db.session() as session:
        fw_id = str(
            session.execute(
                sqlalchemy.select(Firewall).where(Firewall.name == fw_name),
            )
            .scalar_one()
            .id
        )
    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = f'{fw_name}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / f'{fw_name}.fw').read_text()


@pytest.mark.parametrize(
    'driver_class', [CompilerDriver_ipt, CompilerDriver_nft], ids=['ipt', 'nft']
)
def test_every_reader_of_the_routing_table_takes_one_route_per_line(
    tmp_path, driver_class
):
    script = _compile(tmp_path, 'firewall36', driver_class)

    # A reader that forgets the option is the one that breaks the
    # rollback, so every one of them is asked.
    readers = 0
    for line in script.splitlines():
        if '"$IP"' not in line or 'route show' not in line:
            continue
        readers += 1
        assert '-o route show' in line or '-o -6 route show' in line, line
        assert "tr -d '\\134'" in line, line
    # Three in the IPv4 table and three in the IPv6 one; this firewall
    # installs a route in both.
    assert readers == 6


@pytest.mark.skipif(not CAN_ASK_IPROUTE2, reason=SKIP_REASON_IPROUTE2)
def test_a_route_with_several_next_hops_survives_save_and_restore():
    """The property, asked of real iproute2 rather than of the text."""
    script = textwrap.dedent("""
        set -u
        ip link add eth0 type dummy && ip link set eth0 up
        ip link add eth1 type dummy && ip link set eth1 up
        ip addr add 192.0.2.1/24 dev eth0
        ip addr add 198.51.100.1/24 dev eth1
        sleep 1
        ip route add default \
            nexthop via 192.0.2.100 dev eth0 \
            nexthop via 198.51.100.100 dev eth1
        before=$(ip route show)
        # What the configlet writes, both loops.
        ip -o route show | tr -d '\\134' | sort -k 2 |
            awk '{printf "ip route add %s\\n",$0;}' > /tmp/old_routes
        ip -o route show | tr -d '\\134' |
            while read -r route ; do ip route del $route ; done
        sh /tmp/old_routes
        after=$(ip route show)
        test "$before" = "$after" || { echo "TABLE CHANGED"; exit 1; }
        echo OK
    """)
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', script],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip().endswith('OK'), proc.stdout
    # Not one line of the usage dump iproute2 answers a fragment with.
    assert 'Usage: ip route' not in proc.stderr, proc.stderr
