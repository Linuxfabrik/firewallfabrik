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

"""Which routing table the rollback block saves, clears and puts back.

``ip route`` is the IPv4 table and nothing else.  Firewall Builder never
had to say so, because its routing pipeline drops a rule naming an IPv6
object with a warning (``DropIPv6RulesWithWarning``) and compiles no IPv6
route at all.  This compiler does compile them and writes ``ip -6 route
add``, so the block around them has to name the other table as well.

Without that the first activation works and every one after it fails: the
route is still there, ``ip -6 route add`` answers "RTNETLINK answers: File
exists", and the ``|| route_command_error`` behind it puts the IPv4 table
back and stops the script with a non-zero status - the packet filter
already installed, the epilog never run.

The other direction matters just as much.  A script that installs no IPv6
route must not touch the IPv6 table: those routes belong to whatever else
runs on the box.
"""

from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURES = Path(__file__).parent / 'fixtures'

#: The three commands that have to name the family, one per step.
IPV6_STEPS = (
    '"$IP" -6 route show | sort -k 2 |',
    '"$IP" -6 route show | grep -v ',
    '"$IP" -6 route show | while read -r route ;',
)


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
def test_a_script_installing_an_ipv6_route_clears_the_ipv6_table_first(
    tmp_path, driver_class
):
    script = _compile(tmp_path, 'firewall36', driver_class)

    assert '$IP -6 route add ' in script
    for step in IPV6_STEPS:
        assert step in script, step
    # The table is saved before the first route command touches anything,
    # and it is appended to the same file the IPv4 half is restored from.
    assert 'ip -6 route add %s' in script
    assert script.index('>> "$OLD_ROUTES"') < script.index('$IP -6 route add ')


@pytest.mark.parametrize(
    'driver_class', [CompilerDriver_ipt, CompilerDriver_nft], ids=['ipt', 'nft']
)
def test_a_script_with_no_ipv6_route_leaves_the_ipv6_table_alone(
    tmp_path, driver_class
):
    script = _compile(tmp_path, 'firewall36-1', driver_class)

    assert '$IP route add ' in script
    assert '$IP -6 route add ' not in script
    for step in IPV6_STEPS:
        assert step not in script, step
