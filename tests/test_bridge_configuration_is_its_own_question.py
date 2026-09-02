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

""" "Configure bridge interfaces" does not depend on "Configure interfaces".

They are two settings and Firewall Builder asks them separately
(`CompilerDriver_ipt::run`, CompilerDriver_ipt_run.cpp:557-573: the
bonding, VLAN and bridge blocks each stand on their own `if`, and the
address block follows them).  A firewall whose addresses are managed by
something else - NetworkManager, systemd-networkd, cloud-init - can still
be the one that builds its bridges.

The nftables driver nested the bridge block inside the address block, so
that firewall got its bridges on iptables and nothing on nftables.
"""

from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

from .test_bridge_before_addresses import give_the_vlan_interface_an_address

FIXTURE = Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'
FIREWALL = 'gw1-bridge'


def _compile_with_options(platform, tmp_path, options):
    """Compile *FIREWALL* after forcing *options* onto it."""
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURE))

    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == FIREWALL),
        ).scalar_one()
        fw.options = {**(fw.options or {}), **options}
        fw_id = str(fw.id)
        give_the_vlan_interface_an_address(session)

    if platform == 'ipt':
        from firewallfabrik.platforms.iptables._compiler_driver import (
            CompilerDriver_ipt as driver_cls,
        )
    else:
        from firewallfabrik.platforms.nftables._compiler_driver import (
            CompilerDriver_nft as driver_cls,
        )

    driver = driver_cls(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = f'{FIREWALL}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
def test_bridges_are_built_although_addresses_are_managed_elsewhere(platform, tmp_path):
    script = _compile_with_options(
        platform,
        tmp_path,
        {'configure_interfaces': False, 'configure_bridge_interfaces': True},
    )
    assert 'sync_bridge_interfaces br1' in script
    assert 'update_bridge br1 ' in script
    # The addresses stay where the administrator put them.
    assert 'update_addresses_of_interface "br1' not in script
