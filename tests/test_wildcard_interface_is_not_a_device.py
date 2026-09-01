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

"""A wildcard interface name stands for a set, not for a device.

Firewall Builder stores the wildcard as ``*``, iptables spells it ``+``,
and both print rules translate the one into the other when they write a
rule - so a data file may carry either and both mean the same thing.  The
interface block knew only ``*``, so an interface named ``vnet+``:

* was handed to ``verify_interfaces``, where ``ip link show vnet+`` fails
  and the script answers "Interface vnet+ does not exist" and ``exit 1``
  - the firewall could not activate at all; and
* was handed to ``getaddr``, which writes a shell variable from an
  interface that is not there, so the rules built around that variable
  matched nothing.

It stays in the list "clear IP addresses of unknown interfaces" spares,
because that list is matched by prefix and the interfaces it stands for
are the firewall's own.

`objects-for-regression-tests.fwb` carries the name: firewall23-2 and
firewall23-3 bridge over `vnet+`.
"""

from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall

FIXTURE = Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
FIREWALL = 'firewall23-2'
WILDCARD = 'vnet+'


def _compile_with_options(platform, tmp_path, options):
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURE))

    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == FIREWALL),
        ).scalar_one()
        fw.options = {**(fw.options or {}), **options}
        fw_id = str(fw.id)

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
def test_a_wildcard_interface_is_not_verified_or_asked_for_its_address(
    platform, tmp_path
):
    script = _compile_with_options(
        platform,
        tmp_path,
        {
            'configure_interfaces': True,
            'verify_interfaces': True,
            'clear_unknown_interfaces': True,
        },
    )
    verify = next(
        line for line in script.splitlines() if 'Verifying interfaces:' in line
    )
    assert WILDCARD not in verify
    assert f'getaddr {WILDCARD}' not in script
    assert f'update_addresses_of_interface "{WILDCARD}' not in script
    # But the "unknown interfaces" list still names it: that one is
    # matched by prefix, and vnet0 is the firewall's own port.
    spare = next(
        line
        for line in script.splitlines()
        if 'clear_addresses_except_known_interfaces "' in line
    )
    assert WILDCARD in spare
