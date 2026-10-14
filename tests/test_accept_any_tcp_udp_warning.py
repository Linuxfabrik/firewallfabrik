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

"""An Accept rule naming a TCP or UDP service that names no port (#194).

A service whose source and destination ports are all 0 matches every port
of its protocol.  That is how "any TCP port" is written, and the Standard
library's All TCP and All UDP exist for it, but a new TCP service starts
out with port 0, so a forgotten port accepts all TCP traffic.  Both
compilers warn about it and still compile.
"""

from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = Path(__file__).parent / 'fixtures' / 'accept_any_tcp_udp_warning.fwf'

MATCHING = 'matches ALL'


def _warnings(driver_class, tmp_path) -> list[str]:
    db = DatabaseManager()
    db.load(str(FIXTURE))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test'),
        ).scalar_one()
        fw_id = str(fw.id)
    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = 'out.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    assert not driver.all_errors
    return [w for w in driver.all_warnings if MATCHING in w]


@pytest.mark.parametrize('driver_class', [CompilerDriver_ipt, CompilerDriver_nft])
def test_only_a_user_service_in_an_accept_rule_is_reported(driver_class, tmp_path):
    warnings = _warnings(driver_class, tmp_path)
    joined = '\n'.join(warnings)

    # A, D and F: user services with every port 0, in Accept rules.
    assert 'Service "web" matches ALL TCP ports' in joined
    assert 'Service "All TCP" matches ALL TCP ports' in joined
    assert 'Service "forgotten-udp" matches ALL UDP ports' in joined
    assert len(warnings) == 3

    # The rule is named, so the administrator can find it.
    assert any(':0: warning:' in w for w in warnings if '"web"' in w)
