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

"""A rate limit table is shared across rule sets, so the check has to be too.

Every rule set and every table pass is compiled by a compiler of its own,
while the object the rules name is one per firewall: iptables looks a hash
table up by its name and family alone (net/netfilter/xt_hashlimit.c,
htable_find_get) and hands the existing one back with its configuration, so
the second rule counts into the first one's buckets at the first one's rate.
A registry that lives on the compiler cannot see that, which is why the
driver hands one dict to every instance.

test-shadowing-3 is the fixture that shows it: its rule sets Policy_2,
Policy_3 and Policy_4 each cap one table named "test" at a different rate.
"""

from pathlib import Path

import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

FIXTURES = Path(__file__).parent / 'fixtures'


def _compile(tmp_path):
    db = DatabaseManager()
    db.load(str(FIXTURES / 'objects-for-regression-tests.fwb'))
    with db.session() as session:
        fw_id = str(
            session.execute(
                sqlalchemy.select(Firewall).where(Firewall.name == 'test-shadowing-3'),
            )
            .scalar_one()
            .id
        )
    driver = CompilerDriver_ipt(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = 'test-shadowing-3.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return driver


def test_a_table_reused_by_a_second_rule_set_is_reported(tmp_path):
    driver = _compile(tmp_path)
    reported = {
        warning.split(':')[1]
        for warning in driver.all_warnings
        if 'rate limit table "test"' in warning
    }
    assert {'Policy_3', 'Policy_4', 'Policy_5'} <= reported, driver.all_warnings
