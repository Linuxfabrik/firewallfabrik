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

"""How many addresses an address table may hold on iptables.

A run-time address table is matched with ``-m set --match-set``, and the
set behind it is an ipset the generated script fills from a file.  A hash
set holds ``IPSET_DEFAULT_MAXELEM`` elements, which is 65536 (ipset
``kernel/include/linux/netfilter/ipset/ip_set_hash.h``), and the kernel
answers every address after that with ``-IPSET_ERR_HASH_FULL``.  The script
adds one address per ``ipset -A`` and checks none of them, so a block list
longer than that blocked its first 65536 addresses and none of the rest,
while the activation reported success.

The set is therefore created with room for the file it is filled from.  The
size is taken from the file's line count, not from the number of addresses
that end up in this particular set: the file may hold both address families
and each set takes only its own, so the count is an upper bound, and the
headroom is what ``add_to_address_table`` needs later.
"""

import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from tests.tool_probe import CAN_ASK_IPSET, SKIP_REASON_IPSET

FIXTURES = Path(__file__).parent / 'fixtures'

# Past the default ceiling, so the computed size has to differ from it.
LINE_COUNT = 70000
EXPECTED_MAXELEM = 131072

_FUNCTION_RE = re.compile(r'^reload_address_table\(\) \{.*?^\}$', re.M | re.S)


def _script(tmp_path, fw_name='firewall41-1'):
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
    driver = CompilerDriver_ipt(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = f'{fw_name}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


def test_the_set_is_sized_from_the_file(tmp_path):
    """The static half, so the reason survives without the tools."""
    script = _script(tmp_path)
    assert 'maxelem $set_maxelem' in script
    assert 'set_maxelem=$((set_maxelem * 2))' in script


@pytest.mark.skipif(not CAN_ASK_IPSET, reason=SKIP_REASON_IPSET)
def test_a_file_of_seventy_thousand_lines_gets_a_set_that_holds_them(tmp_path):
    script = _script(tmp_path)
    function = _FUNCTION_RE.search(script)
    assert function, 'reload_address_table is no longer where the test looks'

    # A dual-stack block list, loaded for IPv4: the file is long, and the
    # addresses that reach this set are few, so the capacity is decided by
    # the file and the test does not spend a minute on `ipset -A`.
    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text(
        ''.join(f'2001:db8::{i:x}\n' for i in range(LINE_COUNT - 2))
        + '198.51.100.1\n203.0.113.0/24\n'
    )

    harness = f"""
        IPSET=ipset
        {function.group(0)}
        reload_address_table block_these {data_file} -4 > /dev/null || exit 1
        ipset list block_these:ip | sed -n 's/^Header: //p'
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    assert f'maxelem {EXPECTED_MAXELEM}' in proc.stdout, proc.stdout
