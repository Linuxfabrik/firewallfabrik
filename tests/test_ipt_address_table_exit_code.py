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

"""What the address table commands of an iptables script answer.

Every other branch of the generated script ends in ``RETVAL=$?``; the four
that maintain a run-time address table did not, so the script exited 0
whatever happened.  Measured on ``firewall41-1`` in a network namespace:
``test_address_table`` answered 0 for an address in the table and 0 for one
that is not, which is a question a monitoring check cannot ask, and a
reload from a file that does not exist reported success.

``reload_address_table`` could not have answered anyway.  It never asked
whether the file is readable - ``check_run_time_address_table_files`` does
that in the start branch alone - and it ended on ``ipset -X`` of a
temporary set, which succeeds whatever went wrong before it.  An address
ipset refuses was skipped without a word: the rule naming the table is
installed either way, so the firewall came up matching a block list quietly
missing however many addresses.
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

_FUNCTIONS_RE = re.compile(
    r'^reload_address_table\(\) \{.*?^test_address_table\(\) \{.*?^\}$',
    re.M | re.S,
)


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


def test_every_address_table_command_answers_with_its_status(tmp_path):
    script = _script(tmp_path)
    dispatch = script.split('case "$cmd" in', 1)[1]
    for command in (
        'reload_address_table',
        'add_to_address_table',
        'remove_from_address_table',
        'test_address_table',
    ):
        branch = dispatch.split(f'    {command})\n', 1)[1].split(';;', 1)[0]
        assert 'RETVAL=$?' in branch, command


@pytest.mark.skipif(not CAN_ASK_IPSET, reason=SKIP_REASON_IPSET)
def test_a_reload_says_what_it_could_not_load(tmp_path):
    script = _script(tmp_path)
    functions = _FUNCTIONS_RE.search(script)
    assert functions, 'the address table commands are no longer where the test looks'

    # A block list stitched together from several feeds lists an address
    # twice, which is not a line ipset could not read.
    good = tmp_path / 'good.tbl'
    good.write_text('198.51.100.1\n203.0.113.0/24\n198.51.100.1\n')
    # Three lines ipset refuses: a prefix hash:net has no room for, a
    # length out of range and text that is no address at all.
    mixed = tmp_path / 'mixed.tbl'
    mixed.write_text('198.51.100.1\n0.0.0.0/0\n192.0.2.0/33\nnot-an-address\n')

    harness = f"""
        IPSET=ipset
        {functions.group(0)}
        reload_address_table blk {good} -4 > /dev/null || exit 1
        # An address one of the table's networks covers is in the table:
        # 203.0.113.0/24 is in the file and this host is inside it.
        test_address_table blk 203.0.113.7 > /dev/null || exit 1
        reload_address_table blk /nonexistent.tbl -4 > /dev/null && exit 1
        reload_address_table blk {mixed} -4 > {tmp_path}/said.txt && exit 1
        test_address_table blk 198.51.100.1 > /dev/null || exit 1
        test_address_table blk 203.0.113.99 > /dev/null && exit 1
        add_to_address_table blk {good} 198.51.100.1 > /dev/null || exit 1
        echo ANSWERED
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'ANSWERED' in proc.stdout
    said = (tmp_path / 'said.txt').read_text()
    assert '3 of the addresses' in said, said
