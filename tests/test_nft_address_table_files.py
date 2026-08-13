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

"""When the generated nftables script asks whether it can read its data files.

The elements of an address table set come from a file on this machine.  A
file that cannot be read leaves the set empty, and a set no packet is in
turns a Deny rule into one that blocks nothing and an Accept rule into one
that lets nothing through.

The iptables script has asked before it flushes since fwbuilder wrote it
(configlet run_time_address_tables, check_run_time_address_table_files run
ahead of reset_all).  The nftables script only found out inside the loader,
which runs after the ruleset is installed: the firewall was already up on
the empty sets and the script left without running its epilog.
"""

from pathlib import Path

import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURES = Path(__file__).parent / 'fixtures'


def _compile(tmp_path, fw_name='firewall34'):
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
    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = f'{fw_name}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


def test_the_files_are_checked_before_the_running_ruleset_is_replaced(tmp_path):
    script = _compile(tmp_path)
    assert 'check_address_table_file "block_these" "block-hosts.tbl"' in script

    body = script.split('    start)', 1)[1]
    check = body.index('check_address_table_files')
    assert check < body.index('stop_action'), 'checked after the flush'
    assert check < body.index('check_ruleset'), 'checked after the ruleset is built'


def test_the_loader_no_longer_ends_the_script_from_inside(tmp_path):
    """A file that disappears between the check and the load must not exit.

    By then the ruleset is installed, so leaving through `exit` skips the
    epilog and the administrator's own commands never run.
    """
    script = _compile(tmp_path)
    loader = script.split('load_address_table() {', 1)[1].split('\n}', 1)[0]
    assert 'return 1' in loader
    assert 'exit 1' not in loader


def test_the_script_answers_an_unknown_command_the_way_iptables_does(tmp_path):
    """`exit ""` is not an exit code.

    Every branch of the case is expected to leave one in RETVAL, and the
    usage branch left none: the script ended in `exit ""`, which the shell
    answers with "numeric argument required" and a code of its own.  The
    iptables skeleton has had the initialisation and the `RETVAL=1` since
    fwbuilder wrote it.
    """
    script = _compile(tmp_path)
    assert '\nRETVAL=0\n' in script
    usage = script.split('        echo "Usage $0 ', 1)[1]
    assert 'RETVAL=1' in usage.split(';;', 1)[0]
