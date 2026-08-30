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

"""A firewall that shares the machine restores without flushing.

`iptables-restore` empties every chain of a table and deletes every user
chain in it before it reads the first rule (netfilter
iptables/iptables-restore.c, the ``noflush == 0`` branch).  On a firewall
whose "flush the ruleset" setting is off - the coexistence mode that
exists so Docker, CrowdSec and fail2ban keep their rules - that is
exactly what must not happen: it takes the other tools' rules with it and
the ``fwf_*`` chains `setup_fwf_jumps` has just created along with them,
so the very next line, an ``-A fwf_INPUT``, answers "No chain/target/match
by that name" and the activation stops with the built-in policies already
at DROP.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'basic_accept_deny.fwf'


def _compile(tmp_path, version=None, **options):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    with dm.session() as session:
        fw = session.scalars(sqlalchemy.select(Firewall)).one()
        stored = dict(fw.options or {})
        stored.update(options)
        fw.options = stored
        if version is not None:
            data = dict(fw.data or {})
            data['version'] = version
            fw.data = data
        fw_id = str(fw.id)
    driver = CompilerDriver_ipt(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw.fw').read_text()


@pytest.fixture
def restore_line():
    def _line(script):
        return next(
            line.strip()
            for line in script.splitlines()
            if 'IPTABLES_RESTORE_RES=$?' in line
        )

    return _line


def test_a_coexisting_firewall_restores_with_noflush(tmp_path, restore_line):
    script = _compile(tmp_path, use_iptables_restore=True, flush_ruleset=False)
    assert restore_line(script) == (
        ') | $IPTABLES_RESTORE -w 5 --noflush; IPTABLES_RESTORE_RES=$?'
    )
    # The chains the restore stream appends to are the ones
    # `setup_fwf_jumps` creates, and only --noflush leaves them there.
    assert 'echo "-A fwf_INPUT' in script


def test_a_flushing_firewall_restores_the_whole_table(tmp_path, restore_line):
    script = _compile(tmp_path, use_iptables_restore=True, flush_ruleset=True)
    assert restore_line(script) == (
        ') | $IPTABLES_RESTORE -w 5; IPTABLES_RESTORE_RES=$?'
    )


def test_the_restore_waits_for_the_xtables_lock(tmp_path, restore_line):
    """Every `iptables` command of the script waits; the restore too.

    The option reached the restore programs in v1.6.2, later than the
    command, so a firewall pinned to an older release gets none of it
    (netfilter iptables/iptables-restore.c).
    """
    script = _compile(tmp_path, use_iptables_restore=True, version='1.6.2')
    assert '-w 5' in restore_line(script)

    script = _compile(tmp_path, use_iptables_restore=True, version='1.6.1')
    assert '-w' not in restore_line(script)
