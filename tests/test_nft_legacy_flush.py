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

"""The nftables script clears legacy iptables rules without creating any.

With "flush ruleset" the script also removes rules a previous policy left
in the legacy (xtables) backend, which `nft flush ruleset` cannot see.
Two ways of doing that leave something behind:

- Calling `iptables` / `ip6tables`: where they are iptables-nft, they
  recreate the "ip filter" and "ip6 filter" tables right after `nft flush
  ruleset` removed them.
- Calling the legacy binaries unconditionally: that loads the ip_tables /
  ip6_tables kernel modules on a machine that never had a legacy rule, and
  Lynis reports FIRE-4512 "iptables module(s) loaded, but no rules active".

Both were reproduced on Rocky Linux 9 (iptables 1.8.10, Lynis 3.1.7). The
function is run here with stub binaries that record their calls, once with
and once without the /proc file the kernel offers while legacy tables
exist.
"""

import copy
import os
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

from .conftest import FIXTURES_DIR

FIXTURE = FIXTURES_DIR / 'compiler-tests.fwf'
FIREWALL = 'fw-nat'
STUBS = ('ip6tables', 'ip6tables-legacy', 'iptables', 'iptables-legacy')


@pytest.fixture(scope='module')
def flush_function(tmp_path_factory) -> str:
    tmp_path = tmp_path_factory.mktemp('nft-legacy-flush')
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURE))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == FIREWALL)
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['flush_ruleset'] = True
        fw.options = options
        fw_id = str(fw.id)

    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = f'{FIREWALL}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    lines = (tmp_path / f'{FIREWALL}.fw').read_text().splitlines()

    start = lines.index('flush_legacy_iptables() {')
    end = lines.index('}', start)
    return '\n'.join(lines[start : end + 1])


def _run(flush_function: str, tmp_path: Path, *, legacy_tables: bool) -> list[str]:
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    log = tmp_path / 'calls'
    for name in STUBS:
        stub = bin_dir / name
        stub.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\n')
        stub.chmod(0o755)

    proc_net = tmp_path / 'proc-net'
    proc_net.mkdir()
    if legacy_tables:
        (proc_net / 'ip_tables_names').write_text('filter\n')
        (proc_net / 'ip6_tables_names').write_text('filter\n')
    function = flush_function.replace('/proc/net/', f'{proc_net}/')
    assert function != flush_function

    env = {**os.environ, 'PATH': f'{bin_dir}:/usr/bin:/bin'}
    subprocess.run(  # nosec B603 B607
        ['sh', '-c', f'{function}\nflush_legacy_iptables'],
        check=True,
        env=env,
    )
    return log.read_text().splitlines() if log.exists() else []


def test_no_legacy_tables_means_no_call(flush_function, tmp_path):
    """Asking the legacy backend would load its kernel modules."""
    assert _run(flush_function, tmp_path, legacy_tables=False) == []


def test_legacy_tables_are_cleared(flush_function, tmp_path):
    calls = _run(flush_function, tmp_path, legacy_tables=True)
    for ipt in ('iptables-legacy', 'ip6tables-legacy'):
        assert f'{ipt} -P INPUT ACCEPT' in calls
        assert f'{ipt} -t filter -F' in calls
        assert f'{ipt} -t raw -X' in calls


def test_the_alternatives_name_is_never_called(flush_function, tmp_path):
    """`iptables` may be iptables-nft and recreate the "ip filter" table."""
    calls = _run(flush_function, tmp_path, legacy_tables=True)
    assert calls
    assert not any(call.split()[0] in ('iptables', 'ip6tables') for call in calls)
