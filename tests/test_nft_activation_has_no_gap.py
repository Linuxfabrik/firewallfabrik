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

"""The nftables activation never leaves the machine without a firewall.

nft loads a ruleset atomically and the generated one deletes and
recreates each of its own tables in that same transaction, so their rules
are never missing for an instant.  Removing the old rules first undoes
exactly that: a table that is gone hooks nothing, every packet goes
through, and the machine has no firewall at all until the load finishes.

The iptables side has no such gap - `reset_iptables_v4` sets the three
built-in policies to DROP before it flushes anything - and what makes the
two agree is that everything the new ruleset did not install is removed
*after* it is in place.

Verified with a real kernel in a private network namespace: with a
foreign table and a stale table of our own present beforehand, the
foreign one survives a coexistence run and goes in a "flush ruleset" one,
and the stale one goes in both.
"""

import copy
import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

from .conftest import FIXTURES_DIR

FIXTURE = FIXTURES_DIR / 'compiler-tests.fwf'
FIREWALL = 'fw-nat'


def _compile(tmp_path: Path, *, flush_ruleset: bool) -> list[str]:
    db = firewallfabrik.core.DatabaseManager()
    db.load(str(FIXTURE))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == FIREWALL)
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['flush_ruleset'] = flush_ruleset
        fw.options = options
        fw_id = str(fw.id)

    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = f'{FIREWALL}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / f'{FIREWALL}.fw').read_text().splitlines()


def _start_branch(lines: list[str]) -> list[str]:
    start = next(i for i, line in enumerate(lines) if line.strip() == 'start)')
    end = next(i for i, line in enumerate(lines[start:], start) if line.strip() == ';;')
    return [line.strip() for line in lines[start:end]]


@pytest.fixture(scope='module')
def flushing(tmp_path_factory) -> list[str]:
    return _compile(tmp_path_factory.mktemp('nft-flush'), flush_ruleset=True)


@pytest.fixture(scope='module')
def coexisting(tmp_path_factory) -> list[str]:
    return _compile(tmp_path_factory.mktemp('nft-coexist'), flush_ruleset=False)


@pytest.mark.parametrize('which', ('flushing', 'coexisting'))
def test_the_old_rules_go_after_the_new_ones_are_in(which, request):
    branch = _start_branch(request.getfixturevalue(which))
    assert branch.index('script_body || run_epilog_and_exit 1') < branch.index(
        'remove_other_tables'
    )


@pytest.mark.parametrize('which', ('flushing', 'coexisting'))
def test_nothing_is_torn_down_before_the_load(which, request):
    """`stop_action` empties the ruleset; it belongs to `stop`, not `start`."""
    branch = _start_branch(request.getfixturevalue(which))
    assert 'stop_action' not in branch
    assert not any('flush ruleset' in line for line in branch)


@pytest.mark.parametrize('which', ('flushing', 'coexisting'))
def test_the_ruleset_is_checked_before_it_is_loaded(which, request):
    branch = _start_branch(request.getfixturevalue(which))
    assert branch.index('check_ruleset || {') < branch.index(
        'script_body || run_epilog_and_exit 1'
    )


@pytest.mark.parametrize('which', ('flushing', 'coexisting'))
def test_every_table_the_ruleset_installs_is_named(which, request):
    """Or the pass that follows the load would delete what it just made."""
    lines = request.getfixturevalue(which)
    declared = {
        f'table {m.group(1)} {m.group(2)}'
        for m in (
            re.match(r'^delete table (\S+) (\S+)$', line.strip()) for line in lines
        )
        if m
    }
    listed = _own_tables(lines)
    assert declared
    assert declared == listed


def test_a_foreign_table_is_left_alone_when_coexisting(coexisting):
    body = _remove_function(coexisting)
    assert 'case $line in' in body


def test_a_foreign_table_goes_when_the_ruleset_is_flushed(flushing):
    """"Flush ruleset" means everything else, the way `nft flush ruleset` did."""
    body = _remove_function(flushing)
    assert 'case $line in' not in body
    assert 'flush_legacy_iptables' in body


def _own_tables(lines: list[str]) -> set[str]:
    start = next(
        i for i, line in enumerate(lines) if line.startswith("FWF_OWN_TABLES='")
    )
    collected = [lines[start].split("'", 1)[1]]
    while not collected[-1].endswith("'"):
        start += 1
        collected.append(lines[start])
    collected[-1] = collected[-1][:-1]
    return {line for line in collected if line}


def _stale_table(lines: list[str]) -> str:
    """A table of ours this ruleset does not install: the mangle one.

    `fw-nat` has no rule that tags or classifies, so its ruleset carries
    no mangle table and a leftover one from an earlier policy is exactly
    what the pass after the load has to clear away.
    """
    filter_table = next(
        name.split()[-1] for name in _own_tables(lines) if name.endswith('_filter')
    )
    return filter_table.removesuffix('_filter') + '_mangle'


def _remove_function(lines: list[str]) -> str:
    start = lines.index('remove_other_tables() {')
    end = next(i for i, line in enumerate(lines[start:], start) if line == '}')
    return '\n'.join(lines[start : end + 1])


# The script's own definitions, with everything it would reach outside the
# namespace replaced.  `sed` cuts the command dispatch off, the way
# `replay-iptables.sh` does.
_DRIVER = """
eval "$(sed -e '/^# See how we were called/,$d' {script})"
NFT=$(command -v nft)
IP=$(command -v ip)
log() {{ :; }}
check_tools() {{ :; }}
prolog_commands() {{ :; }}
epilog_commands() {{ :; }}
configure_interfaces() {{ :; }}
verify_interfaces() {{ :; }}
ip_forward() {{ :; }}
run_epilog_and_exit() {{ exit "$1"; }}
$NFT add table inet a_foreign_tool
$NFT add table inet {stale}
check_ruleset >/dev/null 2>&1 || {{ echo CHECK-FAILED; exit 1; }}
script_body >/dev/null 2>&1 || {{ echo LOAD-FAILED; exit 1; }}
remove_other_tables
$NFT list tables
"""


def _tables_after_activation(tmp_path: Path, *, flush_ruleset: bool) -> set[str]:
    lines = _compile(tmp_path, flush_ruleset=flush_ruleset)
    script = tmp_path / f'{FIREWALL}.fw'
    driver = tmp_path / 'driver.sh'
    driver.write_text(_DRIVER.format(script=script, stale=_stale_table(lines)))
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'bash', str(driver)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert 'FAILED' not in proc.stdout, proc.stdout + proc.stderr
    return {line.strip() for line in proc.stdout.splitlines() if line.startswith('table')}


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_a_real_kernel_keeps_the_foreign_table_when_coexisting(tmp_path):
    tables = _tables_after_activation(tmp_path, flush_ruleset=False)
    assert 'table inet a_foreign_tool' in tables
    assert not any(name.endswith('_mangle') for name in tables)


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_a_real_kernel_drops_the_foreign_table_when_flushing(tmp_path):
    tables = _tables_after_activation(tmp_path, flush_ruleset=True)
    assert 'table inet a_foreign_tool' not in tables
    assert not any(name.endswith('_mangle') for name in tables)


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
@pytest.mark.parametrize('flush', (True, False))
def test_a_real_kernel_installs_every_table_the_ruleset_names(tmp_path, flush):
    lines = _compile(tmp_path, flush_ruleset=flush)
    tables = _tables_after_activation(tmp_path, flush_ruleset=flush)
    assert _own_tables(lines) <= tables
