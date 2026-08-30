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

"""The sets an address table matches against exist before a rule names one.

A rule naming an address table says `-m set --match-set <name> src`, and
iptables refuses that rule outright when no set of that name is there:
"Set <name> doesn't exist".  The rule is then simply absent from a ruleset
the script reports as activated, and ipsets do not survive a reboot - so
the first activation after one loses every such rule and the second gets
them back from the sets the first left behind.

Measured with real iptables and ipset in a private network namespace on
`firewall41-1`, whose 17 `-m set` rules all reached the ruleset with the
sets filled first and none of them with `script_body` first.
"""

from pathlib import Path

import pytest

from .conftest import FIXTURES_DIR, _compile

FIXTURE = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

# The only firewall of the corpus that switches "Use module set" on.
FIREWALL = 'firewall41-1'


@pytest.fixture(scope='module')
def start_branch(tmp_path_factory) -> list[str]:
    tmp_path = tmp_path_factory.mktemp('ipset-order')
    script = _compile(FIXTURE, FIREWALL, tmp_path, 'ipt')
    lines = Path(script).read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == 'start)')
    end = next(i for i, line in enumerate(lines[start:], start) if line.strip() == ';;')
    return [line.strip() for line in lines[start:end]]


def _index(branch: list[str], call: str) -> int:
    return branch.index(call)


def test_the_sets_are_filled_before_the_rules_name_them(start_branch):
    assert _index(start_branch, 'load_run_time_address_table_files') < _index(
        start_branch, 'script_body || run_epilog_and_exit 1'
    )


def test_the_data_files_are_checked_before_they_are_read(start_branch):
    """A file that cannot be read ends the run before the firewall moves."""
    assert _index(start_branch, 'check_run_time_address_table_files') < _index(
        start_branch, 'load_run_time_address_table_files'
    )


def test_the_module_is_checked_before_the_sets_are_filled(start_branch):
    assert _index(start_branch, 'check_module_ipset') < _index(
        start_branch, 'load_run_time_address_table_files'
    )


def test_it_is_filled_once(start_branch):
    assert start_branch.count('load_run_time_address_table_files') == 1
