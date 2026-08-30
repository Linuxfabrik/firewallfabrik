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

""" "reload" does not take the firewall down on its way to putting it up.

Firewall Builder writes `$0 stop` and `$0 start` into the reload branch.
The stop leaves an iptables machine with no rules and its three built-in
policies at ACCEPT, and an nftables one with no ruleset at all - measured
in a private network namespace - and the start that follows is a second
process that has to read its address tables, load its modules and
configure its interfaces before it installs anything.

Neither platform needs it.  The iptables start branch goes through the
same `reset_all` the stop does, and the nftables ruleset deletes and
recreates each of its own tables in one transaction, keeping the running
firewall when `check_ruleset` refuses the new one.
"""

from pathlib import Path

import pytest

from .conftest import FIXTURES_DIR, _compile

FIXTURE = FIXTURES_DIR / 'basic_accept_deny.fwf'
FIREWALL = 'fw-test'


def _reload_branch(script: str) -> str:
    lines = script.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == 'reload)')
    end = next(i for i, line in enumerate(lines[start:], start) if line.strip() == ';;')
    return '\n'.join(lines[start : end + 1])


@pytest.fixture(scope='module', params=['ipt', 'nft'])
def reload_branch(request, tmp_path_factory) -> str:
    tmp_path = tmp_path_factory.mktemp(f'reload-{request.param}')
    script = Path(_compile(FIXTURE, FIREWALL, tmp_path, request.param)).read_text()
    return _reload_branch(script)


def test_reload_does_not_stop_the_firewall_first(reload_branch):
    assert '$0 stop' not in reload_branch


def test_reload_still_activates(reload_branch):
    assert '$0 start' in reload_branch
    assert 'RETVAL=$?' in reload_branch
