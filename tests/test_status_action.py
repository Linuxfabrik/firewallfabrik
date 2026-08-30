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

"""A firewall that has just installed its rules does not say it is off.

`status` is what an init system and a monitoring check read, and its exit
code is defined: 0 while the rules are loaded and 3 otherwise.  Nothing in
the kernel says which script installed the rules that are there, so the
question can only be answered by asking for something this script installs
- and the answer must not depend on a rule set that happens to need a
chain of its own.  A policy without logging, negation or a branch creates
none, which is the ordinary case: 49 of the 458 scripts of the audit
corpus reported themselves inactive right after a real activation.

The nftables script has always asked the right question - its own table is
either there or it is not - so this is the iptables side catching up.
"""

from pathlib import Path

import pytest

from .conftest import FIXTURES_DIR, _compile

FIXTURE = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

# No logging, no negation, no branch, so no user-defined chain of its own.
NO_CHAINS = 'firewall14'
# Carries rules for both address families.
DUAL_STACK = 'firewall-ipv6-6'


def _status_action(script: str) -> str:
    lines = script.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('status_action('))
    end = next(i for i, line in enumerate(lines[start:], start) if line == '}')
    return '\n'.join(lines[start : end + 1])


@pytest.fixture(scope='module')
def no_chains(tmp_path_factory) -> str:
    tmp_path = tmp_path_factory.mktemp('status-no-chains')
    return _status_action(
        Path(_compile(FIXTURE, NO_CHAINS, tmp_path, 'ipt')).read_text()
    )


@pytest.fixture(scope='module')
def dual_stack(tmp_path_factory) -> str:
    tmp_path = tmp_path_factory.mktemp('status-dual-stack')
    return _status_action(
        Path(_compile(FIXTURE, DUAL_STACK, tmp_path, 'ipt')).read_text()
    )


def test_the_check_counts_rules_and_not_only_chains(no_chains):
    """`-A` is what a policy without a chain of its own leaves behind."""
    assert '-(A|N) ' in no_chains
    assert 'grep -c "^Chain ' not in no_chains


def test_a_firewall_with_no_user_chain_is_still_asked_about(no_chains):
    assert '$IPTABLES' in no_chains


def test_both_address_families_are_asked(dual_stack):
    assert '$IPTABLES' in dual_stack
    assert '$IP6TABLES' in dual_stack


def test_the_answer_is_still_the_documented_exit_code(no_chains):
    assert 'return 0' in no_chains
    assert 'exit 3' in no_chains
