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

"""In coexistence mode every rule goes into the firewall's own chain.

That is what makes the mode work: `reset_fwf_chains` recognises a rule of
this firewall by the chain it is in, so a rule written into the real
PREROUTING, OUTPUT or FORWARD is one it cannot remove - and the next
activation appends a second copy, the one after that a third.

The filter table's automatic rules were prefixed from the start; the three
the mangle table gets were not.  Measured against real iptables in a
private network namespace, by activating each script of the audit corpus
twice with coexistence forced on: 32 of 225 scripts grew a rule on the
second run, and every one of the added lines was one of these three.
"""

import re
from pathlib import Path

import pytest

from .conftest import FIXTURES_DIR, _compile

FIXTURE = FIXTURES_DIR / 'coexistence_automatic_rules.fwf'
FIREWALL = 'fw-coexistence'

BUILT_IN = ('PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING')


@pytest.fixture(scope='module')
def mangle_rules(tmp_path_factory) -> list[str]:
    tmp_path = tmp_path_factory.mktemp('coexistence')
    script = Path(_compile(FIXTURE, FIREWALL, tmp_path, 'ipt')).read_text()
    return [line.strip() for line in script.splitlines() if '-t mangle -A ' in line]


def test_the_clamp_goes_into_the_firewalls_own_chain(mangle_rules):
    clamp = [line for line in mangle_rules if 'TCPMSS' in line]
    assert clamp
    for line in clamp:
        assert '-A fwf_FORWARD ' in line


def test_the_connection_mark_is_restored_in_the_firewalls_own_chains(mangle_rules):
    restore = [line for line in mangle_rules if '--restore-mark' in line]
    assert restore
    for line in restore:
        assert re.search(r'-A fwf_(PREROUTING|OUTPUT) ', line), line


def test_no_mangle_rule_names_a_built_in_chain(mangle_rules):
    """A rule there survives `reset_fwf_chains` and is added again next time."""
    assert mangle_rules
    for line in mangle_rules:
        chain = line.split('-t mangle -A ', 1)[1].split()[0]
        assert chain not in BUILT_IN, line
