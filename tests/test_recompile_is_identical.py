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

"""Compiling the same firewall twice has to give the same script.

`DesignDecisions.md` states it as the reason the compiler versions are
separate from the package version: the same policy compiled again must
produce a byte-identical file, or nobody can tell a real change from
noise.  The GUI compiles in the process it runs in, so "again" usually
means "in the same process as the last one".

The iptables temporary chain names are what that hangs on.  They are
`C<hash>.<n>`, where the hash comes from the rule set name and the rule
position and `<n>` counts how many chains that rule has needed.  The
counter has to start over for every compile: the policy compiler kept it
per instance, the NAT compiler in a module-level dict that nothing ever
reset, so the second compile of a firewall named its NAT chains `.1`,
the third `.2`, and so on for as long as the application ran.
"""

import re

import pytest

from tests.conftest import FIXTURES_DIR

TIMESTAMP = re.compile(r'^.*Generated .*$', re.MULTILINE)


def _script(path):
    return TIMESTAMP.sub('', path.read_text())


@pytest.mark.parametrize('fw_name', ['firewall', 'firewall1'])
def test_the_second_compile_of_a_firewall_matches_the_first(
    compile_ipt, tmp_path, fw_name
):
    """Both carry NAT rules that need a temporary chain."""
    fixture = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

    first = _script(compile_ipt(fixture, fw_name, tmp_path / 'first'))
    second = _script(compile_ipt(fixture, fw_name, tmp_path / 'second'))

    assert first == second
    # Guard the premise: a firewall whose script holds no temporary chain
    # would pass this test without ever asking the question.
    assert re.search(r'C[0-9a-f]{12}\.\d', first)


def test_a_second_firewall_does_not_shift_the_first_ones_chain_names(
    compile_ipt, tmp_path
):
    """The name is derived per rule set and position, which repeat per file."""
    fixture = FIXTURES_DIR / 'objects-for-regression-tests.fwb'

    alone = _script(compile_ipt(fixture, 'firewall', tmp_path / 'alone'))
    compile_ipt(fixture, 'firewall1', tmp_path / 'other')
    after = _script(compile_ipt(fixture, 'firewall', tmp_path / 'after'))

    assert alone == after
