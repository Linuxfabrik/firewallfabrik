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

"""What the generated activation script reports after a successful start.

A firewall that switches on IPv6 forwarding ends its `ip_forward` function
with a write to /proc/sys/net/ipv6/conf/all/forwarding.  That file is
missing on a kernel built without IPv6 or booted with ipv6.disable=1, and
/proc/sys is read-only in a container and under systemd's
ProtectKernelTunables.  The write then fails while the ruleset is loaded
and filtering, so its status must not become the script's.

The iptables skeleton leaves RETVAL at the 0 it was initialised with for
the whole `start` branch, and so does fwbuilder; only a failing
`script_body` ends it, through `run_epilog_and_exit 1`.
"""

import re
import shutil
import subprocess  # nosec B404
import textwrap
from pathlib import Path

import pytest

# The generated scripts, not the templates: a Jinja comment never reaches
# the file the admin runs, and the file is what this is about.
_EXPECTED = Path(__file__).resolve().parents[1] / 'tests' / 'expected-output'
SCRIPTS = {
    'nftables': _EXPECTED / 'nft' / 'basic_accept_deny' / 'fw-test.fw',
    'iptables': _EXPECTED / 'ipt' / 'basic_accept_deny' / 'fw-test.fw',
}


def _start_branch(text: str) -> str:
    """The commands of the `start)` case, comments and blank lines removed."""
    match = re.search(r'\n\s*start\)\n(.*?)\n\s*;;', text, re.S)
    assert match, 'no start branch found'
    return '\n'.join(
        line
        for line in match.group(1).splitlines()
        if line.strip() and not line.lstrip().startswith('#')
    )


@pytest.mark.parametrize('platform', sorted(SCRIPTS), ids=sorted(SCRIPTS))
def test_a_successful_start_does_not_report_the_sysctl_status(platform):
    branch = _start_branch(SCRIPTS[platform].read_text())

    assert 'ip_forward' in branch
    assert 'RETVAL' not in branch, (
        'the start branch must leave RETVAL at 0; only a failing script_body '
        'ends it, through run_epilog_and_exit'
    )


@pytest.mark.skipif(shutil.which('sh') is None, reason='no POSIX shell')
def test_the_shape_this_guards_really_changes_the_exit_code(tmp_path):
    """The guard is only worth having if the two shapes differ."""
    body = textwrap.dedent("""\
        RETVAL=0
        ip_forward() {
            :
            echo 1 > /proc/sys/net/ipv6/conf/all/forwarding_no_such_file
        }
        ip_forward 2>/dev/null
        %s
        exit "$RETVAL"
    """)
    taking = tmp_path / 'taking.sh'
    taking.write_text(body % 'RETVAL=$?')
    leaving = tmp_path / 'leaving.sh'
    leaving.write_text(body % ':')

    assert (
        subprocess.run(  # nosec B603 B607
            ['sh', str(taking)], check=False
        ).returncode
        != 0
    )
    assert (
        subprocess.run(  # nosec B603 B607
            ['sh', str(leaving)], check=False
        ).returncode
        == 0
    )
