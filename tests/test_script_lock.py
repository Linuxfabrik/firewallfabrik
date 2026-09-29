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

"""Two runs of a generated script do not change the firewall at once.

Every command that changes the firewall takes a lock (flock) and waits
for it; the commands that only look do not.  "reload" runs "$0 start",
which must not wait for the lock its own parent holds.
"""

import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

import pytest

from tests.tool_probe import (
    CAN_ASK_IPTABLES,
    CAN_ASK_NFT,
    SKIP_REASON,
    SKIP_REASON_IPTABLES,
)

from .conftest import FIXTURES_DIR, _compile

PLATFORMS = [
    pytest.param(
        'ipt',
        marks=pytest.mark.skipif(not CAN_ASK_IPTABLES, reason=SKIP_REASON_IPTABLES),
    ),
    pytest.param('nft', marks=pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)),
]

pytestmark = pytest.mark.skipif(shutil.which('flock') is None, reason='needs flock')

# How long the other holder keeps the lock, and how much of it a command
# that has to wait must at least have waited.
HOLD = 3
WAITED = 2


def _script(tmp_path, platform):
    return Path(
        _compile(FIXTURES_DIR / 'basic_accept_deny.fwf', 'fw-test', tmp_path, platform)
    )


def _run(tmp_path, script, command, *, hold=False):
    """Run *command* in a namespace, optionally while another process holds the lock.

    Returns the exit status and the seconds the command took.
    """
    lock = tmp_path / 'fwf.lock'
    holder = f'flock {lock} sleep {HOLD} & sleep 0.5' if hold else ':'
    harness = f"""
        export FWF_LOCK_FILE={lock}
        {holder}
        begin=$(date +%s%N)
        sh {script} {command} > {tmp_path}/said.txt 2>&1
        echo $? > {tmp_path}/status.txt
        echo $(( ($(date +%s%N) - begin) / 1000000 )) > {tmp_path}/took.txt
        wait
    """
    subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    return (
        int((tmp_path / 'status.txt').read_text()),
        int((tmp_path / 'took.txt').read_text()) / 1000,
        (tmp_path / 'said.txt').read_text(),
    )


@pytest.mark.parametrize('platform', PLATFORMS)
def test_a_command_that_changes_the_firewall_waits_for_the_lock(tmp_path, platform):
    script = _script(tmp_path, platform)
    status, took, said = _run(tmp_path, script, 'stop', hold=True)
    assert status == 0, said
    assert took >= WAITED, f'stop did not wait for the lock ({took:.1f}s)'


@pytest.mark.parametrize('platform', PLATFORMS)
def test_status_does_not_wait_for_the_lock(tmp_path, platform):
    script = _script(tmp_path, platform)
    _, took, said = _run(tmp_path, script, 'status', hold=True)
    assert took < WAITED, f'status waited for the lock ({took:.1f}s): {said}'


@pytest.mark.parametrize('platform', PLATFORMS)
def test_reload_does_not_wait_for_its_own_lock(tmp_path, platform):
    script = _script(tmp_path, platform)
    start = time.monotonic()
    status, _, said = _run(tmp_path, script, 'reload')
    assert status == 0, said
    assert time.monotonic() - start < 30, 'reload waited for the lock it holds'
    assert 'still holds' not in said, said
