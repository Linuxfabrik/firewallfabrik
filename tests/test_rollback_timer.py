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

"""The rollback timer of the generated script: "try", "confirm", "rollback".

"try <seconds>" activates the policy and puts back the ruleset that was
running before it unless "confirm" follows in time.  Each test starts from
a ruleset of its own (a chain or a table named "marker"), so that "put
back" and "left alone" cannot look the same.

The tests run in an unprivileged network namespace, where systemd-run is
refused and the script falls back to its setsid timer.  Run as real root,
systemd-run would succeed and its timer would act on the host, so the
tests refuse to run as root.
"""

import os
import shutil
import subprocess  # nosec B404
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

pytestmark = [
    pytest.mark.skipif(shutil.which('setsid') is None, reason='needs setsid'),
    pytest.mark.skipif(
        os.geteuid() == 0, reason='as root the timer would act on the host'
    ),
]

TIMEOUT = 2
# Long enough for the timer to have run out and the rollback to be done.
AFTER = 5

PROBE = {
    'ipt': 'iptables -S | sort',
    'nft': 'nft list tables | sort',
}
MARKER = {
    'ipt': 'iptables -N marker',
    'nft': 'nft add table inet marker',
}


def _script(tmp_path, platform):
    return Path(
        _compile(FIXTURES_DIR / 'basic_accept_deny.fwf', 'fw-test', tmp_path, platform)
    )


def _run(tmp_path, platform, steps):
    """Run *steps* in a namespace that starts with the marker ruleset.

    ``$FW`` is the script, and ``probe <name>`` writes the ruleset to
    ``<name>.txt``.  Returns a function that reads such a file, and the
    output of the steps.
    """
    script = _script(tmp_path, platform)
    harness = f"""
        export FWF_LOCK_FILE={tmp_path}/fwf.lock
        export FWF_ROLLBACK_DIR={tmp_path}/rollback
        FW={script}
        probe() {{ {PROBE[platform]} > {tmp_path}/"$1".txt; }}
        {MARKER[platform]}
        probe before
        {steps}
    """
    result = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    said = result.stdout + result.stderr

    def ruleset(name):
        return (tmp_path / f'{name}.txt').read_text()

    return ruleset, said


@pytest.mark.parametrize('platform', PLATFORMS)
def test_an_unconfirmed_activation_is_put_back(tmp_path, platform):
    ruleset, said = _run(
        tmp_path,
        platform,
        f"""
        sh "$FW" try {TIMEOUT} || echo TRY-FAILED
        probe tried
        sleep {AFTER}
        probe after
        """,
    )
    assert 'TRY-FAILED' not in said, said
    assert ruleset('tried') != ruleset('before'), 'try did not activate the policy'
    assert ruleset('after') == ruleset('before'), said
    assert not (tmp_path / 'rollback').exists(), 'the saved state was left behind'


@pytest.mark.parametrize('platform', PLATFORMS)
def test_a_confirmed_activation_stays(tmp_path, platform):
    ruleset, said = _run(
        tmp_path,
        platform,
        f"""
        sh "$FW" try {TIMEOUT} || echo TRY-FAILED
        probe tried
        sh "$FW" confirm || echo CONFIRM-FAILED
        sleep {AFTER}
        probe after
        """,
    )
    assert 'FAILED' not in said, said
    assert ruleset('after') == ruleset('tried'), said
    assert not (tmp_path / 'rollback').exists()


@pytest.mark.parametrize('platform', PLATFORMS)
def test_a_second_try_keeps_the_ruleset_from_before_the_first(tmp_path, platform):
    """Saving again would make the unconfirmed ruleset the one to go back to."""
    ruleset, said = _run(
        tmp_path,
        platform,
        f"""
        sh "$FW" try {TIMEOUT} || echo TRY-FAILED
        sh "$FW" try {TIMEOUT} || echo TRY-FAILED
        sleep {AFTER}
        probe after
        """,
    )
    assert 'TRY-FAILED' not in said, said
    assert ruleset('after') == ruleset('before'), said


@pytest.mark.parametrize('platform', PLATFORMS)
def test_a_plain_start_stops_a_pending_timer(tmp_path, platform):
    """The timer would otherwise undo an activation nobody asked it to."""
    ruleset, said = _run(
        tmp_path,
        platform,
        f"""
        sh "$FW" try {TIMEOUT} || echo TRY-FAILED
        sh "$FW" start || echo START-FAILED
        probe started
        sleep {AFTER}
        probe after
        """,
    )
    assert 'FAILED' not in said, said
    assert 'rollback timer is stopped' in said, said
    assert ruleset('after') == ruleset('started'), said


@pytest.mark.parametrize('platform', PLATFORMS)
def test_try_without_seconds_changes_nothing(tmp_path, platform):
    ruleset, said = _run(
        tmp_path,
        platform,
        """
        sh "$FW" try && echo TRY-SUCCEEDED
        probe after
        """,
    )
    assert 'TRY-SUCCEEDED' not in said, said
    assert ruleset('after') == ruleset('before'), said


@pytest.mark.parametrize('platform', PLATFORMS)
def test_confirm_without_a_pending_activation_fails(tmp_path, platform):
    _, said = _run(
        tmp_path,
        platform,
        """
        sh "$FW" confirm && echo CONFIRM-SUCCEEDED
        """,
    )
    assert 'CONFIRM-SUCCEEDED' not in said, said
    assert 'no activation is waiting for confirmation' in said, said
