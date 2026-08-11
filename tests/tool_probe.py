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

"""Can this machine ask nft and iptables inside a private namespace?

Several tests hand generated rulesets to the real tools.  Neither can talk
to netlink without CAP_NET_ADMIN, so they run under ``unshare -rn``, which
needs an unprivileged user namespace.  Having the binaries is not enough:
a hardened host, a container and the GitHub runner all refuse to write
``/proc/self/uid_map`` ("Operation not permitted"), and then every
invocation fails for a reason that has nothing to do with what was asked.

That failure is easy to misread.  A test that asks "does the tool refuse
this?" gets a refusal for the wrong reason and passes; a test that asks
"does the tool accept this?" fails on every input and turns the suite red.
So each probe actually tries something the tool must accept, and the tests
skip unless it worked.
"""

import shutil
import subprocess  # nosec B404


def _run(command: list[str], stdin: str = '') -> str:
    """Return why *command* could not be run here, or an empty string."""
    for tool in ('unshare', command[2]):
        if not shutil.which(tool):
            return f'needs {command[2]} and unshare'
    try:
        proc = subprocess.run(  # nosec B603 B607
            command,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as ex:
        return f'cannot run {command[2]} under unshare: {ex}'
    if proc.returncode != 0:
        reason = proc.stderr.strip().splitlines()
        return (
            f'cannot run {command[2]} under unshare: '
            f'{reason[0] if reason else "failed"}'
        )
    return ''


# An empty ruleset nft has to accept, and an ordinary chain name iptables
# has to accept.  Both fail the moment the namespace is denied.
SKIP_REASON = _run(
    ['unshare', '-rn', 'nft', '--check', '-f', '-'], 'table inet fwf_probe {\n}\n'
)
CAN_ASK_NFT = not SKIP_REASON

SKIP_REASON_IPTABLES = _run(['unshare', '-rn', 'iptables', '-N', 'fwf_probe_chain'])
CAN_ASK_IPTABLES = not SKIP_REASON_IPTABLES
