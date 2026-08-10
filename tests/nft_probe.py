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

"""Can this machine run ``nft --check`` in a private network namespace?

Two tests hand generated rulesets to the real ``nft``.  It cannot
initialise its cache without CAP_NET_ADMIN, so they run it under
``unshare -rn``, which needs an unprivileged user namespace.  Having both
binaries is not enough: a hardened host or a CI runner may refuse to write
``/proc/self/uid_map`` ("Operation not permitted"), and then every
invocation fails for a reason that has nothing to do with the ruleset -
which reads as "nft refuses this" and turns the whole suite red.

So the probe actually tries it once, and the tests skip on the answer.
"""

import shutil
import subprocess  # nosec B404


def _probe() -> str:
    """Return why nft cannot be asked here, or an empty string."""
    if not shutil.which('nft') or not shutil.which('unshare'):
        return 'needs nft and unshare'
    try:
        proc = subprocess.run(  # nosec B603 B607
            ['unshare', '-rn', 'nft', '--check', '-f', '-'],
            input='table inet fwf_probe {\n}\n',
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as ex:
        return f'cannot run nft under unshare: {ex}'
    if proc.returncode != 0:
        reason = proc.stderr.strip().splitlines()
        return f'cannot run nft under unshare: {reason[0] if reason else "failed"}'
    return ''


SKIP_REASON = _probe()
CAN_ASK_NFT = not SKIP_REASON
