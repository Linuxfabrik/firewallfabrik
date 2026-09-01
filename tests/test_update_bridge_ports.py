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

"""Every port of a bridge is enslaved, not only the last one.

Both compilers write the call the way Firewall Builder writes it, with
the whole port list as one argument: ``update_bridge br1 "eth2 eth3"``.
The loop that turns that list into one entry per port therefore has to
split it, which is what `for subint in $*` in the `update_bridge`
configlet does and what a quoted `"$@"` does not: quoted, the list is a
single port called "eth2 eth3", and `diff_intf` then splits *that* on
whitespace, so every port but the last arrives without the ``@bridge``
suffix and is enslaved to an empty bridge name.

The shell is asked directly here.  `ip` is a stub on PATH, so the test
needs no privileges and no network namespace, and it records the
``link set <port> master <bridge>`` commands the functions issue.
"""

import subprocess  # nosec B404

import pytest

from firewallfabrik.driver._configlet import Configlet

_STUB_IP = """#!/bin/sh
# `ip link show <bridge> type bridge` - the bridge is already there.
# `ip link show master <bridge>`      - and carries no port yet.
# Everything else is recorded.
case "$1 $2" in
    'link show') case "$3" in
                     master) exit 0 ;;
                     *)      exit 0 ;;
                 esac ;;
esac
echo "$@" >> "$IP_LOG"
"""


def _run_update_bridge(tmp_path, ports_argument):
    """Run the configlet's `update_bridge` and return the commands it issued."""
    stub = tmp_path / 'ip'
    stub.write_text(_STUB_IP)
    stub.chmod(0o755)
    log = tmp_path / 'ip.log'

    functions = Configlet('linux24', 'shell_functions')
    functions.set_variable('have_ipv6', True)
    script = tmp_path / 'run.sh'
    script.write_text(
        f'{functions.expand()}\n'
        f'{Configlet("linux24", "update_bridge").expand()}\n'
        f'IP="{stub}"\n'
        f'update_bridge br1 "{ports_argument}"\n'
    )
    subprocess.run(  # nosec B603 B607
        ['/bin/sh', str(script)],
        check=True,
        env={'PATH': '/usr/bin:/bin', 'IP_LOG': str(log)},
        capture_output=True,
    )
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize(
    ('ports', 'expected'),
    [
        ('eth2 eth3', ['eth2', 'eth3']),
        ('eth2 eth3 eth4', ['eth2', 'eth3', 'eth4']),
        ('eth2', ['eth2']),
    ],
)
def test_every_port_is_enslaved_to_the_bridge(tmp_path, ports, expected):
    commands = _run_update_bridge(tmp_path, ports)
    enslaved = [
        line.split()[2]
        for line in commands
        if line.startswith('link set ') and line.endswith(' master br1')
    ]
    assert enslaved == expected
