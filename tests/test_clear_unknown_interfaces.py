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

"""What "Clear IP addresses of unknown interfaces" may not take down.

The option flushes the addresses of every interface the firewall object
does not name and then runs ``ip link set <name> down`` on it.  Two kinds
of interface must survive that:

* the **loopback**, whether the object names it or not.  Every local
  service depends on it, and a firewall object without a loopback child
  is ordinary.  Firewall Builder has no such exception.
* an interface the object *does* name with a **wildcard** - ``ppp*`` in
  the object, ``ppp0`` on the machine.  The ignore list was compared name
  for name, so the firewall's own dial-up link was flushed and taken down
  by its own script.
The shell is asked directly, with ``ip`` stubbed on PATH, so the test
needs neither privileges nor a network namespace.
"""

import subprocess  # nosec B404

import pytest

from firewallfabrik.driver._configlet import Configlet

#: What `ip link show | sed 's/://g'` sees on the machine under test.
_LINK_SHOW = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT
3: ppp0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1492 qdisc fq state UNKNOWN mode DEFAULT
4: virbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT
"""

_STUB_IP = f"""#!/bin/sh
if [ "$1 $2" = 'link show' ] && [ $# -eq 2 ]; then
    cat <<'LINKS'
{_LINK_SHOW}LINKS
    exit 0
fi
echo "$@" >> "$IP_LOG"
"""


def _cleared(tmp_path, ignore_list):
    """The interfaces the function takes down, given *ignore_list*."""
    stub = tmp_path / 'ip'
    stub.write_text(_STUB_IP)
    stub.chmod(0o755)
    log = tmp_path / 'ip.log'

    functions = Configlet('linux24', 'update_addresses')
    script = tmp_path / 'run.sh'
    script.write_text(
        f'{functions.expand()}\nIP="{stub}"\n'
        f'clear_addresses_except_known_interfaces "{ignore_list}"\n'
    )
    subprocess.run(  # nosec B603 B607
        ['/bin/sh', str(script)],
        check=True,
        env={'PATH': '/usr/bin:/bin', 'IP_LOG': str(log)},
        capture_output=True,
    )
    lines = log.read_text().splitlines() if log.exists() else []
    return [line.split()[2] for line in lines if line.endswith(' down')]


@pytest.mark.parametrize(
    ('ignore_list', 'expected'),
    [
        # The object names no loopback - the ordinary case.
        ('eth0', ['ppp0', 'virbr0']),
        # Nothing of the machine's is the firewall's: the loopback still
        # stays up.
        ('', ['eth0', 'ppp0', 'virbr0']),
    ],
)
def test_the_loopback_is_never_taken_down(tmp_path, ignore_list, expected):
    assert _cleared(tmp_path, ignore_list) == expected


@pytest.mark.parametrize(
    ('ignore_list', 'expected'),
    [
        # The object names its dial-up link the only way it can.
        ('eth0 ppp*', ['virbr0']),
        # And the iptables spelling of the same wildcard.
        ('eth0 ppp+', ['virbr0']),
        # A wildcard is a prefix, not a joker: virbr0 is still unknown.
        ('eth* ppp*', ['virbr0']),
    ],
)
def test_a_wildcard_covers_the_interfaces_it_stands_for(
    tmp_path, ignore_list, expected
):
    assert _cleared(tmp_path, ignore_list) == expected
