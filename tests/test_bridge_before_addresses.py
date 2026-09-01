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

"""A bridge is created before the addresses of any interface are set.

`update_addresses_of_interface` answers an interface that is not on the
machine with "Interface br0 does not exist" and `exit 1`, so configuring
the address of a bridge before `sync_bridge_interfaces` has created it
stops the script before it installs a single rule - on exactly the run
that was meant to create the bridge.  Firewall Builder writes the block
in the other order (`CompilerDriver_ipt_run.cpp:557-573`: bonding, VLAN,
bridge, then the addresses).

The expected-output tests cannot see this: `tests/normalize.py` moves
every `update_addresses_of_interface` line to the end of the
`configure_interfaces()` block and sorts them, so both orders normalise
to the same text.
"""

from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'
FIREWALL = 'gw1-bridge'


def _positions(script: str) -> tuple[int, int]:
    """Where the bridge is created and where the first address is set."""
    lines = script.splitlines()
    sync = next(
        i for i, line in enumerate(lines) if line.strip().startswith('sync_bridge_')
    )
    addr = next(
        i
        for i, line in enumerate(lines)
        if line.strip().startswith('update_addresses_of_interface "')
    )
    return sync, addr


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
def test_bridge_is_created_before_its_address_is_configured(
    platform, compile_ipt, compile_nft, tmp_path
):
    compile_fw = compile_ipt if platform == 'ipt' else compile_nft
    script = compile_fw(FIXTURE, FIREWALL, tmp_path).read_text()
    sync, addr = _positions(script)
    assert sync < addr, (
        f'{platform}: the address of an interface is configured on line {addr} '
        f'and the bridge is only created on line {sync}'
    )
