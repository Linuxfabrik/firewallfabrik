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

"""What counts as the address on a line of an address table data file.

Three readers look at the same file and they have to agree.  The
compile-time one takes what is left of the first character that is not an
address character (``AddressTable::loadFromSource``), and the iptables
script takes ``$1`` of the line - so a line carrying a note behind the
address, which is the ordinary shape of a block list stitched together
from several feeds, is an address for both.

The nftables loader hands nft the whole element list in one command, and
nft answers a token it cannot parse by refusing all of it.  Taking the
line rather than its first field therefore did not lose one address, it
lost the table: the set stayed empty and a Deny rule built on that block
list stopped nothing, while the activation reported success.
"""

import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

FIXTURES = Path(__file__).parent / 'fixtures'

_FUNCTIONS_RE = re.compile(
    r'^add_set_elements\(\) \{.*?^load_address_table\(\) \{.*?^\}$',
    re.M | re.S,
)

# One shape per line the readers have to agree on: a plain address, one
# with a note behind it, one with an inline comment, one indented, a
# comment line in either spelling and a blank line.
DATA_FILE = """\
198.51.100.1
198.51.100.2 spam-source seen 2026-09-01
198.51.100.3\t# reported twice
   198.51.100.4
# 198.51.100.5
; 198.51.100.6

"""

EXPECTED = ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4']


def _script(tmp_path, fw_name='firewall34'):
    db = DatabaseManager()
    db.load(str(FIXTURES / 'objects-for-regression-tests.fwb'))
    with db.session() as session:
        fw_id = str(
            session.execute(
                sqlalchemy.select(Firewall).where(Firewall.name == fw_name),
            )
            .scalar_one()
            .id
        )
    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = f'{fw_name}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


def test_the_loader_reads_the_first_field_of_a_line(tmp_path):
    """The static half, so the reason survives without the tools."""
    script = _script(tmp_path)
    body = script.split('load_address_table() {\n', 1)[1].split('\n}\n', 1)[0]
    assert "awk '{print $1}'" in body


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_a_note_behind_an_address_does_not_empty_the_set(tmp_path):
    script = _script(tmp_path)
    functions = _FUNCTIONS_RE.search(script)
    assert functions, 'the loader functions are no longer where the test looks'

    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text(DATA_FILE)

    harness = f"""
        NFT=nft
        {functions.group(0)}
        $NFT add table ip probe
        $NFT add set ip probe s '{{ type ipv4_addr; }}'
        load_address_table ip probe s {data_file} -4 || echo LOADER_FAILED
        $NFT list set ip probe s
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert 'LOADER_FAILED' not in proc.stdout, proc.stdout + proc.stderr
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for address in EXPECTED:
        assert address in proc.stdout, proc.stdout
    for address in ('198.51.100.5', '198.51.100.6'):
        assert address not in proc.stdout, proc.stdout
