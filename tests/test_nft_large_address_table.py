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

"""How many addresses an address table may hold on nftables.

The set a rule matches against is filled after the ruleset is loaded, by a
shell function in the generated script.  Handing nft the element list as
one command-line argument caps it at MAX_ARG_STRLEN, 32 pages
(``include/uapi/linux/binfmts.h``), so a table of more than about eleven
thousand IPv4 addresses could not be passed over at all: the shell answered
"Argument list too long", nft never ran, the set stayed empty, and a Deny
rule built on a block list of that size blocked nothing.

A block list is exactly the object that grows to six figures, so the limit
sits where the feature is used.  Standard input has no such cap.
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

# Comfortably past the argument limit: 20000 addresses are about 228 KB of
# text where execve stops at 128 KB.
ADDRESS_COUNT = 20000

_FUNCTIONS_RE = re.compile(
    r'^add_set_elements\(\) \{.*?^load_address_table\(\) \{.*?^\}$',
    re.M | re.S,
)


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


def test_the_loader_does_not_put_the_element_list_on_the_command_line(tmp_path):
    """The static half, so the reason survives without the tools."""
    script = _script(tmp_path)
    assert '$NFT add element' not in script
    assert 'add_set_elements "$family" "$table" "$setname" "$addrs"' in script


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_a_table_of_twenty_thousand_addresses_reaches_the_set(tmp_path):
    script = _script(tmp_path)
    functions = _FUNCTIONS_RE.search(script)
    assert functions, 'the loader functions are no longer where the test looks'

    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text(
        ''.join(
            f'10.{i >> 16 & 0xFF}.{i >> 8 & 0xFF}.{i & 0xFF}\n'
            for i in range(ADDRESS_COUNT)
        )
    )

    # An interval set with auto-merge folds a contiguous run into one
    # element, which would hide a truncated load, so the set the addresses
    # go into here is a plain one and every address stays its own element.
    harness = f"""
        NFT=nft
        {functions.group(0)}
        $NFT add table ip probe
        $NFT add set ip probe s '{{ type ipv4_addr; }}'
        load_address_table ip probe s {data_file} -4 || echo LOADER_FAILED
        $NFT list set ip probe s | grep -c '10\\.'
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert 'LOADER_FAILED' not in proc.stdout, proc.stderr
    assert 'Argument list too long' not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
