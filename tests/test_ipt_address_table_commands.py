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

"""Maintaining a run-time address table from the command line.

The generated iptables script offers ``add_to_address_table``,
``remove_from_address_table`` and ``test_address_table``, so a block list
can be kept up to date without recompiling the firewall.

An ipset holds one address family, so an address table used by both
rulesets has a set per family and the IPv6 one carries a ``_v6`` suffix -
the name ``normalize_set_name`` gives the rules that match against it.  The
three commands never asked, and handed every address to the set of the
first family: ipset answers an IPv6 address there with "resolving to IPv4
address failed", so the address was neither added, removed nor tested,
while the data file the command also edits said otherwise.
"""

import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from tests.tool_probe import CAN_ASK_IPSET, SKIP_REASON_IPSET

FIXTURES = Path(__file__).parent / 'fixtures'

_FUNCTIONS_RE = re.compile(
    r'^address_table_set_for\(\) \{.*?^test_address_table\(\) \{.*?^\}$',
    re.M | re.S,
)


def _script(tmp_path, fw_name='firewall41-1'):
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
    driver = CompilerDriver_ipt(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = f'{fw_name}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


def test_the_commands_ask_which_family_the_address_has(tmp_path):
    """The static half, so the reason survives without the tools."""
    script = _script(tmp_path)
    assert 'address_table_set_for() {' in script
    for command in ('-A', '-D', '-T'):
        assert f'"$IPSET" {command} "${{set_name}}:net" "$address"' in script


@pytest.mark.skipif(not CAN_ASK_IPSET, reason=SKIP_REASON_IPSET)
def test_an_ipv6_address_reaches_the_set_of_its_own_family(tmp_path):
    script = _script(tmp_path)
    functions = _FUNCTIONS_RE.search(script)
    assert functions, 'the address table commands are no longer where the test looks'

    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text('')

    harness = f"""
        IPSET=ipset
        {functions.group(0)}
        ipset -N blk:ip iphash family inet
        ipset -N blk:net nethash family inet
        ipset -N blk_v6:ip iphash family inet6
        ipset -N blk_v6:net nethash family inet6

        add_to_address_table blk {data_file} 2001:db8::1 || exit 1
        add_to_address_table blk {data_file} 2001:db8:1::/48 || exit 1
        add_to_address_table blk {data_file} 198.51.100.1 || exit 1
        test_address_table blk 2001:db8::1 || exit 1
        remove_from_address_table blk {data_file} 2001:db8::1 || exit 1
        test_address_table blk 2001:db8::1 && exit 1

        echo "v6 hosts: $(ipset list blk_v6:ip | grep -c '^2001:')"
        echo "v6 nets: $(ipset list blk_v6:net | grep -c '^2001:')"
        echo "v4 hosts: $(ipset list blk:ip | grep -c '^198\\.')"
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'v6 hosts: 0' in proc.stdout, proc.stdout
    assert 'v6 nets: 1' in proc.stdout, proc.stdout
    assert 'v4 hosts: 1' in proc.stdout, proc.stdout
