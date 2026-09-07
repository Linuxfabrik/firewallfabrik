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

"""Which binaries the iptables script looks for before it touches anything.

``check_tools`` runs first in every branch of the generated script, so a
tool that is missing or configured under a path it does not have is found
before a single rule is installed.  It asked for ``$IPTABLES`` and not for
``$IP6TABLES``, although the script runs the second one for every rule of
the IPv6 ruleset.

Measured in a network namespace on ``firewall61-1.4`` with the ip6tables
path pointed at a file that is not there: the IPv4 rules are installed and
every ip6tables command fails, so the machine comes up with IPv4 filtered
and IPv6 at policy ACCEPT with no rules at all - the half-configured state
the check exists to prevent, and does prevent for the IPv4 tool.  Firewall
Builder checks neither (res/configlets/linux24/check_utilities).
"""

from pathlib import Path

import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

FIXTURES = Path(__file__).parent / 'fixtures'


def _script(tmp_path, fw_name):
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


def test_a_dual_stack_firewall_looks_for_ip6tables(tmp_path):
    script = _script(tmp_path, 'firewall61-1.4')
    assert '$IP6TABLES' in script, 'the fixture no longer installs IPv6 rules'
    check = script.split('check_tools() {', 1)[1].split('}', 1)[0]
    assert 'find_program "$IPTABLES"' in check
    assert 'find_program "$IP6TABLES"' in check


def test_an_ipv4_only_firewall_does_not(tmp_path):
    """A machine without ip6tables runs an IPv4 firewall perfectly well."""
    script = _script(tmp_path, 'firewall1')
    check = script.split('check_tools() {', 1)[1].split('}', 1)[0]
    assert 'find_program "$IPTABLES"' in check
    assert 'find_program "$IP6TABLES"' not in check
