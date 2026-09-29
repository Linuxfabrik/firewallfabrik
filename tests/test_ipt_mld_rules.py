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

"""The Multicast Listener Discovery rules of the IPv6 neighbour discovery option.

No expected output of an iptables fixture switches the option on - the
three that do are the Firewall Builder reference, which predates the MLD
rules - so the rules are installed here for real: every one of them has
to be accepted by ip6tables, in the shell and the iptables-restore form.
The types are numbers, because ip6tables names 130 to 132 only since
1.8.10 and 143 not at all.
"""

import copy
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from tests.tool_probe import (
    CAN_ASK_IPROUTE2,
    CAN_ASK_IPTABLES,
    SKIP_REASON_IPROUTE2,
    SKIP_REASON_IPTABLES,
)

FIXTURES = Path(__file__).parent / 'fixtures'

# (type, source) of every MLD rule, once per chain.
MLD_RULES = [(t, 'fe80::/10') for t in (130, 131, 132, 143)] + [
    (t, '::/128') for t in (131, 143)
]


def _script(tmp_path, use_iptables_restore):
    db = DatabaseManager()
    db.load(str(FIXTURES / 'compiler-tests.fwf'))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-old-ipt'),
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['add_rules_for_ipv6_neighbor_discovery'] = True
        options['use_iptables_restore'] = use_iptables_restore
        # modprobe cannot load a module from a user namespace.
        options['load_modules'] = False
        fw.options = options
        fw_id = str(fw.id)
    driver = CompilerDriver_ipt(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = 'fw-old-ipt.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id])


@pytest.mark.parametrize(
    'use_iptables_restore', [False, True], ids=['shell', 'restore']
)
def test_the_script_carries_every_mld_rule(tmp_path, use_iptables_restore):
    script = _script(tmp_path, use_iptables_restore).read_text()
    for icmp_type, source in MLD_RULES:
        rule = f'--icmpv6-type {icmp_type} -s {source} -m hl --hl-eq 1 -j ACCEPT'
        assert script.count(rule) == 2, (icmp_type, source)


@pytest.mark.skipif(
    not (CAN_ASK_IPTABLES and CAN_ASK_IPROUTE2),
    reason=SKIP_REASON_IPTABLES or SKIP_REASON_IPROUTE2,
)
@pytest.mark.parametrize(
    'use_iptables_restore', [False, True], ids=['shell', 'restore']
)
def test_ip6tables_accepts_every_mld_rule(tmp_path, use_iptables_restore):
    script = _script(tmp_path, use_iptables_restore)
    harness = f"""
        for i in eth0 eth1 eth2; do ip link add $i type dummy; ip link set $i up; done
        ip link set lo up
        sh {script} start > {tmp_path}/said.txt 2>&1
        echo $? > {tmp_path}/status.txt
        ip6tables -S > {tmp_path}/rules.txt
    """
    subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )
    said = (tmp_path / 'said.txt').read_text()
    assert (tmp_path / 'status.txt').read_text().strip() == '0', said
    rules = (tmp_path / 'rules.txt').read_text()
    for chain in ('INPUT', 'OUTPUT'):
        for icmp_type, source in MLD_RULES:
            assert any(
                line.startswith(f'-A {chain} ')
                and f'-s {source}' in line
                and f'--icmpv6-type {icmp_type}' in line
                and '--hl-eq 1' in line
                for line in rules.splitlines()
            ), (chain, icmp_type, source, rules)
