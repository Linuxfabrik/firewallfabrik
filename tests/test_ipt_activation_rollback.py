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

"""What an iptables script leaves behind when its activation fails.

The start branch empties the ruleset before it installs the new one.  A
rule iptables refused halfway through used to leave the machine with DROP
policies and part of the new rules - on a remote machine usually without
the rule that lets the administrator back in.  On Rocky Linux 8 the
``compiler-tests`` firewall ``fw-nat`` did exactly that, because iptables
1.8.4 refuses an SNAT port range starting at 0.  The script now saves the
running ruleset first and puts it back.

The failure is injected into the IPv6 part, so the IPv4 rules are already
installed when it happens and both families have to come back.  The test
compiles ``fw-old-ipt`` rather than ``fw-nat``: an owner match naming a
uid cannot be installed from a user namespace that maps only root
(``xt_owner`` checks the uid against it), which has nothing to do with
what is tested here.
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

needs_namespace = pytest.mark.skipif(
    not (CAN_ASK_IPTABLES and CAN_ASK_IPROUTE2),
    reason=SKIP_REASON_IPTABLES or SKIP_REASON_IPROUTE2,
)

# A ruleset of its own, so that "put back" cannot be confused with "never
# changed": the failing activation replaces every line of it.
PRIOR_RULESET = """
nft flush ruleset 2>/dev/null
iptables -P INPUT DROP
iptables -N PRIOR
iptables -A INPUT -j PRIOR
iptables -A PRIOR -s 192.0.2.1 -p tcp --dport 22 -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ip6tables -P INPUT DROP
ip6tables -A INPUT -s 2001:db8::1 -j ACCEPT
"""

SNAPSHOT = "{ iptables-save; echo '#v6'; ip6tables-save; }"


def _script(tmp_path, use_iptables_restore):
    db = DatabaseManager()
    db.load(str(FIXTURES / 'compiler-tests.fwf'))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-old-ipt'),
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['use_iptables_restore'] = use_iptables_restore
        # modprobe cannot load a module from a user namespace, and the
        # script stops before it changes anything when that fails.
        options['load_modules'] = False
        fw.options = options
        fw_id = str(fw.id)
    driver = CompilerDriver_ipt(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = 'fw-old-ipt.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


def _break_ipv6_part(script, use_iptables_restore):
    """Add a rule iptables refuses to the end of the IPv6 part."""
    lines = script.split('\n')
    if use_iptables_restore:
        end = max(i for i, line in enumerate(lines) if '| $IP6TABLES_RESTORE' in line)
        table = max(
            i
            for i, line in enumerate(lines[:end])
            if line.strip().startswith("echo '*")
        )
        lines.insert(table + 1, 'echo "-A PREROUTING -m fwfbogus -j ACCEPT"')
    else:
        # The last line of script_body before it points $IPTABLES back at
        # the tool: every rule of both families is installed by then.
        end = lines.index('    IPTABLES="$fwf_tool_v4"')
        lines.insert(end, '    $IP6TABLES -A INPUT -m fwfbogus -j ACCEPT')
    return '\n'.join(lines)


def _chains(saved):
    """Policy and rules per chain, independent of the order chains are listed in.

    The nftables backend of iptables lists chains in the order they were
    created, which a restore changes; what a packet meets does not depend
    on it.
    """
    chains = {}
    family, table = 'v4', ''
    for line in saved.splitlines():
        if line == '#v6':
            family = 'v6'
        elif line.startswith('*'):
            table = line[1:]
        elif line.startswith(':'):
            name, policy = line[1:].split()[:2]
            chains.setdefault((family, table, name), [policy])
        elif line.startswith('-A '):
            name = line.split()[1]
            chains.setdefault((family, table, name), ['-']).append(line)
    # A table that did not exist before comes back empty with ACCEPT
    # policies on some iptables releases instead of vanishing; it filters
    # nothing either way.
    return {key: value for key, value in chains.items() if value != ['ACCEPT']}


def _activate(tmp_path, script, prepare):
    path = tmp_path / 'fw.fw'
    path.write_text(script)
    harness = f"""
        for i in eth0 eth1 eth2; do ip link add $i type dummy; ip link set $i up; done
        ip link set lo up
        {prepare}
        {SNAPSHOT} > {tmp_path}/before.txt
        sh {path} start > {tmp_path}/said.txt 2>&1
        echo $? > {tmp_path}/status.txt
        {SNAPSHOT} > {tmp_path}/after.txt
    """
    subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )
    return (
        int((tmp_path / 'status.txt').read_text()),
        (tmp_path / 'said.txt').read_text(),
        (tmp_path / 'before.txt').read_text(),
        (tmp_path / 'after.txt').read_text(),
    )


@needs_namespace
@pytest.mark.parametrize(
    'use_iptables_restore', [False, True], ids=['shell', 'restore']
)
def test_a_failed_activation_puts_the_previous_ruleset_back(
    tmp_path, use_iptables_restore
):
    good = _script(tmp_path, use_iptables_restore)
    status, said, _, after = _activate(tmp_path, good, 'nft flush ruleset 2>/dev/null')
    assert status == 0, said
    assert _chains(after), 'the good activation installed nothing'

    bad = _break_ipv6_part(good, use_iptables_restore)
    status, said, before, after = _activate(tmp_path, bad, PRIOR_RULESET)
    assert status != 0, said
    assert 'is back in place' in said, said
    assert _chains(before) == _chains(after), said


@needs_namespace
@pytest.mark.parametrize(
    'use_iptables_restore', [False, True], ids=['shell', 'restore']
)
def test_a_failed_first_activation_leaves_the_machine_open(
    tmp_path, use_iptables_restore
):
    """A machine that had no rules has none afterwards, and no DROP policy."""
    bad = _break_ipv6_part(
        _script(tmp_path, use_iptables_restore), use_iptables_restore
    )
    status, said, _, after = _activate(tmp_path, bad, 'nft flush ruleset 2>/dev/null')
    assert status != 0, said
    assert 'is back in place' in said, said
    assert _chains(after) == {}, after


@pytest.mark.parametrize(
    'use_iptables_restore', [False, True], ids=['shell', 'restore']
)
def test_only_the_start_branch_needs_the_save_program(tmp_path, use_iptables_restore):
    """Stop, status and block work on a machine without iptables-save.

    `check_tools` runs in every branch, so a check for the save program
    there made `stop` fail on such a machine - the one command that has
    to open the firewall whatever else is wrong.
    """
    script = _script(tmp_path, use_iptables_restore)
    dispatch = script.split('case "$cmd" in', 1)[1]
    branches = {}
    for name in ('start', 'stop', 'status', 'block'):
        branches[name] = dispatch.split(f'    {name})\n', 1)[1].split(';;', 1)[0]
    assert 'check_rollback_tools' in branches['start']
    for name in ('stop', 'status', 'block'):
        assert 'check_tools' in branches[name], name
        assert 'check_rollback_tools' not in branches[name], name
    check_tools = script.split('check_tools() {', 1)[1].split('\n}', 1)[0]
    assert '_SAVE' not in check_tools
