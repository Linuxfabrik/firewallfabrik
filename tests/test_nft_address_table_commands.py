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

"""Maintaining a run-time address table from the command line, on nftables.

The generated iptables script has offered ``reload_address_table``,
``add_to_address_table``, ``remove_from_address_table`` and
``test_address_table`` since Firewall Builder wrote them, so a block list
can be kept up to date without recompiling the firewall.  The nftables
script offered none of them: an address added to the list reached the
firewall only after a full recompile and activation.

The addresses live in a named set there rather than in an ipset, and a
table used by both the filter and the NAT rules, or by both address
families, has a set for each - so the script carries an index of where its
tables are kept.  The commands take the same arguments on both platforms.
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

_RULES_RE = re.compile(r"<<'NFT_RULES'\n(.*?)\nNFT_RULES", re.S)
_FUNCTIONS_RE = re.compile(
    r'^add_set_elements\(\) \{.*?^test_address_table\(\) \{.*?^\}$',
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


def test_the_script_offers_the_same_commands_as_the_iptables_one(tmp_path):
    script = _script(tmp_path)
    for command in (
        'reload_address_table',
        'add_to_address_table',
        'remove_from_address_table',
        'test_address_table',
    ):
        assert f'    {command})\n' in script, command
        assert f'|{command}' in script, f'{command} missing from the usage line'


def test_the_index_names_every_set_a_table_is_kept_in(tmp_path):
    """A table used by the filter and the NAT rules has a set in each."""
    script = _script(tmp_path)
    index = script.split("<<'FWF_ADDRESS_TABLE_SETS'\n", 1)[1]
    index = index.split('\nFWF_ADDRESS_TABLE_SETS', 1)[0]
    assert 'inet fwf_filter block_these' in index
    assert 'ip fwf_nat block_these' in index
    # A DNS name and a dynamic interface are read again on the next
    # activation, so there is nothing to maintain by hand.
    assert 'i_eth0' not in index


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_a_reload_that_fails_leaves_the_addresses_that_were_there(tmp_path):
    """Emptying the set and filling it are one nft transaction.

    In two commands a reload whose new list nft refuses leaves the set
    empty, and a set no packet is in is a block list that blocks nothing.
    """
    script = _script(tmp_path)
    ruleset = _RULES_RE.search(script)
    functions = _FUNCTIONS_RE.search(script)
    assert ruleset and functions

    ruleset_file = tmp_path / 'ruleset.nft'
    ruleset_file.write_text(ruleset.group(1) + '\n')
    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text('198.51.100.1\n')

    broken = tmp_path / 'broken.tbl'
    broken.write_text('203.0.113.1\n198.51.100.999\n')

    harness = f"""
        NFT=nft
        {functions.group(0)}
        nft -f {ruleset_file} || exit 1
        reload_address_table block_these {data_file} -4 || exit 1
        reload_address_table block_these {broken} -4 && exit 1
        test_address_table block_these 198.51.100.1 > /dev/null || exit 1
        echo KEPT
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'KEPT' in proc.stdout, proc.stdout


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_the_commands_reach_the_running_set(tmp_path):
    script = _script(tmp_path)
    ruleset = _RULES_RE.search(script)
    assert ruleset, 'the ruleset is no longer in a NFT_RULES heredoc'
    functions = _FUNCTIONS_RE.search(script)
    assert functions, 'the address table commands are no longer where the test looks'

    ruleset_file = tmp_path / 'ruleset.nft'
    ruleset_file.write_text(ruleset.group(1) + '\n')
    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text('198.51.100.1\n')

    harness = f"""
        NFT=nft
        {functions.group(0)}
        nft -f {ruleset_file} || exit 1

        reload_address_table block_these {data_file} -4 || exit 1
        test_address_table block_these 198.51.100.1 > /dev/null || exit 1

        add_to_address_table block_these {data_file} 203.0.113.0/24 || exit 1
        test_address_table block_these 203.0.113.7 > /dev/null || exit 1

        remove_from_address_table block_these {data_file} 203.0.113.0/24 || exit 1
        test_address_table block_these 203.0.113.7 > /dev/null && exit 1

        grep -q '203.0.113.0/24' {data_file} && exit 1

        # The NAT table keeps a set of its own for the same block list.
        nft list set ip fwf_nat block_these | grep -c '198\\.51\\.100\\.1'
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip().endswith('1'), proc.stdout


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_the_answer_reads_the_same_as_the_iptables_one(tmp_path):
    """One sentence, and nothing on standard error.

    `nft get element` prints the whole set declaration when it finds the
    address and "Could not process rule: No such file or directory" when it
    does not, which reads as the data file being gone.  The iptables
    command has answered in one sentence since Firewall Builder wrote it,
    and a runbook written for one packet filter is run against the other
    after a migration.
    """
    script = _script(tmp_path)
    ruleset = _RULES_RE.search(script)
    functions = _FUNCTIONS_RE.search(script)
    assert ruleset and functions

    ruleset_file = tmp_path / 'ruleset.nft'
    ruleset_file.write_text(ruleset.group(1) + '\n')
    data_file = tmp_path / 'block-hosts.tbl'
    data_file.write_text('198.51.100.1\n')

    harness = f"""
        NFT=nft
        {functions.group(0)}
        nft -f {ruleset_file} || exit 1
        reload_address_table block_these {data_file} -4 > /dev/null || exit 1
        test_address_table block_these 198.51.100.1 || exit 1
        test_address_table block_these 192.0.2.1 && exit 1
        exit 0
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '198.51.100.1 is in address table block_these' in proc.stdout
    assert '192.0.2.1 is not in address table block_these' in proc.stdout
    assert 'No such file or directory' not in proc.stdout + proc.stderr


def _dual_stack_script(tmp_path):
    """A firewall whose rule names a run-time table in both address families.

    The table then has a set per family, ``lan_prefix`` and
    ``lan_prefix_v6``, the case of a gateway whose rules follow a
    delegated IPv6 prefix that a DHCPv6 hook writes into the file.
    """
    import uuid

    from firewallfabrik.core.objects import (
        AddressTable,
        Library,
        PolicyRule,
        rule_elements,
    )

    db = DatabaseManager()
    db.load(str(FIXTURES / 'basic_accept_deny.fwf'))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test')
        ).scalar_one()
        fw_id = str(fw.id)
        library = session.execute(sqlalchemy.select(Library)).scalars().first()
        table = AddressTable(
            data={'filename': str(tmp_path / 'lan_prefix.txt'), 'run_time': True},
            id=uuid.uuid4(),
            library_id=library.id,
            name='lan_prefix',
            type='AddressTable',
        )
        session.add(table)
        policy = next(rs for rs in fw.rule_sets if rs.type == 'Policy')
        policy.ipv4 = policy.ipv6 = True
        rule = PolicyRule(
            id=uuid.uuid4(),
            policy_action=0,
            position=len(policy.rules),
            rule_set_id=policy.id,
            type='PolicyRule',
        )
        session.add(rule)
        session.flush()
        session.execute(
            rule_elements.insert().values(
                position=0, rule_id=rule.id, slot='src', target_id=table.id
            )
        )
    (tmp_path / 'lan_prefix.txt').write_text('2001:db8:a::/64\n')
    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text()


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_a_reload_touches_the_set_of_the_family_it_names(tmp_path):
    """``-4`` reloads the IPv4 set and ``-6`` the IPv6 set, and nothing else.

    ``-6`` used to look the set up under the plain name and fill the IPv4
    set with the IPv6 lines of the file, which nft refused, so a changed
    IPv6 prefix never reached the running ruleset.  The IPv4 direction is
    checked as well, and so is a name that already carries the suffix.
    """
    script = _dual_stack_script(tmp_path)
    ruleset = _RULES_RE.search(script)
    functions = _FUNCTIONS_RE.search(script)
    assert ruleset and functions
    assert 'lan_prefix_v6' in script

    ruleset_file = tmp_path / 'ruleset.nft'
    ruleset_file.write_text(ruleset.group(1) + '\n')
    first = tmp_path / 'first.txt'
    first.write_text('192.0.2.0/24\n2001:db8:a::/64\n')
    second = tmp_path / 'second.txt'
    second.write_text('198.51.100.0/24\n2001:db8:b::/64\n')

    harness = f"""
        NFT=nft
        {functions.group(0)}
        is_in() {{ test_address_table lan_prefix "$1" > /dev/null; }}
        nft -f {ruleset_file} || exit 1
        reload_address_table lan_prefix {first} -4 || exit 1
        reload_address_table lan_prefix {first} -6 || exit 1
        is_in 192.0.2.7 && is_in 2001:db8:a::7 || exit 1

        # IPv6 only: the new prefix replaces the old, IPv4 is untouched.
        reload_address_table lan_prefix {second} -6 || exit 1
        is_in 2001:db8:b::7 || exit 11
        is_in 2001:db8:a::7 && exit 12
        is_in 192.0.2.7 || exit 13
        is_in 198.51.100.7 && exit 14

        # IPv4 only: the other way round.
        reload_address_table lan_prefix {second} -4 || exit 1
        is_in 198.51.100.7 || exit 21
        is_in 192.0.2.7 && exit 22
        is_in 2001:db8:b::7 || exit 23

        # The name of the IPv6 set itself works too.
        reload_address_table lan_prefix_v6 {first} -6 || exit 1
        is_in 2001:db8:a::7 || exit 31
        is_in 198.51.100.7 || exit 32
        echo SWAPPED
    """
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-c', harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stdout + proc.stderr)
    assert 'SWAPPED' in proc.stdout, proc.stdout
