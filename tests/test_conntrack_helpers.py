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

"""Connection tracking helpers a service asks for, and what the rules make of it.

Since kernel 4.7 a connection gets a helper only where a rule assigns one.
A TCP or UDP service names it (``data['conntrack_helper']``); a rule that
accepts the service assigns it and accepts the RELATED connections it
expects between the rule's own ends, and the automatic rules drop every
other RELATED connection of those helpers.

What passes was measured with vsftpd and in.tftpd behind a routing
firewall on Rocky Linux 8 and 10 and Debian 12 and 13, both platforms,
IPv4 and IPv6, passive and active FTP and TFTP, behind masquerading as
well - and without the assignment, or without the NAT module, the same
transfers fail.  Here the scripts are checked for the rules that do it.
"""

import copy
import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall, NATRule
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.linux._conntrack_helpers import (
    HELPERS,
    helpers_for_protocol,
)
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import (
    CAN_ASK_IPROUTE2,
    CAN_ASK_IPTABLES,
    SKIP_REASON_IPROUTE2,
    SKIP_REASON_IPTABLES,
)

FIXTURES = Path(__file__).parent / 'fixtures'


def _compile(tmp_path, platform, **options):
    """Compile ``fw-helpers``, the options changed as given.

    ``nat=False`` drops the NAT rule set, so the firewall translates nothing.
    """
    nat = options.pop('nat', True)
    db = DatabaseManager()
    db.load(str(FIXTURES / 'conntrack_helpers.fwf'))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-helpers'),
        ).scalar_one()
        merged = copy.deepcopy(fw.options or {})
        merged.update(options)
        fw.options = merged
        if not nat:
            # A disabled rule translates nothing, the way the driver asks.
            for rule in session.scalars(sqlalchemy.select(NATRule)):
                rule_options = copy.deepcopy(rule.options or {})
                rule_options['disabled'] = True
                rule.options = rule_options
        fw_id = str(fw.id)
    driver = (CompilerDriver_ipt if platform == 'ipt' else CompilerDriver_nft)(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = f'{platform}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text(), driver.all_warnings


# -- the catalog --------------------------------------------------------


def test_every_helper_tracks_a_protocol_and_a_family():
    for name, helper in HELPERS.items():
        assert helper.protocols, name
        assert helper.ipv4 or helper.ipv6, name
        assert helper.module.startswith('nf_conntrack_'), name


def test_the_offered_helpers_follow_the_protocol():
    assert 'ftp' in helpers_for_protocol('tcp')
    assert 'tftp' not in helpers_for_protocol('tcp')
    assert 'tftp' in helpers_for_protocol('udp')
    assert 'sip' in helpers_for_protocol('tcp')
    assert 'sip' in helpers_for_protocol('udp')
    # Assigning these by rule would do nothing: H.245 is attached by
    # Q.931, and snmp only rewrites translated payloads.
    for name in ('H.245', 'snmp'):
        assert name not in HELPERS


# -- iptables -----------------------------------------------------------


def test_iptables_assigns_in_the_raw_table(tmp_path):
    script, _ = _compile(tmp_path, 'ipt')
    raw = re.findall(r'-t raw -A (\S+) (.*) -j CT --helper (\S+)', script)
    helpers = {helper for _, _, helper in raw}
    assert {'ftp', 'tftp', 'irc'} <= helpers
    assert all(chain == 'PREROUTING' for chain, _, _ in raw)


def test_a_logged_rule_still_assigns_its_helper(tmp_path):
    """Logging moves the rule into a chain that no longer names the service."""
    script, _ = _compile(tmp_path, 'ipt')
    assert '-A RELATED_HELPER_FWD -m helper --helper ftp -d 192.168.1.10' in script


def test_nat_keeps_the_destination_out_of_the_raw_table(tmp_path):
    """Before a DNAT the packet does not carry the address the rule names."""
    with_nat, _ = _compile(tmp_path, 'ipt')
    assert '-t raw -A PREROUTING -p tcp -m tcp --dport 21 -j CT --helper ftp' in (
        with_nat
    )
    without_nat, _ = _compile(tmp_path, 'ipt', nat=False)
    assert (
        '-t raw -A PREROUTING -p tcp -m tcp -d 192.168.1.10 --dport 21 '
        '-j CT --helper ftp'
    ) in without_nat


def test_a_rule_about_the_firewall_stays_in_its_own_chains(tmp_path):
    """RemoveFW took the address out; the chain says it is the firewall."""
    script, _ = _compile(tmp_path, 'ipt')
    assert '-A RELATED_HELPER_IN -m helper --helper ftp -j ACCEPT' in script
    assert '-A RELATED_HELPER_OUT -m helper --helper ftp -j ACCEPT' in script
    assert '-A RELATED_HELPER_FWD -m helper --helper ftp -j ACCEPT' not in script


def test_related_connections_of_the_helpers_go_through_their_chain(tmp_path):
    script, _ = _compile(tmp_path, 'ipt')
    for chain, helper_chain in (
        ('INPUT', 'RELATED_HELPER_IN'),
        ('OUTPUT', 'RELATED_HELPER_OUT'),
        ('FORWARD', 'RELATED_HELPER_FWD'),
    ):
        jump = f'-A {chain} +-m conntrack --ctstate RELATED -m helper --helper "" -j'
        assert re.search(f'{jump} {helper_chain}', script), chain
        assert re.search(f'{jump} DROP', script), chain
    assert 'ESTABLISHED,RELATED' not in script


def test_the_restore_form_carries_a_raw_section(tmp_path):
    script, _ = _compile(tmp_path, 'ipt', use_iptables_restore=True)
    assert "echo '*raw'" in script
    assert 'echo "-A PREROUTING -p tcp -m tcp --dport 21 -j CT --helper ftp"' in script
    # The empty helper name has to survive the echo into the restore stream.
    assert '--helper \\"\\" -j RELATED_HELPER_IN' in script


def test_the_ipv6_pass_says_irc_is_ipv4_only(tmp_path):
    script, warnings = _compile(tmp_path, 'ipt')
    assert any(
        'irc connection tracking helper exists for IPv4 only' in w for w in warnings
    )
    assert '$IP6TABLES -w 5 -t raw -A PREROUTING -p tcp -m tcp' in script
    assert not re.search(r'\$IP6TABLES.*--helper irc', script)


def test_without_the_established_accept_only_the_assignment_is_written(tmp_path):
    """No helper chain exists then, and an accept into one would stop the script."""
    script, _ = _compile(tmp_path, 'ipt', accept_established=False)
    assert '-j CT --helper ftp' in script
    assert 'RELATED_HELPER' not in script


def test_the_nat_modules_are_loaded_where_addresses_are_translated(tmp_path):
    with_nat, _ = _compile(tmp_path, 'ipt')
    assert 'fwf_load_nat_helpers nf_nat_ftp nf_nat_irc nf_nat_tftp' in with_nat
    without_nat, _ = _compile(tmp_path, 'ipt', nat=False)
    assert 'fwf_load_nat_helpers nf_nat' not in without_nat


@pytest.mark.skipif(
    not (CAN_ASK_IPTABLES and CAN_ASK_IPROUTE2),
    reason=SKIP_REASON_IPTABLES or SKIP_REASON_IPROUTE2,
)
@pytest.mark.parametrize('restore', [False, True], ids=['shell', 'restore'])
def test_iptables_installs_the_helper_rules(tmp_path, restore):
    script, _ = _compile(tmp_path, 'ipt', use_iptables_restore=restore)
    path = tmp_path / 'fw.fw'
    path.write_text(script)
    harness = f"""
        for i in eth0 eth1; do ip link add $i type dummy; ip link set $i up; done
        ip link set lo up
        sh {path} start > {tmp_path}/said.txt 2>&1
        echo $? > {tmp_path}/status.txt
        {{ iptables -t raw -S; iptables -S RELATED_HELPER_FWD; }} > {tmp_path}/rules.txt
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
    assert '-j CT --helper ftp' in rules
    assert '--helper ftp -j ACCEPT' in rules


# -- nftables -----------------------------------------------------------


def test_nftables_assigns_in_front_of_the_accept(tmp_path):
    script, _ = _compile(tmp_path, 'nft')
    assert 'ct helper fwf_ftp_tcp {' in script
    assert 'type "ftp" protocol tcp' in script
    lines = script.splitlines()
    assign = next(
        i for i, line in enumerate(lines) if 'ct helper set "fwf_ftp_tcp"' in line
    )
    accept = next(
        i
        for i, line in enumerate(lines)
        if i > assign and 'tcp dport' in line and 'accept' in line
    )
    assert assign < accept


def test_nftables_restricts_related_by_helper(tmp_path):
    script, _ = _compile(tmp_path, 'nft')
    assert 'ct state established counter accept' in script
    assert re.search(
        r'ct state related ct helper \{ "ftp", "irc", "tftp" \} jump related_helper_fwd',
        script,
    )
    assert 'ct helper "ftp" ip daddr 192.168.1.10 counter accept' in script
    assert 'ct state established,related' not in script


def test_nftables_without_the_established_accept(tmp_path):
    script, _ = _compile(tmp_path, 'nft', accept_established=False)
    assert 'ct helper set "fwf_ftp_tcp"' in script
    assert 'related_helper' not in script


def test_nftables_loads_the_nat_modules(tmp_path):
    script, _ = _compile(tmp_path, 'nft')
    assert 'fwf_load_nat_helpers nf_nat_ftp nf_nat_irc nf_nat_tftp' in script


# -- the standard library ----------------------------------------------


def test_the_standard_ftp_and_tftp_ask_for_their_helper():
    import importlib.resources

    from firewallfabrik.core.objects import TCPService, UDPService

    path = Path(
        str(importlib.resources.files('firewallfabrik') / 'resources' / 'libraries')
    )
    db = DatabaseManager()
    db._load_yaml(path / 'standard.fwf')
    with db.session() as session:
        ftp = session.scalars(
            sqlalchemy.select(TCPService).filter_by(name='FTP 21')
        ).one()
        tftp = session.scalars(
            sqlalchemy.select(UDPService).filter_by(name='TFTP 69')
        ).one()
        assert ftp.data['conntrack_helper'] == 'ftp'
        assert tftp.data['conntrack_helper'] == 'tftp'


# -- anti-spoofing -------------------------------------------------------


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
def test_helpers_without_reverse_path_filter_are_reported(tmp_path, platform):
    """A helper trusts the addresses it reads; anti-spoofing comes first."""
    _, warnings = _compile(tmp_path, platform)
    assert any('reverse path filter is off for IPv4 and IPv6' in w for w in warnings)
    _, warnings = _compile(
        tmp_path, platform, linux24_rp_filter='1', linux24_ipv6_rpfilter='2'
    )
    assert not any('reverse path filter' in w for w in warnings), warnings
