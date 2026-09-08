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

"""How the priority of a base chain is spelled for the target release.

``type filter hook input priority filter;`` is the readable form and what
every current nftables prints back, but the name is younger than the
number: nftables read a priority as ``NUM | DASH NUM`` and nothing else
until v0.9.1 ("src: Set/print standard chain prios with textual names",
c8a0e8c9, 2018-08-03).

That line is the first one of every base chain, so on an older release the
name is not a rule that goes missing - a ruleset loads in one transaction,
so the whole ruleset is refused and the firewall keeps the rules it had.
A firewall pinned to 0.9.0 therefore gets the numbers, which every release
reads.
"""

from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from firewallfabrik.platforms.nftables._utils import (
    NFT_STANDARD_PRIORITIES,
    nft_chain_priority,
)

#: The four names this compiler writes, and the numbers behind them
#: (`std_prios` in netfilter nftables src/rule.c, `NF_IP_PRI_*` in the
#: kernel's include/uapi/linux/netfilter_ipv4.h).
EXPECTED_NUMBERS = {
    'dstnat': '-100',
    'filter': '0',
    'mangle': '-150',
    'srcnat': '100',
}

DATA_FILE = """\
name: 'Test: the release decides how a chain priority is spelled'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'Network'
        name: 'inside-net'
        inet_addr_mask:
          address: '10.0.0.0'
          netmask: '24'
      - type: 'IPv4'
        name: 'server'
        inet_addr_mask:
          address: '192.0.2.10'
          netmask: '32'
      - type: 'Firewall'
        name: 'fw-test'
        data:
          platform: 'nftables'
          host_OS: 'linux24'
          version: '{version}'
        options:
          configure_interfaces: false
          manage_virtual_addr: false
          verify_interfaces: false
        interfaces:
          - name: 'eth0'
            data:
              label: 'outside'
            addresses:
              - type: 'IPv4'
                name: 'eth0-addr'
                inet_addr_mask:
                  address: '192.0.2.1'
                  netmask: '24'
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
            top: true
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
                direction: 'Both'
                options:
                  tagging: true
                  tagvalue: '7'
              - type: 'PolicyRule'
                action: 'Deny'
                direction: 'Both'
          - type: 'NAT'
            name: 'NAT'
            top: true
            rules:
              - type: 'NATRule'
                osrc:
                  - 'Library:Test Objects/Network:inside-net'
                tsrc:
                  - 'Library:Test Objects/IPv4:server'
"""


class _Firewall:
    """The two attributes ``get_nftables_version`` reads."""

    def __init__(self, version: str) -> None:
        self.platform = 'nftables'
        self.version = version


def _compile(tmp_path: Path, version: str) -> str:
    data_file = tmp_path / 'chain-priority.fwf'
    data_file.write_text(DATA_FILE.format(version=version))
    db = DatabaseManager()
    db.load(str(data_file))
    with db.session() as session:
        fw_id = str(
            session.execute(
                sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test'),
            )
            .scalar_one()
            .id
        )
    driver = CompilerDriver_nft(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(tmp_path)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw-test.fw').read_text()


def test_the_numbers_are_the_ones_nftables_names():
    assert {key: str(value) for key, value in NFT_STANDARD_PRIORITIES.items()} == (
        EXPECTED_NUMBERS
    )


@pytest.mark.parametrize('version', ['', '0.9.1', '0.9.5', '1.1.6'])
@pytest.mark.parametrize('name', sorted(EXPECTED_NUMBERS))
def test_a_release_that_reads_the_name_gets_the_name(version, name):
    assert nft_chain_priority(_Firewall(version), name) == name


@pytest.mark.parametrize('name', sorted(EXPECTED_NUMBERS))
def test_an_older_release_gets_the_number(name):
    assert nft_chain_priority(_Firewall('0.9.0'), name) == EXPECTED_NUMBERS[name]


def test_a_firewall_of_another_platform_is_compiled_for_the_newest():
    """An imported ``.fwb`` says iptables and pins an iptables release."""
    other = _Firewall('')
    other.platform = 'iptables'
    other.version = 'lt_1.2.6'
    assert nft_chain_priority(other, 'filter') == 'filter'


def test_a_pinned_0_9_0_ruleset_carries_no_priority_name(tmp_path):
    script = _compile(tmp_path, '0.9.0')

    for name in EXPECTED_NUMBERS:
        assert f'priority {name};' not in script, name
    assert 'type filter hook input priority 0;' in script
    assert 'type filter hook prerouting priority -150;' in script
    assert 'type nat hook prerouting priority -100;' in script
    assert 'type nat hook postrouting priority 100;' in script


def test_a_ruleset_for_a_current_release_keeps_the_names(tmp_path):
    script = _compile(tmp_path, '')

    assert 'type filter hook input priority filter;' in script
    assert 'type filter hook prerouting priority mangle;' in script
    assert 'type nat hook prerouting priority dstnat;' in script
    assert 'type nat hook postrouting priority srcnat;' in script
