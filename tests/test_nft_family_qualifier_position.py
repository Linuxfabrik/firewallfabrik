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

"""Where the address family of a rule in a shared ``inet`` table is named.

A dual-stack firewall writes the rules of both compilation passes into one
``inet`` table, so a rule matching only ports, state, marks or interfaces
has to say which family it belongs to.  ``meta nfproto`` says it - but only
as long as the machine still shows it.

nft reads a ``meta nfproto`` comparison as a protocol dependency and drops
it from the listing as soon as a protocol expression follows
(``meta_match_postprocess`` stores it and ``payload_dependency_kill``
releases it, netfilter nftables src/netlink_delinearize.c).  The kernel
keeps both comparisons, so the installed rule is right either way; the
*listed* one is not.  ``meta nfproto ipv4 meta l4proto icmp`` comes back as
``meta l4proto icmp``, and that matches an IPv6 packet whose last
next-header is 1 as well - which is what an administrator reloads after
``nft list ruleset > /etc/nftables.conf``, the file nftables.service
restores from.

Writing the qualifier at the end of the match half answers it: nothing
follows it there, so nothing can release it.
"""

import shutil
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import CAN_ASK_NFT, SKIP_REASON

DATA_FILE = """\
name: 'Test: a shared inet table names the family where nft keeps it'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'IPService'
        name: 'esp'
        named_protocols:
          protocol_num: '50'
      - type: 'Firewall'
        name: 'fw-test'
        data:
          platform: 'nftables'
          host_OS: 'linux24'
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
              - type: 'IPv6'
                name: 'eth0-addr6'
                inet_addr_mask:
                  address: '2001:db8::1'
                  netmask: '64'
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
            top: true
            ipv4: true
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
                direction: 'Both'
                srv:
                  - 'Library:Test Objects/IPService:esp'
          - type: 'Policy'
            name: 'Policy_v6'
            top: true
            ipv6: true
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
                direction: 'Both'
                srv:
                  - 'Library:Test Objects/IPService:esp'
"""


def _ruleset(tmp_path: Path) -> str:
    """The nftables ruleset the script carries, without the shell around it."""
    data_file = tmp_path / 'family-qualifier.fwf'
    data_file.write_text(DATA_FILE)
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
    script = (tmp_path / 'fw-test.fw').read_text()

    lines: list[str] = []
    inside = False
    for line in script.splitlines():
        if line == 'NFT_RULES':
            inside = False
            continue
        if not inside and line.rstrip().endswith(("<<'NFT_RULES'", '<<NFT_RULES')):
            inside = True
            continue
        if inside:
            lines.append(line)
    return '\n'.join(lines)


def _rules_matching(ruleset: str, keyword: str) -> list[str]:
    return [
        line.strip()
        for line in ruleset.splitlines()
        if keyword in line and not line.lstrip().startswith('#')
    ]


def test_the_family_is_named_after_the_protocol_and_not_before(tmp_path):
    rules = _rules_matching(_ruleset(tmp_path), 'meta l4proto')

    assert rules, 'the fixture produced no rule matching on a protocol number'
    for rule in rules:
        assert 'meta nfproto' in rule, rule
        assert rule.index('meta nfproto') > rule.index('meta l4proto'), rule


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
def test_the_family_is_still_there_when_the_machine_lists_the_ruleset(tmp_path):
    ruleset = _ruleset(tmp_path)
    rules_file = tmp_path / 'ruleset.nft'
    rules_file.write_text(ruleset + '\n')

    listed = subprocess.run(  # nosec B603
        [
            shutil.which('unshare') or 'unshare',
            '-rn',
            'bash',
            '-c',
            f'nft --file {rules_file} && nft list ruleset',
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    for rule in _rules_matching(listed, 'meta l4proto'):
        assert 'meta nfproto' in rule, rule
