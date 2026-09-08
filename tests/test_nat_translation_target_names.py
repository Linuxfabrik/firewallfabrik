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

"""A host name is no address for the NAT target options.

`-s` and `-d` resolve one - that is what a run-time DNS Name is for, and
the resolution happens on the firewall while the script runs.  The NAT
target options do not: `parse_to` in netfilter's `extensions/libxt_NAT.c`
reads the address with `inet_pton`, and every release before it did the
same (`dotted_to_addr` up to 1.4.0, `xtables_numeric_to_ipaddr` after),
so `--to-destination backend.example.com` is answered with

    iptables v1.8.11 (nf_tables): Bad IP address "backend.example.com"

and an exit code of 2.  The activation script stops at that command with
every built-in policy already set to DROP.

Firewall Builder writes the name out all the same
(`NATCompiler_ipt::PrintRule::_printAddr`), so this was inherited rather
than introduced.  The nftables compiler already refused such a rule, for
a reason of its own - nft resolves the name while parsing and throws away
the whole ruleset when it has a second address - and the two platforms
have to give one and the same object the same answer.

The fixture is written here rather than kept under `tests/fixtures/`,
because a firewall whose only NAT rule is reported has no expected output
to compare against: the regression framework fails a compile that reports
anything.
"""

import textwrap

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

DATA_FILE = """
name: 'NAT translating to a run-time DNS name'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'Firewall'
        name: 'fw-test'
        data:
          platform: 'iptables'
          host_OS: 'linux24'
          version: ''
        options:
          accept_established: false
          configure_interfaces: false
          flush_ruleset: false
          load_modules: false
          manage_virtual_addr: false
          verify_interfaces: false
        interfaces:
          - name: 'eth0'
            addresses:
              - type: 'IPv4'
                name: 'eth0-addr'
                inet_addr_mask:
                  address: '203.0.113.1'
                  netmask: '255.255.255.0'
        rule_sets:
          - type: 'NAT'
            name: 'NAT'
            ipv4: true
            top: true
            rules:
              - type: 'NATRule'
                action: 'Translate'
                odst:
                  - 'Library:Test Objects/Firewall:fw-test/Interface:eth0/IPv4:eth0-addr'
                tdst:
                  - 'Library:Test Objects/DNSName:backend'
          - type: 'Policy'
            name: 'Policy'
            ipv4: true
            top: true
            rules:
              - type: 'PolicyRule'
                action: 'Deny'
                direction: 'Both'
      - type: 'DNSName'
        name: 'backend'
        data:
          dnsrec: 'backend.example.com'
          run_time: true
"""


def _compile(tmp_path, driver_class):
    path = tmp_path / 'dns-nat.fwf'
    path.write_text(textwrap.dedent(DATA_FILE).lstrip())
    db = DatabaseManager()
    db.load(str(path))
    with db.session() as session:
        fw_id = str(
            session.execute(
                sqlalchemy.select(Firewall).where(Firewall.name == 'fw-test'),
            )
            .scalar_one()
            .id
        )
    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(tmp_path)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return driver, (tmp_path / 'fw-test.fw').read_text()


@pytest.mark.parametrize(
    'driver_class', [CompilerDriver_ipt, CompilerDriver_nft], ids=['ipt', 'nft']
)
def test_a_dns_name_is_no_translation_target(tmp_path, driver_class):
    driver, script = _compile(tmp_path, driver_class)

    assert any('cannot be a NAT translation target' in e for e in driver.all_errors), (
        driver.all_errors
    )
    # The name reaches the script only as the comment that says why the
    # rule is not there.
    for line in script.splitlines():
        if line.lstrip().startswith('#'):
            continue
        assert 'backend.example.com' not in line, line
