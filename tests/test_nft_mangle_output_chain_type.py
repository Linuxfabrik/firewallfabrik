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

"""The mangle table's output chain is a route chain, not a filter one.

An iptables mangle table does one thing in the output hook that no filter
table does: `ipt_mangle_out` remembers the source, the destination, the
ToS byte and the packet mark, and asks `ip_route_me_harder` for a new
route whenever the chain changed one of them
(linux/net/ipv4/netfilter/iptable_mangle.c).  That is what makes a Tag
rule in the output chain steer locally generated traffic at all - set a
mark there and the packet is routed again with it.

nftables says the same thing with the chain *type*.
`nf_route_table_hook4` makes exactly that comparison and calls exactly
that function (linux/net/netfilter/nft_chain_route.c), and a chain
declared `type filter` does none of it: the mark is set, the packet keeps
the route it already had, and nothing anywhere says so.

The inet family is the exception, and only for an old release: it got the
route chain type in Linux 5.2, and an older kernel answers such a chain
with EOPNOTSUPP - which costs the whole ruleset and not the reroute.
"""

from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from firewallfabrik.platforms.nftables._utils import nft_mangle_chain_type

DATA_FILE = """\
name: 'Test: a mark set in the output chain reroutes the packet'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'Network'
        name: 'inside-net'
        inet_addr_mask:
          address: '10.0.0.0'
          netmask: '24'
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
{ipv6_address}
        rule_sets:
          - type: 'Policy'
            name: 'Policy'
            top: true
            rules:
              - type: 'PolicyRule'
                action: 'Accept'
                direction: 'Outbound'
                itf:
                  - 'Library:Test Objects/Firewall:fw-test/Interface:eth0'
                options:
                  tagging: true
                  tagvalue: '7'
              - type: 'PolicyRule'
                action: 'Deny'
                direction: 'Both'
{ipv6_rule_set}
"""

IPV6_ADDRESS = """\
              - type: 'IPv6'
                name: 'eth0-addr6'
                inet_addr_mask:
                  address: '2001:db8::1'
                  netmask: '64'
"""

IPV6_RULE_SET = """\
          - type: 'Policy'
            name: 'Policy_v6'
            top: true
            ipv6: true
            rules:
              - type: 'PolicyRule'
                action: 'Deny'
                direction: 'Both'
"""


class _Firewall:
    """The two attributes `get_nftables_version` reads."""

    def __init__(self, version: str = '') -> None:
        self.platform = 'nftables'
        self.version = version


def _compile(tmp_path: Path, version: str = '', dual_stack: bool = False) -> str:
    data_file = tmp_path / 'mangle-output.fwf'
    data_file.write_text(
        DATA_FILE.format(
            version=version,
            ipv6_address=IPV6_ADDRESS if dual_stack else '',
            ipv6_rule_set=IPV6_RULE_SET if dual_stack else '',
        )
    )
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


@pytest.mark.parametrize('family', ['ip', 'ip6', 'inet'])
@pytest.mark.parametrize('chain', ['prerouting', 'input', 'forward', 'postrouting'])
def test_every_other_hook_stays_a_filter_chain(family, chain):
    """Only the output hook reroutes; the rest are plain filter chains."""
    assert nft_mangle_chain_type(_Firewall(), family, chain) == 'filter'


@pytest.mark.parametrize('family', ['ip', 'ip6', 'inet'])
def test_the_output_hook_is_a_route_chain(family):
    assert nft_mangle_chain_type(_Firewall(), family, 'output') == 'route'


@pytest.mark.parametrize('version', ['0.9.0', '0.9.1'])
def test_an_inet_table_of_an_old_release_keeps_the_filter_chain(version):
    """Linux 5.2 is what gave the inet family a route chain."""
    assert nft_mangle_chain_type(_Firewall(version), 'inet', 'output') == 'filter'
    assert nft_mangle_chain_type(_Firewall(version), 'ip', 'output') == 'route'


@pytest.mark.parametrize('version', ['0.9.2', '0.9.5', '1.1.6', ''])
def test_a_release_with_the_inet_route_chain_gets_it(version):
    assert nft_mangle_chain_type(_Firewall(version), 'inet', 'output') == 'route'


def test_the_generated_ruleset_declares_the_output_chain_as_route(tmp_path):
    script = _compile(tmp_path)

    assert 'type route hook output priority mangle;' in script
    assert 'type filter hook output priority mangle;' not in script


def test_a_dual_stack_firewall_gets_it_too(tmp_path):
    script = _compile(tmp_path, dual_stack=True)

    assert 'table inet fwf_mangle {' in script
    assert 'type route hook output priority mangle;' in script


def test_a_dual_stack_firewall_pinned_below_the_kernel_keeps_the_filter_chain(
    tmp_path,
):
    script = _compile(tmp_path, version='0.9.1', dual_stack=True)

    assert 'table inet fwf_mangle {' in script
    assert 'type filter hook output priority mangle;' in script
    assert 'type route hook output priority mangle;' not in script
