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

"""A Custom action carries one statement per packet filter (issue #161).

Firewall Builder stores one string and has no second Linux platform to
need another, so a firewall switched from iptables to nftables kept
`-j TCPMSS --set-mss 1400` where it was and the rule stopped compiling.
The statement is now stored the way a Custom Service stores its code: one
per platform, and each compiler reads its own.

The platform-less field is still read, for the platform whose syntax it is
in - an iptables target begins with a `-` - so every rule imported from a
`.fwb` file goes on compiling for the packet filter it was written for.
And where such a target has an nftables statement, the nftables compiler
writes that one rather than leaving the rule out; the targets that have
none are still reported.  See `test_custom_action_translation.py`.
"""

import uuid
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall, PolicyAction
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.linux._netfilter import custom_action_statement
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

IPT_STATEMENT = '-j TCPMSS --set-mss 1400'
NFT_STATEMENT = 'tcp option maxseg size set 1400'

#: An iptables target with no nftables statement anywhere: TARPIT never
#: was in mainline netfilter, so nothing translates it.
UNTRANSLATABLE_IPT_STATEMENT = '-j TARPIT'

DATA_FILE = """\
name: 'Test: a custom action per packet filter'
libraries:
  - name: 'Test Objects'
    children:
      - type: 'Firewall'
        name: 'fw-test'
        data:
          platform: '{platform}'
          host_OS: 'linux24'
          version: ''
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
                position: 0
                action: 'Custom'
                direction: 'Both'
                options:
{options}
              - type: 'PolicyRule'
                position: 1
                action: 'Deny'
                direction: 'Both'
"""


def _rule(**options) -> CompRule:
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Custom,
    )


def _compile(tmp_path: Path, driver_class, platform: str, **options) -> str:
    body = '\n'.join(f"                  {k}: '{v}'" for k, v in options.items())
    data_file = tmp_path / 'custom-action.fwf'
    data_file.write_text(DATA_FILE.format(platform=platform, options=body))
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
    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(tmp_path)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw-test.fw').read_text()


# -- the reader ------------------------------------------------------------


def test_each_platform_reads_its_own_statement():
    rule = _rule(
        custom_str_iptables=IPT_STATEMENT,
        custom_str_nftables=NFT_STATEMENT,
    )
    assert custom_action_statement(rule, 'iptables') == IPT_STATEMENT
    assert custom_action_statement(rule, 'nftables') == NFT_STATEMENT


def test_a_platform_with_no_statement_gets_nothing():
    rule = _rule(custom_str_nftables=NFT_STATEMENT)
    assert custom_action_statement(rule, 'iptables') == ''
    assert custom_action_statement(rule, 'nftables') == NFT_STATEMENT


@pytest.mark.parametrize(
    ('statement', 'platform'),
    [(UNTRANSLATABLE_IPT_STATEMENT, 'iptables'), (NFT_STATEMENT, 'nftables')],
)
def test_the_platform_less_field_is_read_for_the_syntax_it_is_in(statement, platform):
    """Every rule imported from a `.fwb` file carries only that one."""
    other = 'nftables' if platform == 'iptables' else 'iptables'
    rule = _rule(custom_str=statement)
    assert custom_action_statement(rule, platform) == statement
    assert custom_action_statement(rule, other) == ''


def test_the_platform_field_wins_over_the_platform_less_one():
    rule = _rule(custom_str=IPT_STATEMENT, custom_str_iptables='-j LOG')
    assert custom_action_statement(rule, 'iptables') == '-j LOG'


def test_a_rule_with_no_custom_action_has_nothing_for_either():
    rule = _rule()
    assert custom_action_statement(rule, 'iptables') == ''
    assert custom_action_statement(rule, 'nftables') == ''


def test_whitespace_is_not_a_statement():
    rule = _rule(custom_str_nftables='   ', custom_str='  ')
    assert custom_action_statement(rule, 'nftables') == ''


# -- the compilers ---------------------------------------------------------


def test_a_firewall_carrying_both_gets_the_right_one_on_each(tmp_path):
    script = _compile(
        tmp_path,
        CompilerDriver_ipt,
        'iptables',
        custom_str_iptables=IPT_STATEMENT,
        custom_str_nftables=NFT_STATEMENT,
    )
    assert IPT_STATEMENT in script
    assert NFT_STATEMENT not in script

    script = _compile(
        tmp_path,
        CompilerDriver_nft,
        'nftables',
        custom_str_iptables=IPT_STATEMENT,
        custom_str_nftables=NFT_STATEMENT,
    )
    assert NFT_STATEMENT in script
    assert IPT_STATEMENT not in script


def test_a_rule_imported_from_firewall_builder_still_compiles_for_iptables(tmp_path):
    script = _compile(
        tmp_path, CompilerDriver_ipt, 'iptables', custom_str=IPT_STATEMENT
    )
    assert IPT_STATEMENT in script


def test_a_rule_imported_from_firewall_builder_compiles_for_nftables_too(tmp_path):
    """The target has a translation, so the rule is written, not dropped."""
    script = _compile(
        tmp_path, CompilerDriver_nft, 'nftables', custom_str=IPT_STATEMENT
    )
    assert NFT_STATEMENT in script
    assert IPT_STATEMENT not in script


def test_the_firewall_platform_does_not_decide_whether_the_rule_compiles(tmp_path):
    """A `.fwb` firewall says iptables whatever it is compiled with."""
    script = _compile(
        tmp_path, CompilerDriver_nft, 'iptables', custom_str=IPT_STATEMENT
    )
    assert NFT_STATEMENT in script


def test_the_same_rule_is_reported_on_nftables_when_nothing_translates_it(tmp_path):
    script = _compile(
        tmp_path,
        CompilerDriver_nft,
        'nftables',
        custom_str=UNTRANSLATABLE_IPT_STATEMENT,
    )

    rules = [
        line
        for line in script.splitlines()
        if UNTRANSLATABLE_IPT_STATEMENT in line and not line.lstrip().startswith('#')
    ]
    assert not rules, rules
    assert 'no nftables statement' in script
    assert 'under "nftables" in the action panel' in script
