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

"""The three rules a negation expansion builds carry a suffix each.

`SrcNegation`, `DstNegation`, `SrvNegation` and `TimeNegation` write
``subrule_suffix`` 1, 2 and 3 onto the jump, the RETURN and the action
rule.  Every chain name derived afterwards carries it: the temporary
chain of a nested negation and, through `getNewChainName`, the chain a
logged or accounting rule gets - ``RULE_4_3`` rather than ``RULE_4``.

Without it two subrules of one rule ask for the same name, and only the
counter behind the temporary chain hash keeps them apart; the named
chains of `Logging2` and `Accounting` have no such counter and would be
one chain holding the rules of both.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt

FIXTURE = (
    pathlib.Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
)


@pytest.fixture(scope='module')
def tree():
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    return dm


def _compile(tree, name, tmp_path):
    with tree.session() as session:
        fw_id = str(
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == name),
            )
            .one()
            .id
        )
    driver = CompilerDriver_ipt(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw.fw').read_text()


def test_a_logged_rule_behind_a_negation_names_the_subrule(tree, tmp_path):
    """firewall31 rules 4 and 5 negate the time and log the action.

    The reference output calls those chains RULE_4_3 and RULE_5_3.
    """
    script = _compile(tree, 'firewall31', tmp_path)

    assert '-N RULE_4_3' in script
    assert '-N RULE_5_3' in script
    assert '-N RULE_4 ' not in script
    assert '-N RULE_5 ' not in script


def test_the_suffix_is_the_one_the_reference_writes(tree, tmp_path):
    """firewall10 rule 7 negates the service and rejects with a log."""
    script = _compile(tree, 'firewall10', tmp_path)

    assert '-A RULE_7_3  -j REJECT' in script
