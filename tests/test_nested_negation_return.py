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

"""The RETURN rule of a negation returns, whatever the rule it came from did.

A rule with two negated elements is expanded twice: the second expansion
duplicates the jump rule of the first, which already carries a target.
`SrcNegation`, `DstNegation`, `SrvNegation` and `TimeNegation` therefore
clear ``ipt_target`` on the copy they turn into the RETURN rule
(`PolicyCompiler_ipt.cpp`, one ``setStr("ipt_target","")`` in each), and
`decideOnTarget` fills RETURN in afterwards.

Without that the RETURN becomes a second jump into the chain that holds
the action, so the traffic the negation exists to exclude gets the
action instead - an Accept rule that reads "outside business hours"
accepts during them as well.
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


def test_a_time_negation_inside_a_destination_negation_returns(tree, tmp_path):
    """firewall1 rule 30 negates the destination and the time.

    The reference writes the time match with ``-j RETURN``
    (`firewall1.fw.orig`: ``-A Cid414532F3.1 -m time ... -j RETURN``).
    """
    script = _compile(tree, 'firewall1', tmp_path)
    block = script.split('# Rule 30 (global)')[1].split('# Rule 31 (global)')[0]

    time_rules = [
        line.strip()
        for line in block.splitlines()
        if '-m time' in line and '--timestart 09:00' in line
    ]
    assert time_rules, 'the negated time match is not in the rule at all'
    for line in time_rules:
        assert line.endswith('-j RETURN'), line


def test_an_emptied_element_is_not_negated_any_more(tree, tmp_path):
    """firewall1 rule 30 negates the destination and the time.

    `DstNegation` empties the interval on the two rules it puts into its
    chain, and `TimeNegation` runs afterwards.  An element that says
    "any" cannot be negated - ``RuleElement::reset()`` clears the flag
    with the children - so those two must not be expanded a second time.
    The reference builds two chains for the rule, not four.
    """
    script = _compile(tree, 'firewall1', tmp_path)
    block = script.split('# Rule 30 (global)')[1].split('# Rule 31 (global)')[0]

    chains = {line.split()[-2] for line in block.splitlines() if ' -N ' in line}
    assert len(chains) == 2, sorted(chains)
