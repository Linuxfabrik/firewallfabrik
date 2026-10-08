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

"""A firewall has one routing table, so it has one routing rule set.

Firewall Builder refuses a second one (``Firewall::validateChild``, "there
can be only one") and does not offer "New Routing Rule Set" at all.  The
editor here offered it, and both drivers then compiled whichever routing
rule set the database returned first: the routes of the other one were
missing from the script, and nothing said so.
"""

import pathlib
import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall, Routing, RoutingRule, rule_elements
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = (
    pathlib.Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
)


def _firewall_with_routes(session):
    for rs in session.scalars(sqlalchemy.select(Routing)):
        if rs.rules and isinstance(rs.device, Firewall):
            return rs.device, rs
    raise AssertionError('the fixture holds no firewall with routes')


def _second_routing_rule_set(session, fw, source, with_rule):
    second = Routing(id=uuid.uuid4(), device_id=fw.id, name='Routing 2')
    session.add(second)
    session.flush()
    if with_rule:
        original = source.rules[0]
        copy = RoutingRule(
            id=uuid.uuid4(),
            rule_set_id=second.id,
            position=0,
            routing_rule_type=original.routing_rule_type,
            options=dict(original.options or {}),
        )
        session.add(copy)
        session.flush()
        for row in session.execute(
            sqlalchemy.select(rule_elements).where(
                rule_elements.c.rule_id == original.id
            )
        ):
            session.execute(
                rule_elements.insert().values(
                    rule_id=copy.id,
                    slot=row.slot,
                    target_id=row.target_id,
                    position=row.position,
                )
            )


def _run(driver_cls, with_rule, tmp_path):
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    with dm.session() as session:
        fw, routing = _firewall_with_routes(session)
        _second_routing_rule_set(session, fw, routing, with_rule)
        fw_id = str(fw.id)
        fw_name = fw.name
    driver = driver_cls(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return driver, fw_name


@pytest.mark.parametrize('driver_cls', [CompilerDriver_ipt, CompilerDriver_nft])
def test_two_routing_rule_sets_with_rules_are_refused(tmp_path, driver_cls):
    driver, fw_name = _run(driver_cls, True, tmp_path)
    assert any(
        f'{fw_name}: 2 routing rule sets hold rules' in e for e in driver.all_errors
    ), driver.all_errors


@pytest.mark.parametrize('driver_cls', [CompilerDriver_ipt, CompilerDriver_nft])
def test_an_empty_second_routing_rule_set_changes_nothing(tmp_path, driver_cls):
    driver, _fw_name = _run(driver_cls, False, tmp_path)
    assert not any('routing rule sets hold rules' in e for e in driver.all_errors)
    assert ' route ' in (tmp_path / 'fw.fw').read_text()
