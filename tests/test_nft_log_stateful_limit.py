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

"""A logged rule with a stateful limit gets the chain iptables gives it.

A firewall may cap how often a rule logs, and that cap belongs to the log
message and not to the traffic, so a logged rule becomes a rate-limited log
line and a line carrying the verdict.  Both hold the whole match, which is
right until the match holds state: a connection limit and a rate limit kept
per key are consumed by every evaluation, so a packet crossing both lines is
counted twice and half the traffic the rule is meant to stop passes it.

``PolicyCompiler_ipt::Logging2`` answers that with three rules - the match
and the stateful limit on a jump, the log rule and the action rule in the
chain it jumps to - and this is the nftables counterpart.  It used to drop
the firewall's log rate and warn, so the same policy logged at two different
rates on the two platforms.
"""

import pathlib

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Firewall, PolicyRule
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = (
    pathlib.Path(__file__).parent / 'fixtures' / 'objects-for-regression-tests.fwb'
)
#: firewall.fw rule 13, "reject using connlimit": a connection limit, a
#: destination pair and a firewall that caps its log messages at 5/second.
FIREWALL = 'firewall'
RULE = 13


@pytest.fixture
def compiled(tmp_path):
    """The nftables script of *FIREWALL* with rule *RULE* logging."""
    tree = firewallfabrik.core.DatabaseManager('sqlite://')
    tree.load(str(FIXTURE))
    with tree.session() as session:
        firewall = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == FIREWALL),
        ).one()
        fw_id = str(firewall.id)
        rule = session.scalars(
            sqlalchemy.select(PolicyRule).where(PolicyRule.position == RULE),
        ).first()
        rule.options = {**(rule.options or {}), 'log': True}
    driver = CompilerDriver_nft(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / 'fw.fw').read_text()


def _chain_body(script: str, name: str) -> list[str]:
    """Return the rule lines of the chain called *name*."""
    lines = script.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.strip() == f'chain {name} {{'
    )
    body = []
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped == '}':
            break
        if stripped and not stripped.startswith(('#', 'type ')):
            body.append(stripped)
    return body


def test_the_match_and_the_limit_sit_on_a_jump(compiled):
    jumps = [
        line
        for line in compiled.splitlines()
        if 'ct count over 2' in line and ' jump ' in line
    ]
    assert jumps, compiled
    for line in jumps:
        # The whole match is here and evaluated once, which is the point.
        assert 'ip daddr' in line
        assert 'log' not in line


def test_the_chain_holds_the_log_rate_and_the_verdict(compiled):
    name = next(
        line.split(' jump ')[1].strip()
        for line in compiled.splitlines()
        if 'ct count over 2' in line and ' jump ' in line
    )
    body = _chain_body(compiled, name)
    assert len(body) == 2, body
    log_line, verdict_line = body
    assert 'limit rate 5/second' in log_line
    assert ' log ' in f' {log_line} '
    # Nothing stateful may be repeated on the second line.
    assert 'ct count' not in log_line
    assert 'ct count' not in verdict_line
    assert verdict_line.endswith('drop')


def test_the_rule_is_not_reported(compiled):
    assert 'keeps its own rate limit' not in compiled


def test_a_plain_rate_limit_is_not_paid_twice(tmp_path):
    """The jump keeps every limit, the two lines below it keep none.

    A rule may carry a plain rate limit beside the connection limit, and a
    packet crosses the log line and then the action line: a limit left on
    both is a second bucket the same packet has to pay, so only half the
    packets a "20 per second" rule admits reach its action.  `Logging2`
    clears all three on both of its chain rules for that reason.
    """
    tree = firewallfabrik.core.DatabaseManager('sqlite://')
    tree.load(str(FIXTURE))
    with tree.session() as session:
        fw_id = str(
            session.scalars(
                sqlalchemy.select(Firewall).where(Firewall.name == FIREWALL),
            )
            .one()
            .id
        )
        rule = session.scalars(
            sqlalchemy.select(PolicyRule).where(PolicyRule.position == RULE),
        ).first()
        rule.options = {
            **(rule.options or {}),
            'log': True,
            'limit_value': 20,
            'limit_suffix': '/second',
        }
    driver = CompilerDriver_nft(tree)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURE.parent)
    driver.file_name_setting = 'fw.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    script = (tmp_path / 'fw.fw').read_text()

    name = next(
        line.split(' jump ')[1].strip()
        for line in script.splitlines()
        if 'ct count over 2' in line and ' jump ' in line
    )
    jumps = [line for line in script.splitlines() if f'jump {name}' in line]
    assert jumps and all('limit rate 20/second' in line for line in jumps), jumps
    body = _chain_body(script, name)
    assert not any('limit rate 20/second' in line for line in body), body
