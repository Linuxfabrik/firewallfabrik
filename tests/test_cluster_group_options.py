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

"""What a cluster group's protocol options may hold, and what happens if not.

The port and the address of a failover or state sync group are free text
in the data file: the option dialog of every protocol writes the port
through a spin box, but a `.fwb` written by an older release, another
tool or a text editor carries whatever it carries.  Firewall Builder
reads the port with `atoi` (`AutomaticRules_ipt.cpp`) and therefore
writes `--dport 0` for a word; the address it checks against both address
families and then builds an IPv4 object out of whatever came back.

Both cases are answered here: a port that is not a number is reported and
the rules of that group are left out, and an IPv6 address gets an IPv6
object so the rules survive into the IPv6 pass instead of disappearing
without a word.
"""

import pathlib
import tempfile
import uuid

import pytest
import sqlalchemy

import firewallfabrik.core
from firewallfabrik.core.objects import Cluster, Firewall, Group, IPv6, RuleSet
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURE = pathlib.Path(__file__).parent / 'fixtures' / 'cluster-tests.fwb'


def _compile(driver_cls, cluster_name, member_name, group_options, dual_stack=False):
    """Compile one member with *group_options* merged into every group.

    *dual_stack* marks every rule set of the fixture IPv6 as well and
    gives every interface of the member an IPv6 address.  Both are needed
    before an IPv6 rule can be written at all: a rule set that claims
    neither family is IPv4-only (``RuleSet::isV4``) and the fixture's
    clusters were written before the flags existed, and a rule scoped to
    an interface with no address of the family is dropped.

    Returns the generated script (empty when nothing was written) and the
    driver's errors.
    """
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    dm.load(str(FIXTURE))
    with dm.session() as session:
        cluster = session.scalars(
            sqlalchemy.select(Cluster).where(Cluster.name == cluster_name),
        ).one()
        member = session.scalars(
            sqlalchemy.select(Firewall).where(Firewall.name == member_name),
        ).one()
        cluster_id, fw_id = str(cluster.id), str(member.id)
        for group in session.scalars(sqlalchemy.select(Group)).all():
            if group.type not in ('FailoverClusterGroup', 'StateSyncClusterGroup'):
                continue
            options = dict(group.options or {})
            options.update(group_options)
            group.options = options
        if dual_stack:
            for rule_set in session.scalars(sqlalchemy.select(RuleSet)).all():
                rule_set.ipv4 = True
                rule_set.ipv6 = True
            for number, iface in enumerate(member.interfaces, start=1):
                address = IPv6(
                    id=uuid.uuid4(),
                    name=f'{iface.name}:ip6',
                    interface_id=iface.id,
                    library_id=iface.library_id,
                )
                address.data = {}
                address.inet_addr_mask = {
                    'address': f'2001:db8::{number}',
                    'netmask': '64',
                }
                session.add(address)
        session.commit()

    with tempfile.TemporaryDirectory() as tmp:
        driver = driver_cls(dm)
        driver.wdir = tmp
        driver.source_dir = str(FIXTURE.parent)
        driver.file_name_setting = 'member.fw'
        driver.run(cluster_id=cluster_id, fw_id=fw_id, single_rule_id='')
        script = pathlib.Path(tmp) / 'member.fw'
        return (script.read_text() if script.exists() else ''), list(driver.all_errors)


@pytest.mark.parametrize(
    ('driver_cls', 'platform'),
    [(CompilerDriver_ipt, 'ipt'), (CompilerDriver_nft, 'nft')],
)
def test_a_port_that_is_not_a_number_is_reported(driver_cls, platform):
    """It used to end the compile with a `ValueError` traceback.

    `int('conntrack')` raises, and nothing between `AutomaticRules.build`
    and `main()` catches it, so the administrator saw a Python traceback
    instead of a message naming the option.
    """
    _script, errors = _compile(
        driver_cls,
        'heartbeat_cluster_1',
        'linux-1',
        {'conntrack_port': 'not-a-port'},
    )

    assert any('is not a port number' in e for e in errors), errors
    assert any('conntrack_port' in e for e in errors), errors


@pytest.mark.parametrize(
    ('driver_cls', 'platform'),
    [(CompilerDriver_ipt, 'ipt'), (CompilerDriver_nft, 'nft')],
)
def test_a_port_out_of_range_is_reported_by_the_group_it_is_on(driver_cls, platform):
    """65536 parses, so only the range check keeps it out of the rule."""
    _script, errors = _compile(
        driver_cls,
        'heartbeat_cluster_1',
        'linux-1',
        {'conntrack_port': '65536'},
    )

    assert any('is not a port number' in e for e in errors), errors


def test_a_port_the_group_does_not_set_falls_back_to_the_default():
    """An empty value means "the protocol's own port", not "port 0"."""
    script, _errors = _compile(
        CompilerDriver_ipt,
        'heartbeat_cluster_1',
        'linux-1',
        {'conntrack_port': ''},
    )

    assert '--dport 3780' in script


def test_an_ipv6_group_address_keeps_its_rules():
    """The address used to reach an IPv4 object and vanish there.

    `_address` built an `IPv4` whatever the text said, so an IPv6 sync
    address produced an object the IPv4 pass drops for its family and the
    IPv6 pass never sees - the state sync traffic was blocked and no
    message said why.
    """
    script, errors = _compile(
        CompilerDriver_ipt,
        'heartbeat_cluster_1',
        'linux-1',
        {'conntrack_address': 'ff02::1'},
        dual_stack=True,
    )

    assert 'ff02::1' in script, errors
    assert '$IP6TABLES' in script


def test_an_ipv6_group_address_keeps_its_rules_on_nftables_too():
    script, errors = _compile(
        CompilerDriver_nft,
        'heartbeat_cluster_1',
        'linux-1',
        {'conntrack_address': 'ff02::1'},
        dual_stack=True,
    )

    assert 'ff02::1' in script, errors
