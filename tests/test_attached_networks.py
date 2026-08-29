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

"""An "Attached Networks" object stands for the subnets of its interface.

`AttachedNetworks::loadFromSource` reads the addresses of the parent
interface and turns each of them into the network it sits in;
`Preprocessor_ipt::convertObject` is what calls it.  Neither had a port:
the object resolved to nothing, so a rule naming it matched nothing and
said so as an empty group.

Firewall Builder marks the object run time when the parent interface is
not a regular one and then writes `$i_<iface>_network` into the rule, a
shell variable nothing in its generated script sets.  There is nothing to
write down at compile time for such an interface, so it is reported here
instead ([#85]).

[#85]: https://github.com/Linuxfabrik/firewallfabrik/issues/85
"""

import uuid
from pathlib import Path

import pytest

import firewallfabrik.core
from firewallfabrik.core.objects import (
    AttachedNetworks,
    Firewall,
    FWObjectDatabase,
    Interface,
    IPv4,
    IPv6,
    Library,
    Policy,
    PolicyAction,
    PolicyRule,
    rule_elements,
)
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURES = Path(__file__).parent / 'fixtures'


def _element(session, rule, slot, target_id):
    session.execute(
        rule_elements.insert().values(
            rule_id=rule.id, slot=slot, target_id=target_id, position=0
        )
    )


def _tree(*, dynamic=False, ipv6=False):
    """A firewall with one interface and a rule naming its attached networks."""
    dm = firewallfabrik.core.DatabaseManager('sqlite://')
    with dm.session() as session:
        database = FWObjectDatabase(id=uuid.uuid4(), name='fwf')
        session.add(database)
        session.flush()
        library = Library(id=uuid.uuid4(), name='User', database=database)
        session.add(library)
        session.flush()

        fw = Firewall(
            id=uuid.uuid4(),
            type='Firewall',
            name='fw-test',
            library=library,
            data={'platform': 'iptables', 'host_OS': 'linux24'},
        )
        session.add(fw)
        iface = Interface(
            id=uuid.uuid4(),
            name='eth0',
            device=fw,
            library=library,
            data={'dyn': dynamic},
        )
        session.add(iface)
        # Two addresses in different subnets, and a second address in the
        # first one so the duplicate has something to be removed from.
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='fw-test:eth0:ip',
                interface=iface,
                inet_addr_mask={'address': '192.0.2.5', 'netmask': '255.255.255.0'},
            )
        )
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='fw-test:eth0:ip-1',
                interface=iface,
                inet_addr_mask={'address': '192.0.2.6', 'netmask': '255.255.255.0'},
            )
        )
        session.add(
            IPv4(
                id=uuid.uuid4(),
                type='IPv4',
                name='fw-test:eth0:ip-2',
                interface=iface,
                inet_addr_mask={
                    'address': '198.51.100.9',
                    'netmask': '255.255.255.0',
                },
            )
        )
        session.add(
            IPv6(
                id=uuid.uuid4(),
                type='IPv6',
                name='fw-test:eth0:ip6',
                interface=iface,
                inet_addr_mask={'address': '2001:db8:1::5', 'netmask': '64'},
            )
        )

        attached = AttachedNetworks(
            id=uuid.uuid4(),
            type='AttachedNetworks',
            name='fw-test:eth0:attached',
            library=library,
            interface=iface,
        )
        session.add(attached)

        rule_set = Policy(
            id=uuid.uuid4(),
            type='Policy',
            name='Policy',
            device=fw,
            top=True,
            ipv4=True,
            ipv6=ipv6,
        )
        session.add(rule_set)
        rule = PolicyRule(
            id=uuid.uuid4(),
            type='PolicyRule',
            rule_set=rule_set,
            position=0,
            policy_action=PolicyAction.Accept,
        )
        session.add(rule)
        session.flush()
        _element(session, rule, 'src', attached.id)
        fw_id = str(fw.id)
    return dm, fw_id


def _compile(dm, fw_id, tmp_path, driver_cls=CompilerDriver_ipt):
    driver = driver_cls(dm)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = 'fw-test.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return driver, (tmp_path / 'fw-test.fw').read_text()


@pytest.mark.parametrize('driver_cls', [CompilerDriver_ipt, CompilerDriver_nft])
def test_it_stands_for_every_subnet_of_the_interface(tmp_path, driver_cls):
    dm, fw_id = _tree()

    _driver, script = _compile(dm, fw_id, tmp_path, driver_cls)

    assert '192.0.2.0/24' in script
    assert '198.51.100.0/24' in script


def test_two_addresses_in_one_subnet_give_one_network(tmp_path):
    """``loadFromSource`` collects into a map keyed on the subnet.

    eth0 carries two addresses in 192.0.2.0/24 and one in
    198.51.100.0/24.  Without the map the first subnet arrives twice, and
    the rule is then installed twice for it - which is what the counts
    below would show.
    """
    dm, fw_id = _tree()

    _driver, script = _compile(dm, fw_id, tmp_path)

    rules = [line for line in script.splitlines() if '$IPTABLES' in line]
    first = sum(1 for line in rules if '192.0.2.0/24' in line)
    second = sum(1 for line in rules if '198.51.100.0/24' in line)
    assert first and first == second, (first, second)


def test_the_ipv6_pass_gets_the_ipv6_subnet(tmp_path):
    dm, fw_id = _tree(ipv6=True)

    _driver, script = _compile(dm, fw_id, tmp_path)

    assert '2001:db8:1::/64' in script
    # And the IPv4 pass does not see it.
    assert '2001:db8:1::/64' not in script.split('$IP6TABLES')[0]


def test_a_dynamic_interface_is_reported(tmp_path):
    """There is no address to work the subnets out from before it runs.

    Firewall Builder writes ``$i_eth0_network`` here, a variable its own
    script never sets.
    """
    dm, fw_id = _tree(dynamic=True)

    driver, script = _compile(dm, fw_id, tmp_path)

    assert any('Attached Networks' in message for message in driver.all_errors), (
        driver.all_errors
    )
    assert '$i_eth0_network' not in script
