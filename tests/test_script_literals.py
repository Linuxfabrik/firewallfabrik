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

"""Object names that reach the generated script instead of a rule.

Every value guarded so far - the packet mark, the user id, the ToS byte,
the rate-limit table name, the chain and interface names of a match - was
guarded because it goes into an iptables or nft command.  Three names go
somewhere else: into the shell script the commands are wrapped in.

    grep -Ev '^#|^;|^\\s*$' <file> | ... | while read -r L    # iptables
    getaddr <iface>  i_<iface>                                # iptables
    $IPTABLES -s <dnsname>                                    # iptables
    check_address_table_file "<file>"                         # nftables
    load_dns_name "inet" "t" "s" "<dnsname>" "-4"             # nftables
    load_interface_address "inet" "t" "s" "<iface>" "-4"      # nftables

A bare word is shell syntax outright, and a double-quoted one still
expands ``$``, a backtick and a backslash - so any of those in the name
of an address table's data file, of a run-time DNS name or of a dynamic
interface runs a command as root at the moment every chain is already at
DROP.  The alphabets below are positive lists, the same answer the
rate-limit table name and the chain name got.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import (
    VerifyScriptLiterals,
    script_literal_problem,
)
from firewallfabrik.core.objects import (
    AddressTable,
    DNSName,
    Interface,
    PolicyAction,
)


def _table(filename, run_time=True):
    obj = AddressTable()
    obj.id = uuid.uuid4()
    obj.name = 'blocklist'
    obj.data = {'run_time': run_time, 'filename': filename}
    return obj


def _dns(name, run_time=True):
    obj = DNSName()
    obj.id = uuid.uuid4()
    obj.name = 'mirror'
    obj.data = {'run_time': run_time, 'dnsrec': name}
    return obj


def _interface(name, dynamic=True):
    obj = Interface()
    obj.id = uuid.uuid4()
    obj.name = name
    obj.data = {'dyn': dynamic}
    return obj


@pytest.mark.parametrize(
    'filename',
    [
        'block-hosts.tbl',
        '/var/lib/fwf/block-hosts.tbl',
        'addr-table-1.tbl',
    ],
)
def test_a_data_file_the_script_can_read(filename):
    assert not script_literal_problem(_table(filename))


@pytest.mark.parametrize(
    'filename',
    [
        'block $(reboot).tbl',
        'block;reboot.tbl',
        'block`id`.tbl',
        'two words.tbl',
        'block|reboot.tbl',
    ],
)
def test_a_data_file_the_shell_would_read_as_syntax(filename):
    assert script_literal_problem(_table(filename))


class _Firewall:
    def __init__(self, data_dir=''):
        self._data_dir = data_dir

    def get_option(self, key, default=None):
        assert key == 'linux24_data_dir'
        return self._data_dir


def test_a_data_file_below_the_data_directory():
    table = _table('%DATADIR%/block-hosts.tbl')
    assert not script_literal_problem(table, _Firewall('/var/lib/fwf'))


def test_a_data_directory_the_firewall_does_not_name():
    """fwbuilder refuses to compile such a firewall at all.

    ``MultiAddressRunTime::getSourceNameAsPath`` answers an empty path
    when the file name holds ``%DATADIR%`` and the firewall's data
    directory is unset, and ``processMultiAddressObjectsInRE`` aborts
    over it.  Leaving the token in the path ships a script that looks
    for a directory called "%DATADIR%" and stops the activation on the
    firewall over something the compiler could have said.
    """
    table = _table('%DATADIR%/block-hosts.tbl')
    assert script_literal_problem(table, _Firewall(''))
    assert not script_literal_problem(table, _Firewall('/var/lib/fwf'))


def test_a_compile_time_table_never_reaches_the_script():
    """The compiler opens that file itself, with Python and not with sh."""
    assert not script_literal_problem(_table('block $(reboot).tbl', run_time=False))


@pytest.mark.parametrize('name', ['6bone.net', 'ny6ix.net', 'a-b_c.example.com'])
def test_a_host_name_the_script_can_resolve(name):
    assert not script_literal_problem(_dns(name))


@pytest.mark.parametrize('name', ['$(reboot)', 'a;reboot', 'a b', 'a`id`'])
def test_a_host_name_the_shell_would_read_as_syntax(name):
    assert script_literal_problem(_dns(name))


def test_a_compile_time_dns_name_never_reaches_the_script():
    assert not script_literal_problem(_dns('$(reboot)', run_time=False))


@pytest.mark.parametrize('name', ['ppp0', 'ppp-dsl', 'eth0.100', 'ppp*', 'vnet+'])
def test_a_dynamic_interface_the_script_can_ask_about(name):
    assert not script_literal_problem(_interface(name))


@pytest.mark.parametrize('name', ['ppp$(reboot)', 'ppp;reboot', 'ppp 0'])
def test_a_dynamic_interface_the_shell_would_read_as_syntax(name):
    assert script_literal_problem(_interface(name))


def test_an_interface_with_an_address_contributes_the_address():
    """Only a dynamic interface puts its own name into the script."""
    assert not script_literal_problem(_interface('ppp$(reboot)', dynamic=False))


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    fw = None

    def __init__(self) -> None:
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(objects, rule_type='PolicyRule', slot='src'):
    rule = CompRule(
        id=uuid.uuid4(),
        type=rule_type,
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    setattr(rule, slot, objects)
    return rule


def _run(rule):
    proc = VerifyScriptLiterals(name='VerifyScriptLiterals')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return proc


def test_the_rule_is_left_out_and_the_object_is_named():
    proc = _run(_rule([_table('block;reboot.tbl')]))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages
    assert 'blocklist' in proc.compiler.messages[0]


def test_a_nat_rule_is_asked_about_its_translated_elements_too():
    proc = _run(_rule([_dns('$(reboot)')], rule_type='NATRule', slot='tdst'))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages


def test_an_ordinary_rule_passes_through():
    proc = _run(_rule([_table('block-hosts.tbl'), _interface('ppp0')]))
    assert len(proc.tmp_queue) == 1
    assert proc.compiler.messages == []
