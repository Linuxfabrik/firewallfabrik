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

"""What happens when a route the script installs is refused.

`ip route add` fails for reasons the compiler cannot see: the gateway is
not reachable from where the box actually sits, the interface is down, the
destination is already routed by something else.  Without the rollback the
script walked past it, finished and reported success, leaving the box
behind the new packet filter with half a routing table.

Firewall Builder wraps every command in `|| route_command_error "<label>"`
and defines that function, together with the saved routing table it puts
back, in the `routing_functions` configlet
(`RoutingCompiler_ipt::PrintRule::processNext` and
`RoutingCompiler_ipt::epilog`).  The configlet was in the tree and nothing
rendered it.
"""

import uuid
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.linux._routing_compiler import RoutingPrintRule
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft

FIXTURES = Path(__file__).parent / 'fixtures'


def _compile(tmp_path, fw_name, driver_class=CompilerDriver_ipt):
    db = DatabaseManager()
    db.load(str(FIXTURES / 'objects-for-regression-tests.fwb'))
    with db.session() as session:
        fw_id = str(
            session.execute(
                sqlalchemy.select(Firewall).where(Firewall.name == fw_name),
            )
            .scalar_one()
            .id
        )
    driver = driver_class(db)
    driver.wdir = str(tmp_path)
    driver.source_dir = str(FIXTURES)
    driver.file_name_setting = f'{fw_name}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return (tmp_path / f'{fw_name}.fw').read_text()


@pytest.mark.parametrize(
    'driver_class', [CompilerDriver_ipt, CompilerDriver_nft], ids=['ipt', 'nft']
)
def test_every_route_command_can_put_the_old_table_back(tmp_path, driver_class):
    script = _compile(tmp_path, 'firewall36', driver_class)

    assert 'route_command_error()' in script
    assert 'restore_script_output()' in script
    # The table the rollback puts back has to be saved before the first
    # route is touched.
    assert script.index('OLD_ROUTES') < script.index('$IP route add')
    # Every route command, the multi-path one at the end included.
    for line in script.splitlines():
        if line.strip().startswith('$IP ') and ' route add ' in line:
            assert line.rstrip().endswith('\\'), line
    assert '|| route_command_error "' in script
    # The last mention closes the block; the first is the call inside
    # `route_command_error` itself.
    assert script.rindex('restore_script_output\n') > script.rindex('$IP route add')


def test_a_firewall_with_a_default_route_may_drop_the_one_that_is_there(tmp_path):
    """`proto_filter` is the whole point of `FindDefaultRoute`.

    With a default route of its own to install the script may delete the
    one the box has; without one it has to keep it, or the box loses its
    way out the moment the script runs.
    """
    with_default = _compile(tmp_path, 'firewall36')
    without_default = _compile(tmp_path, 'firewall36-1')

    assert "grep -v 'proto kernel'" in with_default
    assert r"grep -v '\( proto kernel \)\|\(default via \)'" in without_default


def test_a_firewall_without_routing_rules_defines_none_of_it(tmp_path):
    script = _compile(tmp_path, 'firewall1')

    assert 'route_command_error' not in script
    assert 'restore_script_output' not in script


class _Compiler:
    def __init__(self, defined=True, single_rule=False):
        self.defined_restore_script_output = defined
        self._single_rule = single_rule

    def in_single_rule_compile_mode(self):
        return self._single_rule


def _rule(**options):
    return CompRule(
        id=uuid.uuid4(),
        type='RoutingRule',
        position=0,
        label='0 (main)',
        comment='',
        options=options,
        negations={},
    )


def test_a_non_critical_rule_is_allowed_to_fail():
    """The routing options dialog writes `no_fail` and nobody read it.

    Firewall Builder answers it with a warning and goes on
    (`RoutingRuleToString`), which is the whole difference between "this
    route matters" and "try it".
    """
    printer = RoutingPrintRule()
    printer.compiler = _Compiler()

    assert printer._rollback_tail(_rule()) == (' \\\n|| route_command_error "0 (main)"')
    tail = printer._rollback_tail(_rule(no_fail=True))
    assert 'route_command_error' not in tail
    assert 'failed. ignored.' in tail


@pytest.mark.parametrize(
    'compiler',
    [_Compiler(defined=False), _Compiler(single_rule=True)],
    ids=['no-functions', 'single-rule'],
)
def test_nothing_calls_a_function_the_script_does_not_define(compiler):
    printer = RoutingPrintRule()
    printer.compiler = compiler

    assert printer._rollback_tail(_rule()) == ''
