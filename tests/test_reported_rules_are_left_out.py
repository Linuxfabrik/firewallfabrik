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

"""A rule the compiler says it cannot express must not reach the script.

The C++ ``abort()`` throws (fwbuilder
libfwbuilder/src/fwcompiler/BaseCompiler.cpp), so nothing is emitted at
all.  fwf reports and carries on, to show the administrator every problem
in one run - which only works if the reported rule is left behind.  Four
processors recorded the message and then pushed the rule on regardless.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import CheckForTCPEstablished
from firewallfabrik.core.objects import PolicyAction, TCPService


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def my_platform_name(self) -> str:
        return 'iptables'

    def abort(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)


def _rule(services):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='0 (global)',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
    )
    rule.srv = services
    return rule


def _tcp(established: bool):
    srv = TCPService()
    srv.name = 'All TCP established' if established else 'http'
    srv.data = {'established': 'True'} if established else {}
    return srv


def _run(rule):
    proc = CheckForTCPEstablished(name='CheckForTCPEstablished')
    proc.set_context(_Compiler())
    proc.set_data_source(_Feeder([rule]))
    proc.process_next()
    return proc


def test_a_service_with_established_takes_its_rule_with_it():
    """Neither packet filter has that match, so nothing replaces it."""
    proc = _run(_rule([_tcp(established=True)]))
    assert list(proc.tmp_queue) == []
    assert proc.compiler.messages


@pytest.mark.parametrize('services', [[], [_tcp(established=False)]])
def test_an_ordinary_rule_passes_through(services):
    proc = _run(_rule(services))
    assert len(proc.tmp_queue) == 1
    assert proc.compiler.messages == []
