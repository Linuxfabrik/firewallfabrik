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

"""A NAT rule with the Branch action translates nothing of its own.

`NATCompiler::classifyNATRule` clears the three translated elements of
such a rule and says so.  Leaving them there is what made a branch
imported from a `.fwb` come out as an ordinary translation once before
(`dc154927`); the elements are also read by processors further down, so
the compiler should not carry values it will not compile.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import NATAction, NATRuleType
from firewallfabrik.platforms.iptables._nat_compiler import ClassifyNATRule
from firewallfabrik.platforms.nftables._nat_compiler import (
    ClassifyNATRule as ClassifyNATRuleNft,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self):
        self.warnings = []
        self.fw = None

    def warning(self, rule, text):
        self.warnings.append(text)


class _Address:
    id = uuid.uuid4()
    name = 'translated'


@pytest.mark.parametrize('cls', [ClassifyNATRule, ClassifyNATRuleNft])
def test_a_branch_rule_loses_its_translated_elements(cls):
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=1,
        label='1 (NAT)',
        comment='',
        options={},
        negations={},
    )
    rule.action = NATAction.Branch
    rule.tsrc = [_Address()]
    rule.tdst = [_Address()]

    compiler = _Compiler()
    proc = cls(name='classify')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True

    out = proc.tmp_queue[0]
    assert out.nat_rule_type == NATRuleType.NATBranch
    assert out.tsrc == []
    assert out.tdst == []
    assert out.tsrv == []
    assert compiler.warnings, 'the administrator has to be told'


@pytest.mark.parametrize('cls', [ClassifyNATRule, ClassifyNATRuleNft])
def test_a_branch_rule_that_translates_nothing_says_nothing(cls):
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=1,
        label='1 (NAT)',
        comment='',
        options={},
        negations={},
    )
    rule.action = NATAction.Branch

    compiler = _Compiler()
    proc = cls(name='classify')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    assert compiler.warnings == []
