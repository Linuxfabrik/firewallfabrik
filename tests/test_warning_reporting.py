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

"""A warning follows the same two rules every message follows.

``Compiler.warning`` writes the message the way the Firewall Builder
output words it, and that wording is the only thing about it that may
differ from ``BaseCompiler.warning``: a muted block still records
nothing, and a sentence about a rule is still recorded once and not once
per internal copy of that rule.
"""

from firewallfabrik.compiler._base import BaseCompiler, CompilerStatus
from firewallfabrik.compiler._compiler import Compiler


class _Rule:
    def __init__(self, label='3 (global)', position=3):
        self.label = label
        self.position = position


class _RuleSet:
    name = 'Policy'


class _Firewall:
    name = 'fw-test'


def _compiler():
    compiler = Compiler.__new__(Compiler)
    BaseCompiler.__init__(compiler)
    compiler.fw = _Firewall()
    compiler.source_ruleset = _RuleSet()
    return compiler


def test_the_same_sentence_about_one_rule_is_recorded_once():
    compiler = _compiler()
    rule = _Rule()
    for _ in range(6):
        compiler.warning(rule, 'the weekday is matched in the kernel timezone')
    assert compiler.get_warnings() == [
        'fw-test:Policy:3: warning: the weekday is matched in the kernel timezone'
    ]
    assert compiler.get_errors_for_rule(rule).count('weekday') == 1


def test_two_rules_each_get_their_own_copy():
    compiler = _compiler()
    compiler.warning(_Rule('3 (global)', 3), 'same sentence')
    compiler.warning(_Rule('4 (global)', 4), 'same sentence')
    assert len(compiler.get_warnings()) == 2


def test_a_muted_block_records_nothing():
    compiler = _compiler()
    with compiler.muted():
        compiler.warning(_Rule(), 'rendered only to compare the result')
    assert compiler.get_warnings() == []
    assert compiler.status == CompilerStatus.FWCOMPILER_SUCCESS


def test_a_muted_warning_is_still_said_afterwards():
    """Muting must not mark the message as already reported."""
    compiler = _compiler()
    rule = _Rule()
    with compiler.muted():
        compiler.warning(rule, 'the one that counts')
    compiler.warning(rule, 'the one that counts')
    assert len(compiler.get_warnings()) == 1
