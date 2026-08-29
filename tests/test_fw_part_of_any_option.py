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

"""What "assume firewall is part of any" reads as.

The option was a checkbox in Firewall Builder 3.0 and a tri-state
afterwards, and a `.fwb` carries every spelling the two produced side by
side - the reference corpus has `''`, `'0'`, `'1'`, `'False'`, `'True'`
and `'true'`.  `PolicyCompiler_ipt::prolog` (PolicyCompiler_ipt.cpp:444)
turns all of them into a 0 or a 1 before the pipeline runs, and every
reader afterwards asks whether the value is 1.

Read as a Python truth value instead, `'0'` is a non-empty string and
therefore on, so a rule that says "do not assume it" got the extra INPUT
and OUTPUT copies naming the firewall that the option exists to suppress:
108 rules of the cluster reference alone, and `firewall94` and
`firewall-ipv6-8` now match the reference output exactly.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler.processors._policy import (
    FW_PART_OF_ANY,
    assumes_fw_is_part_of_any,
    normalize_fw_part_of_any,
)
from firewallfabrik.core._options import option_int
from firewallfabrik.core.objects import Direction, PolicyAction


class _Firewall:
    """Answers the one option `normalize_fw_part_of_any` asks it about."""

    def __init__(self, global_afpa):
        self._global = global_afpa

    def get_option(self, key):
        assert key == FW_PART_OF_ANY
        return self._global


def _rule(stored):
    options = {} if stored is None else {FW_PART_OF_ANY: stored}
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
        direction=Direction.Both,
    )


@pytest.mark.parametrize('global_afpa', [True, False])
@pytest.mark.parametrize(
    ('stored', 'expected'),
    [
        # The tri-state values decide for themselves.
        ('0', 0),
        ('1', 1),
        # The old checkbox ticked means on.
        ('True', 1),
        # `atoi` is what reads the tri-state, and it answers 0 for a word.
        ('true', 0),
    ],
)
def test_a_rule_that_decides_for_itself(stored, expected, global_afpa):
    rules = [_rule(stored)]

    normalize_fw_part_of_any(rules, _Firewall(global_afpa))

    assert rules[0].options[FW_PART_OF_ANY] == expected
    assert assumes_fw_is_part_of_any(rules[0]) is (expected == 1)


@pytest.mark.parametrize('global_afpa', [True, False])
@pytest.mark.parametrize('stored', [None, '', 'False'])
def test_a_rule_that_leaves_it_to_the_firewall(stored, global_afpa):
    """An empty value and the old cleared checkbox both mean "use global".

    The comment above the C++ loop says why the cleared checkbox does:
    back then a rule could not turn the option off on its own when it was
    on globally.
    """
    rules = [_rule(stored)]

    normalize_fw_part_of_any(rules, _Firewall(global_afpa))

    assert rules[0].options[FW_PART_OF_ANY] == int(global_afpa)
    assert assumes_fw_is_part_of_any(rules[0]) is global_afpa


def test_the_value_survives_a_second_pass():
    """The filter and the mangle run normalise the same rules again."""
    rules = [_rule('0'), _rule('True'), _rule('')]
    fw = _Firewall(True)

    normalize_fw_part_of_any(rules, fw)
    first = [r.options[FW_PART_OF_ANY] for r in rules]
    normalize_fw_part_of_any(rules, fw)

    assert [r.options[FW_PART_OF_ANY] for r in rules] == first == [0, 1, 1]


def test_option_int_reads_what_getint_reads():
    """`FWObject::getInt` runs the stored string through `atoi`."""
    assert option_int('0') == 0
    assert option_int('1') == 1
    assert option_int('true') == 0
    assert option_int('') == 0
    assert option_int(None) == 0
    assert option_int('  2 ') == 2
    assert option_int('-3') == -3
    assert option_int(True) == 1
