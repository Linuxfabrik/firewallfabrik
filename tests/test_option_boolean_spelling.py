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

"""A stored boolean has to survive the line breaks a data file may carry.

Firewall Builder writes an option either inline or on a line of its own,
and reads both the same way: ``FWObject::getBool`` removes every space,
tab and newline before it compares.  Without that removal a wrapped
``True`` reads as False where the value is compared against the literal,
and as True where it is only tested for truthiness - so the same file
answers the question both ways round depending on which reader asks.
"""

import re

import pytest

from firewallfabrik.compiler.processors._policy import is_mangle_only_rule_set
from firewallfabrik.core._options import option_bool, option_is_true

from .conftest import FIXTURES_DIR

WRAPPED_TRUE = '\n          True\n        '
WRAPPED_FALSE = '\n          False\n        '


@pytest.mark.parametrize(
    'value',
    [True, 1, 'True', 'true', 'TRUE', '1', WRAPPED_TRUE, '\ttrue\r\n'],
)
def test_true_spellings(value):
    assert option_is_true(value) is True


@pytest.mark.parametrize(
    'value',
    [False, 0, None, '', 'False', 'false', WRAPPED_FALSE, 'RULE %N -- %A '],
)
def test_false_spellings(value):
    assert option_is_true(value) is False


def test_option_bool_leaves_a_non_boolean_alone():
    """A log prefix ends in a space on purpose and a prompt is only spaces."""
    assert option_bool('RULE %N -- %A ', 'keep') == 'keep'
    assert option_bool(' # ', 'keep') == 'keep'
    assert option_bool(WRAPPED_TRUE, 'keep') is True
    assert option_bool(WRAPPED_FALSE, 'keep') is False


class _RuleSet:
    def __init__(self, options):
        self.options = options


def test_wrapped_mangle_only_rule_set_is_read_as_true():
    """The whole policy of such a rule set belongs in the mangle table."""
    assert is_mangle_only_rule_set(_RuleSet({'mangle_only_rule_set': WRAPPED_TRUE}))
    assert not is_mangle_only_rule_set(
        _RuleSet({'mangle_only_rule_set': WRAPPED_FALSE})
    )
    assert not is_mangle_only_rule_set(_RuleSet({}))
    assert not is_mangle_only_rule_set(None)


def test_the_reference_fixture_still_carries_the_wrapped_spelling():
    """Guard the input, not only the reader.

    Three rule sets of the Firewall Builder regression suite store the flag
    across three lines.  If the fixture is ever rewritten inline, this
    test stops asserting anything and should be re-pointed rather than
    quietly passing.
    """
    text = (FIXTURES_DIR / 'objects-for-regression-tests.fwb').read_text()
    wrapped = re.findall(
        r'<Option name="mangle_only_rule_set">\s*\n\s*(\w+)\s*\n\s*</Option>', text
    )
    assert wrapped == ['True', 'True', 'True']
