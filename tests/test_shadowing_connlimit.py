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

"""A connection limit narrows a rule, so it never shadows one without.

The ordinary use is a rule that rejects the connections of a source above
a limit, placed ahead of the rule that accepts the service. Both name the
same addresses and services; the limit is what tells them apart, and the
shadowing check has to read it that way instead of as a rate.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler.processors._generic import DetectShadowing
from firewallfabrik.core.objects import PolicyAction


def _rule(**options):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=options,
        negations={},
        action=PolicyAction.Accept,
    )


@pytest.mark.parametrize(
    ('above', 'below', 'shadows'),
    [
        # The case of the example data center: reject above 100, accept the rest.
        ({'connlimit_value': 100}, {}, False),
        # An unlimited rule matches everything a limited one does.
        ({}, {'connlimit_value': 100}, True),
        # "more than 100" contains "more than 200", not the other way round.
        ({'connlimit_value': 100}, {'connlimit_value': 200}, True),
        ({'connlimit_value': 200}, {'connlimit_value': 100}, False),
        # "100 or fewer" contains "50 or fewer".
        (
            {'connlimit_value': 100, 'connlimit_above_not': True},
            {'connlimit_value': 50, 'connlimit_above_not': True},
            True,
        ),
        (
            {'connlimit_value': 50, 'connlimit_above_not': True},
            {'connlimit_value': 100, 'connlimit_above_not': True},
            False,
        ),
        # Opposite directions of the count never contain each other.
        (
            {'connlimit_value': 100},
            {'connlimit_value': 100, 'connlimit_above_not': True},
            False,
        ),
        # Counted per /24 is a different count than per address.
        (
            {'connlimit_value': 100},
            {'connlimit_value': 100, 'connlimit_masklen': 24},
            False,
        ),
        # -1 marks a temporary rule the compiler split off: no limit.
        ({'connlimit_value': -1}, {'connlimit_value': 100}, True),
        ({'connlimit_value': 100}, {'connlimit_value': -1}, False),
        # Values as a file imported from fwbuilder stores them.
        ({'connlimit_value': '100', 'connlimit_masklen': '0'}, {}, False),
    ],
)
def test_connection_limit_decides_shadowing(above, below, shadows):
    assert (
        DetectShadowing._limits_allow_shadowing(_rule(**above), _rule(**below))
        is shadows
    )
