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

"""The metric of a routing rule, and the two places that read it.

``ip route add ... metric N`` carries a 32-bit number: iproute2 reads it
with ``get_u32(&metric, *argv, 0)`` (iproute2 ip/iproute.c).  Measured in
a network namespace:

    ip route add 10.9.9.0/24 dev lo metric 4294967295   -> installed
    ip route add 10.9.9.0/24 dev lo metric 5000000000
    ip route add 10.9.9.0/24 dev lo metric -5
    -> Error: argument "..." is wrong: "metric" value is invalid

That route is then not installed at all while the rest of the activation
carries on, and two rules that differ only in their metric are told apart
by exactly this number.

The single-path printer used to read the option itself, so a value that
is no number ended the whole compile with a ``ValueError`` where the
multi-path branch next to it answered 0 - and it wrote the stored text
out unread, so ``007`` reached iproute2 as octal 7 while the multi-path
branch wrote 7.  One helper now answers for both.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.platforms.linux._routing_compiler import (
    MAX_ROUTE_METRIC,
    VerifyRouteMetrics,
    route_metric,
)


class _Compiler:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, rule, msg):
        self.errors.append(msg)

    def warning(self, rule, msg):
        self.warnings.append(msg)


class _Source:
    def __init__(self, rules):
        self._rules = list(rules)

    def get_next_rule(self):
        return self._rules.pop(0) if self._rules else None


def _rule(metric):
    options = {} if metric is None else {'metric': metric}
    return CompRule(
        id=uuid.uuid4(),
        type='RoutingRule',
        position=0,
        label='0 (main)',
        comment='',
        options=options,
        negations={},
        rdst=[],
        rgtw=[],
        ritf=[],
    )


@pytest.mark.parametrize('metric', ['0', '1', '100', '4294967295', 5, 0])
def test_a_metric_iproute2_takes(metric):
    assert route_metric(_rule(metric)) == int(metric)


@pytest.mark.parametrize('metric', ['4294967296', '5000000000', '-1', '-5', 'abc'])
def test_a_metric_iproute2_refuses(metric):
    assert route_metric(_rule(metric)) is None


@pytest.mark.parametrize('metric', [None, '', 0])
def test_no_metric_is_zero_the_way_iproute2_reads_a_missing_one(metric):
    assert route_metric(_rule(metric)) == 0


def test_the_ceiling_is_the_one_iproute2_enforces():
    assert MAX_ROUTE_METRIC == 0xFFFFFFFF


def _run(rules):
    proc = VerifyRouteMetrics('verify route metrics')
    proc.compiler = _Compiler()
    proc.prev_processor = _Source(rules)
    out = []
    while (rule := proc.get_next_rule()) is not None:
        out.append(rule)
    return proc.compiler, out


def test_an_unusable_metric_is_reported_and_the_route_still_goes_out():
    """Installing the route without a metric beats not installing it.

    Which of two competing routes wins is then the kernel's choice, and
    that is what the message is for.
    """
    compiler, out = _run([_rule('abc')])
    assert len(out) == 1
    assert compiler.warnings
    assert 'abc' in compiler.warnings[0]


def test_a_usable_metric_says_nothing():
    compiler, out = _run([_rule('50')])
    assert len(out) == 1
    assert compiler.warnings == []
