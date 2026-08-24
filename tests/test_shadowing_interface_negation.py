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

""" "Not eth1" is not a rule about eth1, and the shadowing pass has to know.

``InterfacePolicyRules`` splits the interface element into one rule per
interface and never asks whether the element is negated, so a rule
written for "every interface except eth0" arrived at ``DetectShadowing``
as a rule about eth0 - exactly the interface it was written to leave out.
The comparison then answers the interface question backwards: a pair that
really does shadow goes unreported, and an unrelated pair is reported as
shadowed.  The false positive is the half that costs something, because a
shadowing finding is what an administrator deletes a working rule over
(issues #73 and #136).

Firewall Builder runs the full interface negation in that pass for this
reason and says so in ``PolicyCompiler_ipt::compile``: "use full negation
rule processor in shadowing detection.  This rule processor replaces
interface(s) object(s) with a complimentary set of 'other' interfaces of
the firewall."
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import DetectShadowing
from firewallfabrik.compiler.processors._policy import (
    InterfacePolicyRules,
    ItfNegation,
)
from firewallfabrik.core.objects import Interface, PolicyAction, TCPService

ETH0 = Interface(id=uuid.uuid4(), name='eth0')
ETH1 = Interface(id=uuid.uuid4(), name='eth1')
ETH2 = Interface(id=uuid.uuid4(), name='eth2')
LO = Interface(id=uuid.uuid4(), name='lo')


class _Firewall:
    def __init__(self) -> None:
        self.interfaces = [ETH0, ETH1, ETH2, LO]
        self.options: dict = {}

    def get_option(self, key, default=None):
        return self.options.get(key, default)


class _Compiler:
    def __init__(self) -> None:
        self.fw = _Firewall()
        self.warnings: list[str] = []

    def warning(self, msg, *args) -> None:
        self.warnings.append(msg if isinstance(msg, str) else str(args))


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


def _http():
    srv = TCPService(id=uuid.uuid4(), name='http')
    srv.dst_range_start = 80
    srv.dst_range_end = 80
    return srv


def _rule(position, interfaces, negated, services=(), action=PolicyAction.Accept):
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=position,
        label=f'{position} (global)',
        comment='',
        options={},
        negations={'itf': negated},
        action=action,
    )
    rule.abs_rule_number = position
    rule.itf = list(interfaces)
    rule.srv = list(services)
    return rule


def _run(rules, with_negation_expansion):
    """Push *rules* through the interface half of the shadowing pipeline."""
    compiler = _Compiler()
    source = _Feeder(rules)
    chain = []
    if with_negation_expansion:
        chain.append(ItfNegation('process negation in Itf'))
    chain.append(InterfacePolicyRules('process interface policy rules'))
    for processor in chain:
        processor.set_context(compiler)
        processor.set_data_source(source)
        while processor.process_next():
            pass
        source = processor

    detect = DetectShadowing('Detect shadowing')
    detect.set_context(compiler)
    detect.set_data_source(source)
    while detect.process_next():
        pass
    return compiler.warnings


def test_a_rule_on_the_other_interfaces_shadows_what_it_covers():
    """ "Not eth0" reaches eth1, so it covers the eth1 rule below it."""
    above = _rule(0, [ETH0], negated=True)
    below = _rule(1, [ETH1], negated=False, services=[_http()])
    assert _run([above, below], with_negation_expansion=True)


def test_a_rule_on_the_other_interfaces_does_not_shadow_the_one_it_excludes():
    """ "Not eth1" never sees an eth1 packet, so it covers nothing there."""
    above = _rule(0, [ETH1], negated=True)
    below = _rule(1, [ETH1], negated=False, services=[_http()])
    assert _run([above, below], with_negation_expansion=True) == []


def test_without_the_expansion_the_answer_is_the_wrong_way_round():
    """This is what the pass reported before ItfNegation was wired in."""
    above = _rule(0, [ETH1], negated=True)
    below = _rule(1, [ETH1], negated=False, services=[_http()])
    assert _run([above, below], with_negation_expansion=False)


def test_the_shadowing_pass_expands_the_negation_before_it_splits():
    """The order matters: splitting first is what produced the wrong rule."""
    source = PolicyCompiler.run_shadowing_pass.__doc__ or ''
    assert 'ItfNegation -> InterfacePolicyRules' in source
