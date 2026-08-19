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

"""The NAT rules the compiler has to refuse before writing them out.

`NATCompiler_ipt::VerifyRules` is what fwbuilder's own `firewall2-4`
("tests for error conditions in NATCompiler_ipt::VerifyRules") exercises,
and its reference output lists the messages one per rule.  Two of them
were missing here, and both turn into a translation that quietly does
something else: several translated services leave the printer taking the
first one, and a one-to-one network map between differently sized networks
puts two source addresses on one translated address.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.compiler.processors._generic import VerifyRules
from firewallfabrik.core.objects import NATRuleType


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Compiler:
    def __init__(self):
        self.errors = []

    def abort(self, rule_or_msg=None, msg=None):
        self.errors.append(msg if msg is not None else rule_or_msg)


def _network(netmask):
    from firewallfabrik.core.objects import Network

    return Network(
        id=uuid.uuid4(),
        name=f'net-{netmask}',
        inet_addr_mask={'address': '192.168.1.0', 'netmask': netmask},
    )


def _service():
    from firewallfabrik.core.objects import TCPService

    return TCPService(id=uuid.uuid4(), name='http', data={})


def _run(**slots):
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=1,
        label='',
        comment='',
        options={},
        negations={},
    )
    rule.nat_rule_type = slots.pop('nat_rule_type', NATRuleType.SNAT)
    for slot, value in slots.items():
        setattr(rule, slot, value)
    compiler = _Compiler()
    proc = VerifyRules(name='verify')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return compiler.errors, list(proc.tmp_queue)


def test_more_than_one_translated_service_is_refused():
    errors, out = _run(tsrv=[_service(), _service()])
    assert out == []
    assert 'should contain single object' in errors[0]


def test_one_translated_service_is_fine():
    errors, out = _run(tsrv=[_service()])
    assert errors == []
    assert len(out) == 1


def test_a_network_in_the_translated_source_is_refused():
    errors, out = _run(tsrc=[_network('255.255.255.0')])
    assert out == []
    assert 'network object in translated source' in errors[0]


@pytest.mark.parametrize(
    ('kind', 'original', 'translated'),
    [
        (NATRuleType.SNetnat, 'osrc', 'tsrc'),
        (NATRuleType.DNetnat, 'odst', 'tdst'),
    ],
)
def test_a_one_to_one_map_between_different_sizes_is_refused(
    kind, original, translated
):
    errors, out = _run(
        nat_rule_type=kind,
        **{
            original: [_network('255.255.255.0')],
            translated: [_network('255.255.255.128')],
        },
    )
    assert out == []
    assert 'networks of the same size' in errors[0]


@pytest.mark.parametrize(
    ('kind', 'original', 'translated'),
    [
        (NATRuleType.SNetnat, 'osrc', 'tsrc'),
        (NATRuleType.DNetnat, 'odst', 'tdst'),
    ],
)
def test_the_same_size_passes(kind, original, translated):
    errors, out = _run(
        nat_rule_type=kind,
        **{
            original: [_network('255.255.255.0')],
            translated: [_network('255.255.255.0')],
        },
    )
    assert errors == []
    assert len(out) == 1


def test_every_message_names_its_rule():
    """`abort(msg)` records the sentence without the rule it is about."""
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=7,
        label='7 (NAT)',
        comment='',
        options={},
        negations={'tsrc': True},
    )
    rule.nat_rule_type = NATRuleType.SNAT
    seen = []

    class _C:
        @staticmethod
        def abort(rule_or_msg=None, msg=None):
            seen.append((rule_or_msg, msg))

    proc = VerifyRules(name='verify')
    proc.set_context(_C())
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    assert seen[0][0] is rule
