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

"""Which chains a rule with "any" on one side is copied into.

"The firewall is part of any" means a rule whose source is any also
covers what the firewall itself sends, so
`PolicyCompiler_ipt::splitIfSrcAny` adds an OUTPUT copy - and, in the
mangle table, a POSTROUTING copy on top when the rule assigns a traffic
class, because `xt_CLASSIFY` registers for LOCAL_OUT, FORWARD and
POST_ROUTING and INPUT/OUTPUT alone leaves forwarded traffic
unclassified.  `splitIfDstAny` is the mirror, with prerouting.

The same processor skips a rule on a bridge port of a bridging firewall:
that rule is written with `-m physdev --physdev-out`, which iptables does
not allow in the OUTPUT chain (fwbuilder #2008), so the copy would be a
command that stops the activation.

Whether the rule assumes it is decided before the pipeline runs and is
written into the rule as a 0 or a 1 (`normalize_fw_part_of_any`, ported
from the loop in `PolicyCompiler_ipt::prolog`), so these processors read
the rule and nothing else.
"""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import Direction, PolicyAction
from firewallfabrik.platforms.iptables._policy_compiler import (
    SplitIfDstAny,
    SplitIfSrcAny,
)


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for rule in rules:
            self.tmp_queue.append(rule)

    def process_next(self) -> bool:
        return False


class _Firewall:
    name = 'fw-test'

    def __init__(self, bridging=False):
        self._bridging = bridging

    def get_option(self, key):
        if key == 'firewall_is_part_of_any_and_networks':
            return True
        if key == 'bridging_fw':
            return self._bridging
        return False


class _Compiler:
    def __init__(self, table='filter', bridging=False):
        self.my_table = table
        self.fw = _Firewall(bridging)

    @staticmethod
    def complex_match(obj, fw, **kwargs):
        return False

    @staticmethod
    def set_chain(rule, chain):
        rule.ipt_chain = chain


class _BridgePort:
    name = 'eth2'

    @staticmethod
    def is_bridge_port():
        return True


def _run(cls, compiler, **options):
    # The prolog leaves a 0 or a 1 behind; 1 is what "assume the firewall
    # is part of any" means and what makes these processors split.
    rule_options = {'firewall_is_part_of_any_and_networks': 1}
    rule_options.update(options.pop('options', {}))
    rule = CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=rule_options,
        negations={},
        action=PolicyAction.Accept,
        direction=Direction.Both,
    )
    for key, value in options.items():
        setattr(rule, key, value)
    proc = cls(name='split')
    proc.set_context(compiler)
    proc.set_data_source(_Feeder([rule]))
    assert proc.process_next() is True
    return [r.ipt_chain for r in proc.tmp_queue]


def test_a_filter_rule_gets_one_copy():
    assert _run(SplitIfSrcAny, _Compiler()) == ['OUTPUT', '']
    assert _run(SplitIfDstAny, _Compiler()) == ['INPUT', '']


def test_a_classifying_mangle_rule_also_reaches_the_routed_chain():
    chains = _run(
        SplitIfSrcAny,
        _Compiler(table='mangle'),
        options={'classification': True},
    )
    assert chains == ['OUTPUT', 'POSTROUTING', '']

    chains = _run(
        SplitIfDstAny,
        _Compiler(table='mangle'),
        options={'classification': True},
    )
    assert chains == ['INPUT', 'PREROUTING', '']


def test_a_mangle_rule_that_does_not_classify_gets_no_extra_copy():
    assert _run(SplitIfSrcAny, _Compiler(table='mangle')) == ['OUTPUT', '']


def test_a_bridge_port_rule_gets_no_output_copy():
    """`--physdev-out` in OUTPUT is a command iptables refuses."""
    chains = _run(SplitIfSrcAny, _Compiler(bridging=True), itf=[_BridgePort()])
    assert chains == ['']


def test_a_bridge_port_rule_on_a_routing_firewall_is_split_as_usual():
    chains = _run(SplitIfSrcAny, _Compiler(), itf=[_BridgePort()])
    assert chains == ['OUTPUT', '']


def test_a_rule_that_says_no_gets_no_copy():
    """A rule that turns the option off is not split.

    Firewall Builder stores the tri-state as the string "0", which reads
    as true in Python because it is not empty: the rule got the very copy
    the option exists to suppress, and the reference output for
    `firewall94` and `firewall-ipv6-8` shows it should not.
    """
    for processor in (SplitIfSrcAny, SplitIfDstAny):
        chains = _run(
            processor,
            _Compiler(),
            options={'firewall_is_part_of_any_and_networks': 0},
        )
        assert chains == ['']
