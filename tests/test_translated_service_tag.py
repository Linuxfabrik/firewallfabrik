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

"""A Tag Service is no translated service.

Firewall Builder refuses it in the Translated Service element
(``RuleElementTSrv::validateChild``).  Neither print rule here has anything
to write for it, so a NAT rule carrying one translated without the service
the editor showed, and said nothing.
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import NATAction, NATRuleType, TagService, TCPService
from firewallfabrik.platforms.iptables._nat_compiler import (
    VerifyRules2 as VerifyRules2_ipt,
)
from firewallfabrik.platforms.nftables._nat_compiler import (
    VerifyRules2 as VerifyRules2_nft,
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
        self.messages: list[str] = []

    def error(self, _rule, msg: str = '') -> None:
        self.messages.append(msg)

    abort = error


@pytest.mark.parametrize('processor_cls', [VerifyRules2_ipt, VerifyRules2_nft])
def test_a_tag_service_in_the_translated_service_is_refused(processor_cls):
    http = TCPService(id=uuid.uuid4(), name='http')
    tag = TagService(id=uuid.uuid4(), name='tag5')
    rule = CompRule(
        id=uuid.uuid4(),
        type='NATRule',
        position=0,
        label='0',
        comment='',
        options={},
        negations={},
        action=NATAction.Translate,
        nat_rule_type=NATRuleType.SNAT,
        osrv=[http],
        tsrv=[tag],
    )
    compiler = _Compiler()
    proc = processor_cls(name='under test')
    proc.set_context(compiler)
    proc.prev_processor = _Feeder([rule])
    while proc.process_next():
        pass

    assert list(proc.tmp_queue) == []
    assert compiler.messages == [
        'Tag Service "tag5" cannot be a translated service; the rule is left out'
    ]
