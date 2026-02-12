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

"""Unit tests for the StoreAction rule processor."""

import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import PolicyAction


class _Feeder(BasicRuleProcessor):
    """Minimal source processor that yields pre-built CompRules."""

    def __init__(self, rules: list[CompRule]) -> None:
        super().__init__(name='Feeder')
        for r in rules:
            self.tmp_queue.append(r)

    def process_next(self) -> bool:
        return False


def _make_rule(
    action: PolicyAction = PolicyAction.Accept,
    options: dict | None = None,
) -> CompRule:
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options=options or {},
        negations={},
        action=action,
    )


def _run_store_action(rule: CompRule, *, platform: str = 'ipt') -> CompRule:
    """Feed *rule* through StoreAction and return the output rule."""
    if platform == 'ipt':
        from firewallfabrik.platforms.iptables._policy_compiler import StoreAction
    else:
        from firewallfabrik.platforms.nftables._policy_compiler import StoreAction

    feeder = _Feeder([rule])
    proc = StoreAction(name='StoreAction')
    proc.set_data_source(feeder)
    assert proc.process_next() is True
    assert len(proc.tmp_queue) == 1
    return proc.tmp_queue[0]


class TestStoreActionIpt:
    """Tests for the iptables StoreAction processor."""

    def test_stored_action_accept(self):
        rule = _make_rule(action=PolicyAction.Accept)
        out = _run_store_action(rule)
        assert out.stored_action == 'Accept'

    def test_stored_action_deny(self):
        rule = _make_rule(action=PolicyAction.Deny)
        out = _run_store_action(rule)
        assert out.stored_action == 'Deny'

    def test_tagging_true(self):
        rule = _make_rule(options={'tagging': True})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_tagging is True

    def test_tagging_false(self):
        rule = _make_rule(options={'tagging': False})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_tagging is False

    def test_tagging_absent(self):
        rule = _make_rule(options={})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_tagging is False

    def test_classification_true(self):
        rule = _make_rule(options={'classification': True})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_classification is True

    def test_classification_false(self):
        rule = _make_rule(options={'classification': False})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_classification is False

    def test_routing_true(self):
        rule = _make_rule(options={'routing': True})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_routing is True

    def test_routing_false(self):
        rule = _make_rule(options={'routing': False})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_routing is False

    def test_all_flags_combined(self):
        rule = _make_rule(
            action=PolicyAction.Continue,
            options={
                'tagging': True,
                'classification': True,
                'routing': True,
            },
        )
        out = _run_store_action(rule)
        assert out.stored_action == 'Continue'
        assert out.originated_from_a_rule_with_tagging is True
        assert out.originated_from_a_rule_with_classification is True
        assert out.originated_from_a_rule_with_routing is True

    def test_no_flags_set(self):
        rule = _make_rule(action=PolicyAction.Reject, options={})
        out = _run_store_action(rule)
        assert out.stored_action == 'Reject'
        assert out.originated_from_a_rule_with_tagging is False
        assert out.originated_from_a_rule_with_classification is False
        assert out.originated_from_a_rule_with_routing is False

    def test_tagging_string_true(self):
        """XML-parsed options store booleans as strings."""
        rule = _make_rule(options={'tagging': 'True'})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_tagging is True

    def test_tagging_string_false(self):
        """XML-parsed 'False' string must not be truthy."""
        rule = _make_rule(options={'tagging': 'False'})
        out = _run_store_action(rule)
        assert out.originated_from_a_rule_with_tagging is False


class TestStoreActionNft:
    """Tests for the nftables StoreAction processor."""

    def test_stored_action(self):
        rule = _make_rule(action=PolicyAction.Accept)
        out = _run_store_action(rule, platform='nft')
        assert out.stored_action == 'Accept'

    def test_all_flags(self):
        rule = _make_rule(
            options={
                'tagging': True,
                'classification': True,
                'routing': True,
            },
        )
        out = _run_store_action(rule, platform='nft')
        assert out.originated_from_a_rule_with_tagging is True
        assert out.originated_from_a_rule_with_classification is True
        assert out.originated_from_a_rule_with_routing is True

    def test_no_flags(self):
        rule = _make_rule(options={})
        out = _run_store_action(rule, platform='nft')
        assert out.originated_from_a_rule_with_tagging is False
        assert out.originated_from_a_rule_with_classification is False
        assert out.originated_from_a_rule_with_routing is False
