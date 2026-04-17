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

"""Tests for CustomService, TagService and UserService code output.

Verifies that the iptables and nftables print_rule modules correctly
inject platform-specific code from CustomService, TagService and
UserService objects into the compiled rule output.

Regression test for GitHub issue #72: CustomService code (e.g.
``-m conntrack --ctstate ESTABLISHED,RELATED``) was silently
dropped, producing bare ``-j ACCEPT`` rules without state matching.
"""

import io
import uuid

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.core.objects import (
    CustomService,
    Direction,
    PolicyAction,
    TagService,
    UserService,
)


def _make_rule(
    services,
    *,
    action=PolicyAction.Accept,
    direction=Direction.Inbound,
    stateless=False,
    chain='INPUT',
    target='ACCEPT',
):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=0,
        label='test',
        comment='',
        options={'stateless': stateless},
        negations={},
        action=action,
        direction=direction,
        srv=list(services),
        ipt_chain=chain,
        ipt_target=target,
    )


def _make_custom_service(name, codes, protocol='any'):
    svc = CustomService()
    svc.id = uuid.uuid4()
    svc.name = name
    svc.codes = codes
    svc.protocol = protocol
    return svc


def _make_tag_service(name, tagvalue):
    svc = TagService()
    svc.id = uuid.uuid4()
    svc.name = name
    svc.codes = {'tag_tagvalue': tagvalue}
    svc.data = {'tagvalue': tagvalue}
    return svc


def _make_user_service(name, userid):
    svc = UserService()
    svc.id = uuid.uuid4()
    svc.name = name
    svc.userid = userid
    return svc


class _FakeFw:
    def __init__(self):
        self.version = '1.4.20'

    def get_option(self, key, default=None):
        return default


class _FakeIptCompiler:
    """Minimal compiler stub for iptables PrintRule."""

    def __init__(self):
        self.fw = _FakeFw()
        self.ipv6_policy = False
        self.output = io.StringIO()
        self._errors: list[str] = []

    def my_platform_name(self):
        return 'iptables'

    def error(self, rule, msg):
        self._errors.append(msg)

    def get_errors_for_rule(self, rule):
        return ''


class _FakeNftCompiler:
    """Minimal compiler stub for nftables PrintRule."""

    def __init__(self):
        self.fw = _FakeFw()
        self.ipv6_policy = False
        self.output = io.StringIO()
        self._errors: list[str] = []

    def my_platform_name(self):
        return 'nftables'

    def error(self, rule, msg):
        self._errors.append(msg)

    def get_errors_for_rule(self, rule):
        return ''


# -- iptables CustomService tests --


class TestIptCustomServiceOutput:
    def _render(self, rule):
        from firewallfabrik.platforms.iptables._print_rule import (
            PrintRule,
        )

        pr = PrintRule()
        pr.compiler = _FakeIptCompiler()
        return pr._build_rule_command(rule)

    def test_established_code_emitted(self):
        svc = _make_custom_service(
            'ESTABLISHED',
            {'iptables': '-m conntrack --ctstate ESTABLISHED,RELATED'},
        )
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-m conntrack --ctstate ESTABLISHED,RELATED' in cmd
        assert '-j ACCEPT' in cmd

    def test_state_code_emitted(self):
        svc = _make_custom_service(
            'ESTABLISHED',
            {'iptables': '-m state --state ESTABLISHED,RELATED'},
        )
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-m state --state ESTABLISHED,RELATED' in cmd

    def test_custom_with_protocol(self):
        svc = _make_custom_service(
            'custom-with-proto',
            {'iptables': '-p tcp -m irc'},
        )
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-p tcp -m irc' in cmd
        # Must not duplicate -p tcp
        assert cmd.count('-p tcp') == 1

    def test_empty_code_produces_no_output(self):
        svc = _make_custom_service(
            'empty',
            {'iptables': ''},
        )
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-m ' not in cmd


class TestIptTagServiceOutput:
    def _render(self, rule):
        from firewallfabrik.platforms.iptables._print_rule import (
            PrintRule,
        )

        pr = PrintRule()
        pr.compiler = _FakeIptCompiler()
        return pr._build_rule_command(rule)

    def test_tag_mark_emitted(self):
        svc = _make_tag_service('my-tag', '42')
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-m mark --mark 42' in cmd

    def test_tag_empty_no_output(self):
        svc = _make_tag_service('empty-tag', '')
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-m mark' not in cmd


class TestIptUserServiceOutput:
    def _render(self, rule):
        from firewallfabrik.platforms.iptables._print_rule import (
            PrintRule,
        )

        pr = PrintRule()
        pr.compiler = _FakeIptCompiler()
        return pr._build_rule_command(rule)

    def test_user_owner_emitted(self):
        svc = _make_user_service('my-user', '1000')
        rule = _make_rule(
            [svc],
            stateless=True,
            chain='OUTPUT',
            direction=Direction.Outbound,
        )
        cmd = self._render(rule)
        assert '-m owner --uid-owner 1000' in cmd

    def test_user_empty_no_output(self):
        svc = _make_user_service('empty-user', '')
        rule = _make_rule([svc], stateless=True)
        cmd = self._render(rule)
        assert '-m owner' not in cmd


# -- nftables CustomService tests --


class TestNftCustomServiceOutput:
    def _render(self, rule):
        from firewallfabrik.platforms.nftables._print_rule import (
            PrintRule_nft,
        )

        pr = PrintRule_nft()
        pr.compiler = _FakeNftCompiler()
        return pr._build_rule(rule)

    def test_ct_state_code_emitted(self):
        svc = _make_custom_service(
            'ESTABLISHED',
            {'nftables': 'ct state established,related'},
        )
        rule = _make_rule([svc], stateless=True)
        line = self._render(rule)
        assert 'ct state established,related' in line
        assert 'accept' in line

    def test_empty_code_no_output(self):
        svc = _make_custom_service(
            'empty',
            {'nftables': ''},
        )
        rule = _make_rule([svc], stateless=True)
        line = self._render(rule)
        assert 'ct state' not in line


class TestNftTagServiceOutput:
    def _render(self, rule):
        from firewallfabrik.platforms.nftables._print_rule import (
            PrintRule_nft,
        )

        pr = PrintRule_nft()
        pr.compiler = _FakeNftCompiler()
        return pr._build_rule(rule)

    def test_meta_mark_emitted(self):
        svc = _make_tag_service('my-tag', '42')
        rule = _make_rule([svc], stateless=True)
        line = self._render(rule)
        assert 'meta mark 42' in line


class TestNftUserServiceOutput:
    def _render(self, rule):
        from firewallfabrik.platforms.nftables._print_rule import (
            PrintRule_nft,
        )

        pr = PrintRule_nft()
        pr.compiler = _FakeNftCompiler()
        return pr._build_rule(rule)

    def test_meta_skuid_emitted(self):
        svc = _make_user_service('my-user', '1000')
        rule = _make_rule(
            [svc],
            stateless=True,
            chain='OUTPUT',
            direction=Direction.Outbound,
        )
        line = self._render(rule)
        assert 'meta skuid 1000' in line
