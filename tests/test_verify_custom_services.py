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

"""Regression tests for CustomService code lookup during verification.

Guards against a past bug where the verifiers read platform codes from
``srv.data`` instead of ``srv.codes``, causing every CustomService to
fail validation with "Custom service ... is not configured for the
platform ...".
"""

import uuid

import pytest

from firewallfabrik.compiler._comp_rule import CompRule
from firewallfabrik.compiler._rule_processor import BasicRuleProcessor
from firewallfabrik.core.objects import CustomService, PolicyAction


class _Feeder(BasicRuleProcessor):
    def __init__(self, rules):
        super().__init__(name='Feeder')
        for r in rules:
            self.tmp_queue.append(r)

    def process_next(self) -> bool:
        return False


class _FakeCompiler:
    def __init__(self, platform: str) -> None:
        self._platform = platform
        self.aborted: list[str] = []

    def my_platform_name(self) -> str:
        return self._platform

    def abort(self, rule, msg: str) -> None:
        self.aborted.append(msg)


def _make_rule(services):
    return CompRule(
        id=uuid.uuid4(),
        type='PolicyRule',
        position=1,
        label='',
        comment='',
        options={},
        negations={},
        action=PolicyAction.Accept,
        srv=list(services),
    )


def _make_custom_service(name: str, codes: dict | None) -> CustomService:
    svc = CustomService()
    svc.name = name
    svc.codes = codes
    return svc


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_custom_service_with_code_is_accepted(platform):
    """CustomService with a non-empty code must pass verification."""
    from firewallfabrik.compiler.processors._service import VerifyCustomServices

    svc = _make_custom_service('my-custom', {platform: '-m something'})
    rule = _make_rule([svc])

    comp = _FakeCompiler(platform)
    proc = VerifyCustomServices(name='VerifyCustomServices')
    proc.compiler = comp
    proc.set_data_source(_Feeder([rule]))

    assert proc.process_next() is True
    assert comp.aborted == []


@pytest.mark.parametrize('platform', ['iptables', 'nftables'])
def test_custom_service_missing_code_aborts(platform):
    """CustomService with no code for this platform must abort."""
    from firewallfabrik.compiler.processors._service import VerifyCustomServices

    svc = _make_custom_service('my-custom', {'junosacl': 'something'})
    rule = _make_rule([svc])

    comp = _FakeCompiler(platform)
    proc = VerifyCustomServices(name='VerifyCustomServices')
    proc.compiler = comp
    proc.set_data_source(_Feeder([rule]))

    assert proc.process_next() is True
    assert comp.aborted, f'expected abort for missing {platform} code'
    assert f"'{platform}'" in comp.aborted[0]
