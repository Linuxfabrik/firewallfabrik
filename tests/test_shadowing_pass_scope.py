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

"""The shadowing pass reasons about the rules its own table installs.

``PolicyCompiler_ipt::compile`` calls ``addRuleFilter()`` in the shadowing
pass as well as in the main one, so the filter run detects shadowing among
filter rules and the mangle run among mangle rules.  Without it every
finding is reported twice on iptables - once by each table - and the
mangle run compares rules it never installs.
"""

import collections
import re

from firewallfabrik.compiler._policy_compiler import PolicyCompiler
from firewallfabrik.platforms.iptables._mangle_compiler import MangleTableCompiler_ipt
from firewallfabrik.platforms.iptables._policy_compiler import PolicyCompiler_ipt
from firewallfabrik.platforms.nftables._mangle_compiler import MangleCompiler_nft
from firewallfabrik.platforms.nftables._policy_compiler import PolicyCompiler_nft

from .conftest import FIXTURES_DIR

SHADOWS = re.compile(r"Rule '(.+?)' shadows rule '(.+?)' below it")


def test_every_shadowing_finding_is_reported_once(compile_ipt, tmp_path):
    output = compile_ipt(
        FIXTURES_DIR / 'compiler-tests.fwf', 'fw-shadowing', tmp_path
    ).read_text(encoding='utf-8')

    counts = collections.Counter(SHADOWS.findall(output))
    assert counts, 'the fixture is meant to produce shadowing findings'
    repeated = {pair: n for pair, n in counts.items() if n > 1}
    assert not repeated, f'reported more than once: {repeated}'


def test_every_policy_compiler_can_filter_the_rules_of_its_table():
    """The shared pass calls it, so every compiler that runs it needs one."""
    assert hasattr(PolicyCompiler, 'add_rule_filter')
    for cls in (
        PolicyCompiler_ipt,
        MangleTableCompiler_ipt,
        PolicyCompiler_nft,
        MangleCompiler_nft,
    ):
        assert cls.add_rule_filter is not PolicyCompiler.add_rule_filter, (
            f'{cls.__name__} inherits the base no-op rule filter'
        )
