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

"""`--xp`, `--xn` and `--xr` trace a rule and then finish.

With a rule to debug, `Compiler.add()` puts a Debug processor behind every
processor except SimplePrintProgress, and a Debug answers True for as long
as it holds rules.  A chain that does not end in SimplePrintProgress
therefore ends in a Debug, and `run_rule_processors()` never returns: the
shadowing pass and the routing compiler did that, and every `--xp` and
`--xr` run printed the same trace forever.
"""

import pathlib
import subprocess  # nosec B404
import sys

import pytest

FIXTURES = pathlib.Path(__file__).parent / 'fixtures'


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
@pytest.mark.parametrize(
    ('flag', 'fixture', 'processor'),
    [
        ('--xp', 'basic_accept_deny', 'Detect shadowing'),
        ('--xn', 'basic_accept_deny', 'Begin'),
        ('--xr', 'routing_default_route_per_family', 'generate ip route commands'),
    ],
)
def test_a_debugged_compile_finishes(tmp_path, platform, flag, fixture, processor):
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            '-m',
            f'firewallfabrik.cli.fwf_{platform}',
            '--file',
            str(FIXTURES / f'{fixture}.fwf'),
            '-d',
            str(tmp_path),
            flag,
            '0',
            'fw-test',
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    # The trace was written, once per processor and not over and over.
    assert result.stderr.count(f'--- {processor} ') == 1
