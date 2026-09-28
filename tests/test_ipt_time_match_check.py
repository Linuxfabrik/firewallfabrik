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

"""A script with time-of-day rules checks the kernel's time match first.

RHEL 8, 9 and 10 build their kernels without xt_time
(`# CONFIG_NETFILTER_XT_MATCH_TIME is not set`), and iptables then refuses
every rule with a time window - after reset_all has dropped the old
rules.  The script tries the match on a chain of its own before anything
is touched, and stops if the kernel refuses it even after modprobe.
Activated on clones: RHEL 8 to 10 stop with the old rules in place,
Debian 12 and Ubuntu 24.04 load the rules.
"""

from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures'


def _start_block(script: str) -> str:
    return script[script.index('    start)') :]


def test_a_script_with_time_rules_checks_before_the_reset(compile_ipt, tmp_path):
    script = compile_ipt(
        FIXTURES / 'objects-for-regression-tests.fwb', 'firewall1', tmp_path
    ).read_text()
    assert ' -m time ' in script
    start = _start_block(script)
    assert 'check_time_match "$IPTABLES"' in start
    assert start.index('check_time_match') < start.index('reset_all')


def test_a_script_without_time_rules_does_not(compile_ipt, tmp_path):
    script = compile_ipt(
        FIXTURES / 'basic_accept_deny.fwf', 'fw-test', tmp_path
    ).read_text()
    assert ' -m time ' not in script
    assert 'check_time_match' not in script
