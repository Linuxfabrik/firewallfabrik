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

"""`script_body` answers for every command it ran, not for the last one.

The start branch of both scripts ends with `script_body ||
run_epilog_and_exit 1`, so what that function returns is what the
administrator, the init system and the installer read.

The shell form of the iptables policy is hundreds of separate commands and
the shell hands back the status of the last one, so a rule the tool refused
in the middle left the ruleset incomplete under a clean activation.  The
nftables script runs one `nft -f` - and then fills the sets its address
tables, DNS names and dynamic interfaces stand for, so its status was the
last set's, and a set that is empty on purpose answers 0.
"""

import re
import shutil
import subprocess  # nosec B404
from pathlib import Path

import pytest

_EXPECTED = Path(__file__).resolve().parents[1] / 'tests' / 'expected-output'
_IPT = _EXPECTED / 'ipt' / 'basic_accept_deny' / 'fw-test.fw'
_NFT_WITH_SETS = (
    _EXPECTED / 'nft' / 'objects-for-regression-tests' / 'firewall-ipv6-4.fw'
)


def _function(text: str, name: str) -> str:
    match = re.search(rf'\n{name}\(\) \{{\n(.*?)\n\}}\n', text, re.S)
    assert match, f'no {name} in the script'
    return match.group(1)


def test_the_iptables_body_counts_what_the_tool_refused():
    body = _function(_IPT.read_text(), 'script_body')

    assert 'IPTABLES=fwf_run_iptables' in body
    assert 'IP6TABLES=fwf_run_ip6tables' in body
    assert body.rstrip().endswith('test "$fwf_failed_commands" -eq 0')


def test_the_two_variables_hold_the_tool_path_again_afterwards():
    """`check_tools`, `reset_all` and the block/stop/status actions read them."""
    text = _IPT.read_text()
    body = _function(text, 'script_body')

    assert 'IPTABLES="$fwf_tool_v4"' in body
    assert 'IP6TABLES="$fwf_tool_v6"' in body
    assert 'find_program "$IPTABLES"' in text


def test_the_nftables_body_does_not_let_a_filled_set_hide_a_refused_ruleset():
    body = _function(_NFT_WITH_SETS.read_text(), 'script_body')

    assert '$NFT -f /dev/stdin || return 1' in body
    assert 'load_address_tables' in body


def test_every_nftables_set_load_records_its_own_failure():
    text = _NFT_WITH_SETS.read_text()
    loader = _function(text, 'load_address_tables')

    assert 'fwf_set_failures=0' in loader
    for line in loader.splitlines():
        if line.strip().startswith('load_'):
            assert line.rstrip().endswith('|| fwf_set_failures=1'), line
    assert loader.rstrip().endswith('test "$fwf_set_failures" -eq 0')


@pytest.mark.skipif(shutil.which('sh') is None, reason='no POSIX shell')
def test_the_wrapper_counts_a_refused_command_and_spares_chain_creation(tmp_path):
    """Run the script's own wrapper, with a tool that answers as asked.

    The `-N` exemption is not cosmetic: the script asks for every chain on
    every activation and Firewall Builder redirects the answer away for
    that reason, so counting those would report a failure on every run.
    """
    definitions = _function(_IPT.read_text(), 'fwf_run_tool')
    tool = tmp_path / 'tool'
    tool.write_text('#!/bin/sh\ncase " $* " in *fail*) exit 1 ;; esac\nexit 0\n')
    tool.chmod(0o755)

    script = tmp_path / 'run.sh'
    script.write_text(
        f'fwf_run_tool() {{\n{definitions}\n}}\n'
        'fwf_failed_commands=0\n'
        f'fwf_run_tool {tool} -A INPUT -j ACCEPT\n'
        f'fwf_run_tool {tool} -N fail_chain\n'
        'echo "after the good ones: $fwf_failed_commands"\n'
        f'fwf_run_tool {tool} -A INPUT -j fail\n'
        'echo "after the bad one: $fwf_failed_commands"\n'
    )
    result = subprocess.run(  # nosec B603 B607
        ['sh', str(script)], capture_output=True, text=True, check=False
    )
    assert 'after the good ones: 0' in result.stdout, result.stderr
    assert 'after the bad one: 1' in result.stdout, result.stderr
