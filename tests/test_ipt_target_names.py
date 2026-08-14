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

"""The names iptables refuses as a chain name because a target has them.

``assert_valid_chain_name`` (netfilter iptables/xshared.c) asks
``xtables_find_target(name, XTF_TRY_LOAD)`` and refuses the name when it
answers, so a rule set or branch named after a target produces a ``-N`` the
firewall rejects, and the activation stops there.

The compiler keeps the names in ``IPTABLES_TARGET_NAMES``. The two tests
here re-derive that list instead of trusting it: one from the extension
files of a netfilter iptables checkout (``FWF_IPTABLES_SOURCE``), one by
offering every name to the installed binaries. Both skip themselves when
what they need is missing; see ``tests/tool_probe.py`` for why the second
cannot decide that on its own.
"""

import os
import pathlib
import re
import shutil
import subprocess  # nosec B404

import pytest

from firewallfabrik.platforms.iptables._utils import (
    IPTABLES_TARGET_NAMES,
    _chain_name_problem,
    check_chain_name,
    shell_safe_name,
)
from tests.tool_probe import CAN_ASK_IPTABLES, SKIP_REASON_IPTABLES

_SOURCE = os.environ.get('FWF_IPTABLES_SOURCE', '')

# The extension file that holds the shared parser of SNAT and DNAT and
# names no target of its own.
_NOT_A_TARGET = frozenset({'NAT'})

# The verdicts the standard target provides. They have no extension file,
# so the file sweep cannot find them.
_VERDICTS = frozenset({'ACCEPT', 'DROP', 'QUEUE', 'RETURN'})

_EXTENSION = re.compile(r'^lib(?:xt|ipt|ip6t)_([A-Z][A-Za-z0-9_]*)\.[a-z]+$')


def _names_from_source(repo: pathlib.Path) -> set[str]:
    extensions = repo / 'extensions'
    names = set()
    for path in extensions.iterdir():
        match = _EXTENSION.match(path.name)
        if match:
            names.add(match.group(1))
    return names


def _chain_name_refused(tool: str, name: str) -> bool:
    """Return whether *tool* refuses *name* as a chain name."""
    result = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', tool, '-N', name],
        capture_output=True,
        text=True,
        check=False,
    )
    return 'may not clash with target name' in result.stderr


def test_verdicts_are_listed():
    assert _VERDICTS <= IPTABLES_TARGET_NAMES


@pytest.mark.parametrize('name', ['SNAT', 'TEE', 'MASQUERADE', 'ACCEPT'])
def test_a_target_name_is_refused_as_a_chain_name(name):
    assert 'iptables target' in _chain_name_problem(name)


@pytest.mark.parametrize('name', ['mail_server', 'SecMark', 'branch1', 'Accept'])
def test_an_ordinary_name_is_accepted(name):
    assert _chain_name_problem(name) == ''


@pytest.mark.parametrize(
    'name',
    [
        'a;reboot',
        'a`id`',
        'a$HOME',
        'a|b',
        'a&b',
        'a(b)',
        'a<b',
        'a*b',
        'a?b',
        'a[0]b',
        "a'b",
        'a"b',
        'a\\b',
    ],
)
def test_a_name_the_shell_would_read_is_refused(name):
    """iptables takes all of these; the script around it does not.

    Every command in the generated script is a bare shell word, so `$`, a
    backtick, `;`, `&`, `|`, the redirections and the globs are syntax
    there - and they would run as root at the moment every chain is already
    set to drop.  `assert_valid_chain_name` refuses none of them.
    """
    assert 'cannot pass on' in _chain_name_problem(name)
    assert not shell_safe_name(name)


@pytest.mark.parametrize(
    'name', ['mail_server', 'C9b7d4795a1e8.0', 'In_RULE_0', 'fwf_INPUT', 'a:b', 'a-b']
)
def test_a_name_the_compiler_generates_is_accepted(name):
    assert shell_safe_name(name)
    assert _chain_name_problem(name) == ''


@pytest.mark.parametrize('name', ['eth0', 'eth0.100', 'br-lan', 'vnet+', 'bond0'])
def test_an_interface_name_the_kernel_gives_is_accepted(name):
    # net/core/dev.c:dev_valid_name allows far more than this, which is why
    # the check exists; these are the shapes a real system produces.
    assert shell_safe_name(name)


@pytest.mark.parametrize('name', ['eth$0', 'eth;0', 'eth*0', 'eth 0'])
def test_an_interface_name_the_shell_would_read_is_refused(name):
    assert not shell_safe_name(name)


def test_check_chain_name_answers_whether_the_name_can_be_used():
    """The answer is what makes the print rules leave the rule out.

    A chain name goes into the `-N` that creates it and into every `-j`
    that points at it, so there is no emitting the rule without it.  The
    message is recorded once per name.
    """

    class _Compiler:
        def __init__(self):
            self.messages = []

        def error(self, msg=''):
            self.messages.append(msg)

    compiler = _Compiler()
    reported = set()
    assert check_chain_name(compiler, 'mail_server', reported) is True
    assert compiler.messages == []

    assert check_chain_name(compiler, 'a;reboot', reported) is False
    assert len(compiler.messages) == 1
    assert check_chain_name(compiler, 'a;reboot', reported) is False
    assert len(compiler.messages) == 1


@pytest.mark.skipif(not CAN_ASK_IPTABLES, reason=SKIP_REASON_IPTABLES)
@pytest.mark.parametrize('name', ['a;reboot', 'a$HOME', 'a*b'])
def test_iptables_itself_takes_the_names_the_shell_cannot(name):
    """Which is exactly why the check cannot be left to iptables."""
    assert not _chain_name_refused('iptables', name)


@pytest.mark.skipif(not _SOURCE, reason='set FWF_IPTABLES_SOURCE to a git clone')
def test_list_matches_the_netfilter_extensions():
    expected = (_names_from_source(pathlib.Path(_SOURCE)) - _NOT_A_TARGET) | _VERDICTS
    assert expected == IPTABLES_TARGET_NAMES


@pytest.mark.skipif(not CAN_ASK_IPTABLES, reason=SKIP_REASON_IPTABLES)
@pytest.mark.parametrize('name', sorted(IPTABLES_TARGET_NAMES))
def test_the_tools_refuse_every_listed_name(name):
    refused = _chain_name_refused('iptables', name)
    if not refused and shutil.which('ip6tables'):
        # Some targets exist for one family only: HL, DNPT and SNPT are
        # IPv6, TTL and ECN are IPv4. A dual-stack firewall creates its
        # chains in both rulesets, so either tool refusing the name is
        # enough to keep it out.
        refused = _chain_name_refused('ip6tables', name)
    assert refused, f'{name} is not a target name of the installed iptables'
