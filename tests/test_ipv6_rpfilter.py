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

"""The IPv6 reverse path filter of the Linux host settings.

IPv6 has no rp_filter sysctl, so the script filters itself: an
``rpfilter`` match in the mangle table on iptables, a ``fib`` lookup in a
prerouting chain on nftables.  What it drops was measured on Rocky Linux 8
and 10 and Debian 12 and 13 (see the comments at the two emitters); here
the rules are checked for being there, for their mode, and for being
accepted by the tools.
"""

import copy
import re
import subprocess  # nosec B404
from pathlib import Path

import pytest
import sqlalchemy

from firewallfabrik.core import DatabaseManager
from firewallfabrik.core.objects import Firewall
from firewallfabrik.platforms.iptables._compiler_driver import CompilerDriver_ipt
from firewallfabrik.platforms.nftables._compiler_driver import CompilerDriver_nft
from tests.tool_probe import (
    CAN_ASK_IPTABLES,
    CAN_ASK_NFT,
    SKIP_REASON,
    SKIP_REASON_IPTABLES,
)

FIXTURES = Path(__file__).parent / 'fixtures'


def _compile(tmp_path, platform, mode, version=None):
    """Compile the dual-stack ``fw-old-ipt`` with the filter set to *mode*."""
    db = DatabaseManager()
    db.load(str(FIXTURES / 'compiler-tests.fwf'))
    with db.session() as session:
        fw = session.execute(
            sqlalchemy.select(Firewall).where(Firewall.name == 'fw-old-ipt'),
        ).scalar_one()
        options = copy.deepcopy(fw.options or {})
        options['linux24_ipv6_rpfilter'] = mode
        fw.options = options
        data = copy.deepcopy(fw.data or {})
        data['platform'] = 'iptables' if platform == 'ipt' else 'nftables'
        # fw-old-ipt names an iptables release below the rpfilter match.
        data['version'] = version or ('1.6.2' if platform == 'ipt' else '')
        fw.data = data
        fw_id = str(fw.id)
    driver = (CompilerDriver_ipt if platform == 'ipt' else CompilerDriver_nft)(db)
    driver.wdir = str(tmp_path)
    driver.file_name_setting = f'{platform}-{mode or "off"}.fw'
    driver.run(cluster_id='', fw_id=fw_id, single_rule_id='')
    return Path(driver.file_names[fw_id]).read_text(), driver.all_warnings


@pytest.mark.parametrize(
    ('mode', 'expected'),
    [('1', '--invert --validmark -j DROP'), ('2', '--invert --validmark --loose')],
)
def test_iptables_filters_the_ipv6_family_only(tmp_path, mode, expected):
    script, _ = _compile(tmp_path, 'ipt', mode)
    rules = [line for line in script.splitlines() if '-m rpfilter' in line]
    assert rules, 'no reverse path filter in the script'
    assert all('$IP6TABLES' in line and '-t mangle' in line for line in rules)
    assert all(expected in line for line in rules)
    # Duplicate address detection sends from ::, which has no route back.
    assert re.search(r'\$IP6TABLES.*neighbour-solicitation -j ACCEPT', script)


@pytest.mark.parametrize(
    ('mode', 'lookup'), [('1', 'saddr . mark . iif'), ('2', 'saddr . mark')]
)
def test_nftables_filters_in_a_prerouting_chain(tmp_path, mode, lookup):
    script, _ = _compile(tmp_path, 'nft', mode)
    assert f'meta nfproto ipv6 fib {lookup} oif missing counter drop' in script
    assert 'hook prerouting' in script


@pytest.mark.parametrize('platform', ['ipt', 'nft'])
@pytest.mark.parametrize('mode', ['', '0'])
def test_off_writes_nothing(tmp_path, platform, mode):
    script, _ = _compile(tmp_path, platform, mode)
    assert '-m rpfilter' not in script
    assert 'fib saddr' not in script


def test_an_iptables_without_the_match_is_told(tmp_path):
    script, warnings = _compile(tmp_path, 'ipt', '1', version='1.4.11')
    assert '-m rpfilter' not in script
    assert any('rpfilter' in warning for warning in warnings), warnings


@pytest.mark.skipif(not CAN_ASK_NFT, reason=SKIP_REASON)
@pytest.mark.parametrize('mode', ['1', '2'])
def test_nft_accepts_the_ruleset(tmp_path, mode):
    script, _ = _compile(tmp_path, 'nft', mode)
    ruleset = script.split("cat <<'NFT_RULES'\n", 1)[1].split('\nNFT_RULES', 1)[0]
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'nft', '--check', '-f', '-'],
        input=ruleset,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(not CAN_ASK_IPTABLES, reason=SKIP_REASON_IPTABLES)
@pytest.mark.parametrize('mode', ['1', '2'])
def test_ip6tables_accepts_the_rules(tmp_path, mode):
    script, _ = _compile(tmp_path, 'ipt', mode)
    lines = [
        line.strip().replace('$IP6TABLES', 'ip6tables')
        for line in script.splitlines()
        if '$IP6TABLES' in line and '-t mangle -A PREROUTING' in line
    ]
    assert len(lines) == 3, lines
    proc = subprocess.run(  # nosec B603 B607
        ['unshare', '-rn', 'sh', '-ec', '\n'.join(lines)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
