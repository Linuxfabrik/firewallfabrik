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

"""A rule's rate limit is one bucket for the whole rule, on both platforms.

A rule is compiled into several lines - one per address, per chain, per
protocol group - and a `-m limit` or an anonymous nftables `limit rate` is a
token bucket per line.  So a rule naming two sources admitted its rate
twice, unless a temporary chain happened to collect the lines first.
Measured on Rocky 8 to 10, Debian 11 to 13, Fedora 44, Leap 15.5 and 16.0
and Ubuntu 22.04 to 26.04: two sources sending twenty packets each at a
"5/second, burst 5" rule got 5+5 through with a line per source, 5 with the
sources folded into one nftables set.

Every line of a rule therefore names one bucket: a hash table without a key
on iptables, a limit object on nftables.  And where iptables factors a rule
into a temporary chain, the limit sits on the rule inside it, which is where
the whole rule has matched - on the jump, a sender the rule does not name
spent the rule's rate.
"""

import re
from pathlib import Path

from firewallfabrik.core.objects import Firewall

FIXTURE = Path(__file__).parent / 'fixtures' / 'rate_limit_per_rule.fwf'
FW = 'fw-test'


def _rule_lines(script: str, position: int) -> list[str]:
    """Return the non-comment lines of every block the rule is written as.

    A block ends at the next rule, at the end of an nftables chain or at the
    first empty line of the iptables script.
    """
    blocks = re.findall(
        rf'# Rule {position} \(global\)\n(.*?)(?=# Rule \d+ \(global\)|\n    \}}|\n\s*\n)',
        script,
        re.S,
    )
    return [
        line.strip()
        for block in blocks
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith(('#', 'echo'))
    ]


def test_nftables_names_one_limit_object_per_rule(compile_nft, tmp_path):
    script = compile_nft(FIXTURE, FW, tmp_path).read_text()

    for position, rate in (
        (0, 'rate 5/second burst 5 packets'),
        (1, 'rate 10/second'),
        (2, 'rate 20/minute'),
        (3, 'rate over 50/second'),
    ):
        name = f'limit_Policy_{position}'
        assert f'    limit {name} {{\n        {rate}\n    }}' in script
        lines = [line for line in _rule_lines(script, position) if 'limit' in line]
        assert lines, position
        # Every line of the rule names the object; none has a bucket of its
        # own.  A log line keeps its own cap on the log messages, and it is
        # the only anonymous limit left.
        for line in lines:
            assert f'limit name "{name}"' in line or ' log ' in line, line


def test_nftables_logs_only_what_the_limit_lets_through(compile_nft, tmp_path):
    """The limit sits on the jump, the log line comes after it."""
    script = compile_nft(FIXTURE, FW, tmp_path).read_text()

    jump = next(line for line in _rule_lines(script, 2) if 'limit_Policy_2' in line)
    chain = jump.split(' jump ')[1]
    body = re.search(rf'chain {re.escape(chain)} \{{\n(.*?)\n    \}}', script, re.S)
    log_line = next(line for line in body.group(1).splitlines() if ' log ' in line)
    assert 'limit name' not in log_line


def test_iptables_names_one_hash_table_per_rule(compile_ipt, tmp_path):
    script = compile_ipt(FIXTURE, FW, tmp_path).read_text()

    for position, match in (
        (0, '--hashlimit-upto 5/second --hashlimit-burst 5'),
        (1, '--hashlimit-upto 10/second'),
        (2, '--hashlimit-upto 20/minute'),
        (3, '--hashlimit-above 50/second'),
    ):
        lines = [line for line in _rule_lines(script, position) if 'hashlimit' in line]
        assert lines, position
        for line in lines:
            assert f'-m hashlimit {match} --hashlimit-name limit_rule_{position} ' in (
                line
            )
        # The rule's own rate is never a bucket per line.
        assert not any(
            '-m limit' in line and '-j LOG' not in line
            for line in _rule_lines(script, position)
        )


def test_iptables_keeps_the_limit_off_the_optimizer_jump(compile_ipt, tmp_path):
    """The jump matches only the service; a stranger would spend the rate."""
    script = compile_ipt(FIXTURE, FW, tmp_path).read_text()

    lines = _rule_lines(script, 1)
    jumps = [line for line in lines if '--dport 9999' in line]
    assert jumps
    assert not any('hashlimit' in line for line in jumps), jumps
    assert all('hashlimit' in line for line in lines if '-s 198.51.100.' in line), lines


def test_iptables_before_1_4_1_keeps_a_limit_per_line(compile_ipt, tmp_path):
    """No keyless hash table there; the rule says so rather than guessing."""

    def pin_old_release(session):
        fw = session.query(Firewall).filter_by(name=FW).one()
        fw.data = {**(fw.data or {}), 'version': '1.4.0'}

    script = compile_ipt(FIXTURE, FW, tmp_path, prepare=pin_old_release).read_text()

    lines = _rule_lines(script, 0)
    assert any('-m limit --limit 5/second --limit-burst 5' in line for line in lines)
    assert 'every line this rule is written as admits the rate on its own' in (script)
