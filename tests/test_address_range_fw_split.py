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

"""An address range around the firewall gets its input and output copy.

Firewall Builder copies a rule into INPUT when its destination is an
address range that contains a firewall address, and into OUTPUT when its
source is (PolicyCompiler_ipt.cpp, splitIfDstMatchingAddressRange and
splitIfSrcMatchingAddressRange), whatever the other side of the rule is.
An anti-spoofing rule names the firewall as source on the external
interface; with an address range as destination, skipping the INPUT copy
because the source is the firewall left the forged packets addressed to
the firewall itself unfiltered.
"""

import re

from .conftest import _find_fixture

_FIXTURE = 'address_range_fw_split'


def _chains_nft(text: str) -> dict[str, list[str]]:
    chains: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        m = re.match(r'\s+chain (\w+) \{', line)
        if m:
            current = m.group(1)
            continue
        if current and line.strip() and not line.strip().startswith('#'):
            chains.setdefault(current, []).append(line.strip())
    return chains


def test_nft_anti_spoofing_rule_reaches_input(compile_nft, tmp_path):
    out = compile_nft(_find_fixture(_FIXTURE), 'fw-test', tmp_path).read_text()
    chains = _chains_nft(out)
    for chain in ('input', 'forward'):
        assert any(
            line.startswith('iifname "eth0" ip saddr { 192.168.1.1, 203.0.113.1 }')
            and line.endswith('drop')
            for line in chains[chain]
        ), chain


def test_nft_range_as_source_reaches_output(compile_nft, tmp_path):
    out = compile_nft(_find_fixture(_FIXTURE), 'fw-test', tmp_path).read_text()
    assert any(
        'ip saddr 192.168.1.1-192.168.1.10' in line and 'tcp dport 22' in line
        for line in _chains_nft(out)['output']
    )


def test_ipt_anti_spoofing_rule_reaches_input(compile_ipt, tmp_path):
    out = compile_ipt(_find_fixture(_FIXTURE), 'fw-test', tmp_path).read_text()
    assert re.search(r'-A fwf_INPUT\s+-i eth0\s+-d 0\.0\.0\.0/0\s+-j ', out)
    assert re.search(r'-A fwf_FORWARD\s+-i eth0\s+-d 0\.0\.0\.0/0\s+-j ', out)


def test_ipt_range_as_source_reaches_output(compile_ipt, tmp_path):
    out = compile_ipt(_find_fixture(_FIXTURE), 'fw-test', tmp_path).read_text()
    assert re.search(
        r'-A fwf_OUTPUT\s.*--src-range 192\.168\.1\.1-192\.168\.1\.10\s+--dport 22',
        out,
    )
