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

"""Tests that the nftables compiler uses named tables.

The compiler must never emit ``flush ruleset`` (which wipes tables
managed by other tools like Docker, CrowdSec, or fail2ban).  Instead
it uses named tables (default: ``fwf_filter`` / ``fwf_nat``)
and only flushes those.
"""

import re

from .conftest import _find_fixture


def test_no_flush_ruleset(compile_nft, tmp_path):
    """Generated script must not contain 'flush ruleset'."""
    fixture_path = _find_fixture('basic_accept_deny')
    output_path = compile_nft(fixture_path, 'fw-test', tmp_path)
    script = output_path.read_text()

    assert 'flush ruleset' not in script


def test_filter_table_uses_named_table(compile_nft, tmp_path):
    """Filter rules must use named table, not generic 'filter'."""
    fixture_path = _find_fixture('basic_accept_deny')
    output_path = compile_nft(fixture_path, 'fw-test', tmp_path)
    script = output_path.read_text()

    assert re.search(r'table \w+ fwf_filter \{', script)
    assert not re.search(r'table \w+ filter \{', script)


def test_nat_table_uses_named_table(compile_nft, tmp_path):
    """NAT rules must use named table, not generic 'nat'."""
    fixture_path = _find_fixture('compiler-tests')
    output_path = compile_nft(fixture_path, 'fw-nat-negation', tmp_path)
    script = output_path.read_text()

    assert re.search(r'table \w+ fwf_nat \{', script)
    assert not re.search(r'table \w+ nat \{', script)


def test_flush_own_tables_function(compile_nft, tmp_path):
    """Generated script must define flush_own_tables() that deletes only our tables."""
    fixture_path = _find_fixture('basic_accept_deny')
    output_path = compile_nft(fixture_path, 'fw-test', tmp_path)
    script = output_path.read_text()

    assert 'flush_own_tables()' in script
    # Must delete both inet and ip variants of filter table
    assert '$NFT delete table inet fwf_filter' in script
    assert '$NFT delete table ip fwf_filter' in script
    # Must delete both inet and ip variants of nat table
    assert '$NFT delete table inet fwf_nat' in script
    assert '$NFT delete table ip fwf_nat' in script


def test_block_action_uses_inet(compile_nft, tmp_path):
    """block_action() must use inet family to block both IPv4 and IPv6."""
    fixture_path = _find_fixture('basic_accept_deny')
    output_path = compile_nft(fixture_path, 'fw-test', tmp_path)
    script = output_path.read_text()

    # Extract block_action function body
    match = re.search(r'block_action\(\) \{(.+?)\n\}', script, re.DOTALL)
    assert match, 'block_action() not found in script'
    block_body = match.group(1)

    assert '$NFT add table inet fwf_filter' in block_body
    assert '$NFT add chain inet fwf_filter input' in block_body
    assert '$NFT add chain inet fwf_filter forward' in block_body
    assert '$NFT add chain inet fwf_filter output' in block_body


def test_stop_action_calls_flush_own_tables(compile_nft, tmp_path):
    """stop_action() must call flush_own_tables()."""
    fixture_path = _find_fixture('basic_accept_deny')
    output_path = compile_nft(fixture_path, 'fw-test', tmp_path)
    script = output_path.read_text()

    match = re.search(r'stop_action\(\) \{(.+?)\n\}', script, re.DOTALL)
    assert match, 'stop_action() not found in script'
    assert 'flush_own_tables' in match.group(1)


def test_script_body_atomic_table_recreation(compile_nft, tmp_path):
    """script_body() must atomically create+delete tables before recreating them."""
    fixture_path = _find_fixture('basic_accept_deny')
    output_path = compile_nft(fixture_path, 'fw-test', tmp_path)
    script = output_path.read_text()

    # Extract heredoc content
    match = re.search(r"<<'NFT_RULES'\n(.+?)\nNFT_RULES", script, re.DOTALL)
    assert match, 'NFT_RULES heredoc not found'
    heredoc = match.group(1)

    # Must create empty table then delete it (atomic cleanup)
    assert re.search(r'table \w+ fwf_filter \{\}', heredoc)
    assert 'delete table' in heredoc
    # Then recreate with actual rules
    assert re.search(r'table \w+ fwf_filter \{\n', heredoc)
