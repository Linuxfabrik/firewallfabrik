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

"""Output normalization for golden file comparison.

Strips timestamps, usernames, and other non-deterministic parts of
compiler output so that golden files remain stable across machines
and runs.
"""

import re


def normalize_ipt(text: str) -> str:
    """Normalize iptables compiler output for golden file comparison."""
    # Replace generated timestamp line
    text = re.sub(
        r'^(#  Generated ).*$',
        r'\1TIMESTAMP',
        text,
        flags=re.MULTILINE,
    )
    # Replace version header (Python: fwb_ipt v0.1.0, C++: fwb_ipt v-5.3.7.7846)
    text = re.sub(
        r'^(#  Firewall Builder  fwb_ipt )v.*$',
        r'\1VERSION',
        text,
        flags=re.MULTILINE,
    )
    # Replace activation log line
    text = re.sub(
        r'(log "Activating firewall script generated ).*(")',
        r'\1TIMESTAMP\2',
        text,
    )
    # Normalize Python chain name hashes (C<hex>.N -> CHAIN)
    text = re.sub(
        r'\bC[0-9a-f]{8,}\.\d+',
        'CHAIN',
        text,
    )
    # Normalize C++ chain name hashes (Cid<N>X<N>.<N> -> CHAIN)
    text = re.sub(
        r'\bCid\d+X\d+\.\d+',
        'CHAIN',
        text,
    )
    # Collapse runs of multiple spaces into a single space
    text = re.sub(r'  +', ' ', text)
    # Collapse multiple consecutive blank lines into one
    text = re.sub(r'\n{3,}', '\n\n', text)
    # Strip trailing whitespace per line
    text = re.sub(r'[ \t]+$', '', text, flags=re.MULTILINE)
    # Ensure exactly one trailing newline (end-of-file-fixer compatibility)
    text = text.rstrip('\n') + '\n'
    return text


def normalize_nft(text: str) -> str:
    """Normalize nftables compiler output for golden file comparison."""
    # Replace generated timestamp line
    text = re.sub(
        r'^(#  Generated ).*$',
        r'\1TIMESTAMP',
        text,
        flags=re.MULTILINE,
    )
    # Replace version header
    text = re.sub(
        r'^(#  Firewall Builder  fwf )v.*$',
        r'\1VERSION',
        text,
        flags=re.MULTILINE,
    )
    # Strip trailing whitespace per line
    text = re.sub(r'[ \t]+$', '', text, flags=re.MULTILINE)
    # Ensure exactly one trailing newline (end-of-file-fixer compatibility)
    text = text.rstrip('\n') + '\n'
    return text
