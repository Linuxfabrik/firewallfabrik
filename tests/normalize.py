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

"""Output normalization for expected output comparison.

Strips timestamps, usernames, and other non-deterministic parts of
compiler output so that expected output files remain stable across machines
and runs.
"""

import re


def _sort_interfaces(text: str) -> str:
    """Sort interface lists in verify/configure blocks and rule label comments.

    Handles both ipt (single-space indent) and nft (4-space indent) formats.
    """

    # Sort interface names in: echo "Verifying interfaces: eth0 eth1 lo"
    def _sort_verify_echo(m):
        prefix = m.group(1)
        ifaces = sorted(m.group(2).split())
        return f'{prefix}{" ".join(ifaces)}"'

    text = re.sub(
        r'(echo "Verifying interfaces: )(.*?)"',
        _sort_verify_echo,
        text,
    )

    # Sort interface names in: for i in eth0 eth1 lo ; do
    def _sort_verify_for(m):
        prefix = m.group(1)
        ifaces = sorted(m.group(2).split())
        suffix = m.group(3)
        return f'{prefix}{" ".join(ifaces)}{suffix}'

    text = re.sub(
        r'(for i in )(.*?)( ; do)',
        _sort_verify_for,
        text,
    )

    # Sort update_addresses_of_interface lines within configure_interfaces()
    def _sort_configure_block(m):
        header = m.group(1)
        body = m.group(2)
        closing = m.group(3)
        lines = body.strip('\n').split('\n')
        update_lines = [
            line for line in lines if 'update_addresses_of_interface' in line
        ]
        other_lines = [
            line for line in lines if 'update_addresses_of_interface' not in line
        ]
        update_lines.sort()
        sorted_body = '\n'.join(other_lines + update_lines)
        return f'{header}\n{sorted_body}\n{closing}'

    text = re.sub(
        r'(configure_interfaces\(\) \{)\n(.*?)\n(\})',
        _sort_configure_block,
        text,
        flags=re.DOTALL,
    )

    # Sort comma-separated interface lists in rule labels:
    #   # Rule N (eth1,eth0)  ->  # Rule N (eth0,eth1)
    #   echo "Rule N (eth1,eth0)"  ->  echo "Rule N (eth0,eth1)"
    def _sort_rule_ifaces(m):
        prefix = m.group(1)
        ifaces = sorted(m.group(2).split(','))
        suffix = m.group(3)
        return f'{prefix}{",".join(ifaces)}{suffix}'

    text = re.sub(
        r'(Rule \d+ \()([a-zA-Z0-9_.,]+)(\))',
        _sort_rule_ifaces,
        text,
    )

    return text


def normalize_ipt(text: str) -> str:
    """Normalize iptables compiler output for expected output comparison."""
    # Normalize header comment (C++: "automatically generated", Python: "managed by")
    text = re.sub(
        r'^# +This is automatically generated file\. DO NOT MODIFY !$',
        '#  MANAGED_HEADER',
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^# +This file is managed by FirewallFabrik - do not edit$',
        '#  MANAGED_HEADER',
        text,
        flags=re.MULTILINE,
    )
    # Replace generated timestamp line
    text = re.sub(
        r'^(# +Generated ).*$',
        r'\1TIMESTAMP',
        text,
        flags=re.MULTILINE,
    )
    # Replace version header (C++: "Firewall Builder  fwb_ipt v5.3.7",
    # Python: "FirewallFabrik fwf-ipt v0.1.0")
    text = re.sub(
        r'^# +(?:Firewall Builder +fwb_ipt|FirewallFabrik fwf-ipt) (?:v\S+|VERSION)$',
        '#  TOOL VERSION',
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
    # Sort interface lists in verify_interfaces() and configure_interfaces()
    text = _sort_interfaces(text)
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
    """Normalize nftables compiler output for expected output comparison."""
    # Replace generated timestamp line (header comment)
    text = re.sub(
        r'^(# +Generated ).*$',
        r'\1TIMESTAMP',
        text,
        flags=re.MULTILINE,
    )
    # Replace version header
    text = re.sub(
        r'^(#  FirewallFabrik fwf-nft )v.*$',
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
    # Sort interface lists in verify_interfaces() and configure_interfaces()
    text = _sort_interfaces(text)
    # Collapse multiple consecutive blank lines into one
    text = re.sub(r'\n{3,}', '\n\n', text)
    # Strip trailing whitespace per line
    text = re.sub(r'[ \t]+$', '', text, flags=re.MULTILINE)
    # Ensure exactly one trailing newline (end-of-file-fixer compatibility)
    text = text.rstrip('\n') + '\n'
    return text
