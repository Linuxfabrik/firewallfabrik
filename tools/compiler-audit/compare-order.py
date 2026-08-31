#!/usr/bin/env python3
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

"""Do the two platforms install one base chain's rules in one order?

First match wins in both packet filters, so two rules that swap places are
two different firewalls - and no other oracle looks: `compare-reference.sh`
compares multisets of lines, `parity.py` compares what a label matches on
and not where the label sits, and `nft --check` and the iptables replay are
happy with any order at all.

The comparison is per base chain, because that is where the order decides
something.  A user chain is reached by a jump whose position in the base
chain is what was compared, and its name differs between the two compilers
anyway.  Only the labels both sides carry are compared: a rule one platform
reports and leaves out is a difference of its own and the report.json
ranking is where it belongs.

With `--reference` the same question is asked of the iptables output
against the Firewall Builder reference.

    python tools/compiler-audit/compare-order.py /tmp/audit
    python tools/compiler-audit/compare-order.py /tmp/audit --reference \\
        ~/git/other/fwbuilder/fwbuilder5/test/ipt
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import parity

# The chains a packet reaches without a jump, in the spelling each side
# writes.  Everything else is a user chain.
BASE_CHAINS = {
    'FORWARD': 'forward',
    'INPUT': 'input',
    'OUTPUT': 'output',
    'POSTROUTING': 'postrouting',
    'PREROUTING': 'prerouting',
}


def ipt_order(path: Path) -> dict[tuple[str, str], list[str]]:
    """Return the label sequence of each base chain of an iptables script."""
    order: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    label = ''
    for line in path.read_text(errors='replace').splitlines():
        # The same boundaries `parity.read_ipt` keeps: the commands of
        # `block_action` and `stop_action` install rules too and carry no
        # label of their own.
        if line.startswith(('}', '#!')) or re.match(r'^\w+\(\)\s*\{', line):
            label = ''
            continue
        label_match = parity.LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            continue
        cmd = parity.IPT_CMD_RE.search(line)
        if not cmd or not label:
            continue
        args = cmd.group(2)
        appended = re.search(r'\s-A\s+(\S+)', args)
        if not appended or appended.group(1) not in BASE_CHAINS:
            continue
        key = (parity.section_of(args), BASE_CHAINS[appended.group(1)])
        if not order[key] or order[key][-1] != label:
            order[key].append(label)
    return order


def nft_order(path: Path) -> dict[tuple[str, str], list[str]]:
    """Return the label sequence of each base chain of an nftables script."""
    order: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    label = ''
    section = 'filter'
    chain = ''
    for line in path.read_text(errors='replace').splitlines():
        table = re.match(r'^table\s+\w+\s+(\S+)\s*\{\s*$', line)
        if table:
            # The table is named after the firewall: `fwf_filter`, `fwf_nat`.
            section = table.group(1).rsplit('_', 1)[-1]
            label, chain = '', ''
            continue
        opened = re.match(r'^\s*chain\s+(\S+)\s*\{', line)
        if opened:
            chain, label = opened.group(1), ''
            continue
        label_match = parity.LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(
            ('#', '}', 'type ', 'set ', 'counter ', 'table ')
        ):
            continue
        if not label or chain not in BASE_CHAINS.values():
            continue
        key = (section, chain)
        if not order[key] or order[key][-1] != label:
            order[key].append(label)
    return order


def compare(
    left: dict[tuple[str, str], list[str]], right: dict[tuple[str, str], list[str]]
) -> list[tuple[tuple[str, str], list[str], list[str]]]:
    """Return the chains whose common labels come in two different orders."""
    differences = []
    for key in sorted(set(left) & set(right)):
        here = [name for name in left[key] if name in set(right[key])]
        there = [name for name in right[key] if name in set(left[key])]
        if here != there:
            differences.append((key, here, there))
    return differences


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        'outdir', type=Path, help='the directory compile-corpus.py wrote'
    )
    parser.add_argument(
        '--reference',
        type=Path,
        help='compare the iptables output against a Firewall Builder test/ipt '
        'directory instead of against the nftables output',
    )
    args = parser.parse_args()

    scripts = 0
    differing = 0
    for script_ipt in sorted((args.outdir / 'ipt').rglob('*.fw')):
        if args.reference:
            other = args.reference / f'{script_ipt.stem}.fw.orig'
            if not other.exists():
                continue
            left, right = ipt_order(script_ipt), ipt_order(other)
            names = ('ours', 'gold')
        else:
            other = args.outdir / 'nft' / script_ipt.relative_to(args.outdir / 'ipt')
            if not other.exists():
                continue
            left, right = ipt_order(script_ipt), nft_order(other)
            names = ('ipt', 'nft')
        scripts += 1
        for (section, chain), here, there in compare(left, right):
            differing += 1
            print(f'=== {script_ipt.stem} {section}/{chain}')
            print(f'  {names[0]}: {" ".join(here)}')
            print(f'  {names[1]}: {" ".join(there)}')

    print('---')
    print(f'{scripts} scripts compared, {differing} base chains ordered differently')
    return 0


if __name__ == '__main__':
    sys.exit(main())
