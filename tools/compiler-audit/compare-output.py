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

"""Compare two compiled corpora at the level of packet filter rules.

Answers the question a release needs answered: which firewalls does this
change actually affect?  Compile the same corpus with the old and the new
compiler, then diff the two output trees.

    git worktree add /tmp/before v1.9.0
    PYTHONPATH=/tmp/before/src python tools/compiler-audit/compile-corpus.py /tmp/out-before
    python tools/compiler-audit/compile-corpus.py /tmp/out-after
    python tools/compiler-audit/compare-output.py /tmp/out-before /tmp/out-after

Only lines that append a rule to a chain are compared.  Everything else -
the version header, the helper functions, chain creation, comments - moves
around for reasons that never change how a packet is treated, and counting
it makes every script look changed.  Two normalisations matter in
particular, because leaving them out turns an unchanged corpus into a
hundred percent changed one:

* the nftables `counter` statement counts packets and decides nothing;
* `reset_all` and its helpers contain `$IPTABLES` without installing a rule.
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

# "$IPTABLES ... -A chain" and the iptables-restore "echo \"-A chain ...\"".
IPT_RULE = re.compile(r'\$(IPTABLES|IP6TABLES)\b.*\s-[AI]\s|^echo "-[AI]\s')
# Chain names carry a hash of the rule they were generated for.
CHAIN_HASH = re.compile(r'C[0-9a-fA-F]{6,}\.[0-9]*|Cid[0-9A-Za-z]*\.[0-9]*')
# Structure of an nftables ruleset, not a rule in it.
NFT_STRUCTURE = re.compile(
    r'^(table|chain|set|map|type|policy|flags|auto-merge|elements|delete|'
    r'flush|\}|\{)\b'
)
# A named counter object is structure; the counter statement of a rule is not.
NFT_COUNTER_DECL = re.compile(r'^counter\s+\S+\s*\{')
# Which table and chain the rules that follow are in.  A rule that moves
# between chains is a different rule - the iptables side says so in the
# command (`-A input`) and the nftables side only in the block around it,
# so without these two the whole policy of a firewall can move from the
# filter table to the mangle table and read as no change at all.
NFT_TABLE = re.compile(r'^table\s+(\S+)\s+(\S+)\s*\{')
NFT_CHAIN = re.compile(r'^chain\s+(\S+)\s*\{')


def rules(path: Path, platform: str) -> list[str]:
    """Return the normalised rule lines of one generated script."""
    out: list[str] = []
    in_ruleset = False
    where = ''
    for raw in path.read_text(errors='replace').splitlines():
        line = raw.strip()
        if platform == 'nft':
            if line.startswith('$NFT -f') or line.endswith("<<'NFT_RULES'"):
                in_ruleset = True
                continue
            if line == 'NFT_RULES':
                in_ruleset = False
                continue
            if not in_ruleset or not line or line.startswith('#'):
                continue
            table = NFT_TABLE.match(line)
            if table:
                where = f'{table.group(1)} {table.group(2)}'
                continue
            chain = NFT_CHAIN.match(line)
            if chain:
                where = f'{where.split(" @ ")[0]} @ {chain.group(1)}'
                continue
            if NFT_STRUCTURE.match(line) or NFT_COUNTER_DECL.match(line):
                continue
        elif not line or line.startswith('#') or not IPT_RULE.search(line):
            continue

        line = CHAIN_HASH.sub('CHAIN', line)
        line = re.sub(r'\s-w \d+\s', ' ', line)
        line = re.sub(r'-m conntrack --ctstate', '-m state --state', line)
        line = re.sub(r'\bcounter ', '', line)
        line = re.sub(r'\s+', ' ', line).strip()
        out.append(f'{where}: {line}' if platform == 'nft' else line)
    return sorted(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument(
        '--show',
        type=int,
        default=0,
        help='print up to N changed rules per script',
    )
    args = parser.parse_args()

    per_platform: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    changed: list[tuple[str, int, int]] = []

    for old in sorted(args.before.rglob('*.fw')):
        rel = old.relative_to(args.before)
        platform = rel.parts[0]
        per_platform[platform][0] += 1
        new = args.after / rel
        old_rules = rules(old, platform)
        if not new.exists():
            changed.append((str(rel), len(old_rules), 0))
            per_platform[platform][1] += 1
            continue
        new_rules = rules(new, platform)
        gone = set(old_rules) - set(new_rules)
        added = set(new_rules) - set(old_rules)
        if gone or added:
            changed.append((str(rel), len(gone), len(added)))
            per_platform[platform][1] += 1
            if args.show:
                print(f'=== {rel}')
                for rule in sorted(gone)[: args.show]:
                    print(f'  - {rule}')
                for rule in sorted(added)[: args.show]:
                    print(f'  + {rule}')

    if not per_platform:
        print(f'no scripts found under {args.before}', file=sys.stderr)
        return 1

    if not args.show:
        for rel, gone, added in changed:
            print(f'  -{gone:<5} +{added:<5} {rel}')

    print('---')
    for platform, (total, diff) in sorted(per_platform.items()):
        share = (total - diff) * 100 / total
        print(f'{platform}: {total - diff}/{total} scripts unchanged ({share:.1f}%)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
