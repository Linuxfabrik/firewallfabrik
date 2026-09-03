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

"""Find nftables rules whose negations were split into an "or".

A negated rule element means "none of these".  One nftables rule says it
with several ANDed matches or with one ``!=`` against a set; two rules
each negating one of the objects say something else entirely.  "Not this
*or* not that" holds for every packet as soon as the two objects differ,
so the rule matches everything: a Deny built on it blocks all traffic and
an Accept lets all of it through.

Nothing else in this directory can see it.  Both rules parse, both load,
both pass every replay, and `compare-reference.sh` counts lines rather
than asking what they match - the iptables compiler writes the same
element as a temporary chain with one RETURN per object and the two
outputs are not comparable line by line.

So: group the generated nftables rules by the ``# Rule <label>`` comment
they sit under, and within a group look for rules that are identical
except for the value one ``!=`` compares against.  Those are the split
negation.

    python tools/compiler-audit/check-negations.py /tmp/audit

Rules under one label that differ in something *else* as well are a
legitimate expansion - one rule per address family, per interface, per
protocol - and are left alone, because then the two do not both see the
same packet.
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

#: A negated comparison and the value behind it: `ip saddr != 10.0.0.1`,
#: `meta skuid != 500`, `tcp dport != { 22, 25 }`.  The keyword is
#: everything up to the operator, which is what makes two clauses
#: comparable.
NEGATION_RE = re.compile(
    r'(?P<keyword>[a-z0-9]+(?: [a-z0-9]+)*) != (?P<value>\{[^}]*\}|\S+)'
)

RULE_LABEL_RE = re.compile(r'^#\s*Rule\s')


CHAIN_RE = re.compile(r'^chain (?P<name>\S+) \{')

TABLE_RE = re.compile(r'^table (?P<family>\S+) (?P<name>\S+) \{')


def rules_by_label(script: Path) -> dict[str, list[str]]:
    """Return the rule lines of *script*, keyed by table, chain and label.

    The chain belongs in the key: one rule of the editor becomes a copy
    per chain, and the copy in `input` and the copy in `output` never see
    the same packet - so two negations that differ between them are the
    expansion doing its job and not an "or".  `RemoveFW` alone rewrites
    the source element of the output copy and leaves the input one as it
    was.
    """
    groups: dict[str, list[str]] = collections.defaultdict(list)
    label = ''
    table = ''
    chain = ''
    for raw in script.read_text().splitlines():
        line = raw.strip()
        found = TABLE_RE.match(line)
        if found:
            table = found.group('name')
            continue
        found = CHAIN_RE.match(line)
        if found:
            chain = found.group('name')
            label = ''
            continue
        if RULE_LABEL_RE.match(line):
            label = line
            continue
        if not line or line.startswith('#'):
            continue
        groups[f'{table} {chain}  {label}'].append(line)
    return groups


def split_negations(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Return (keyword, values) for every negation split across rules.

    Two rules that are the same except for what one ``!=`` compares
    against are an "or" of negations.  The rest of the line has to match
    exactly: a rule that also differs in its source address, its protocol
    or its interface is a different rule and sees different packets.
    """
    found: list[tuple[str, list[str]]] = []
    # signature -> {keyword: [values]}
    seen: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for line in lines:
        for match in NEGATION_RE.finditer(line):
            blanked = line[: match.start('value')] + '\x00' + line[match.end('value') :]
            key = (blanked, match.group('keyword').strip())
            values = seen[key]
            if match.group('value') not in values:
                values.append(match.group('value'))
    for (_, keyword), values in seen.items():
        if len(values) > 1:
            found.append((keyword, values))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        'outdir', type=Path, help='the directory compile-corpus.py wrote'
    )
    args = parser.parse_args()

    total = 0
    scripts = 0
    for script in sorted((args.outdir / 'nft').rglob('*.fw')):
        scripts += 1
        for label, lines in rules_by_label(script).items():
            for keyword, values in split_negations(lines):
                total += 1
                print(f'=== {script.relative_to(args.outdir / "nft")}  {label}')
                print(f'    "{keyword} !=" is split over {len(values)} rules: ')
                for value in values:
                    print(f'      {keyword} != {value}')
    print('---')
    print(f'{scripts} rulesets checked, {total} negations split into an "or"')
    return 0 if total == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
