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

"""Ask iptables-translate what our nftables rules should have looked like.

The other checks in this directory prove that a ruleset *loads*.  This one
asks the harder question: does the nftables ruleset match the same packets
as the iptables one compiled from the same rule?  Nothing in the project
can answer that on its own, because the two compilers share no code path
that far down.  netfilter ships an answer key, though - `iptables-translate`
turns an iptables command into the nftables rule netfilter itself considers
equivalent, and `extensions/*.txlate` are its regression tests.

So: group the generated iptables commands by their `# Rule <label>`
comment, translate each one, and compare the multiset of match keywords
against our own nftables rules under the same label.  A keyword the
translation has and we do not is a condition we fail to check; one we have
and it does not is a condition we invented.

    python tools/compiler-audit/parity.py /tmp/audit
    python tools/compiler-audit/parity.py /tmp/audit --fixture compiler-tests
    python tools/compiler-audit/parity.py /tmp/audit --show

The comparison is deliberately coarse.  It looks at *which* conditions a
rule carries, not at their values or their order, because the two compilers
legitimately differ in how they spell a condition (`iif` vs `iifname`,
`th dport` vs `tcp dport`) and in how many rules they spread it over.  What
it does catch is a condition that is present on one side and absent on the
other, which is the failure mode that silently opens or closes a firewall.

Blocks it skips, with the reason:

  * a label whose iptables commands are wrapped in a shell loop (an address
    table read at run time, a dynamic interface address) - the command line
    is not complete until the firewall runs it;
  * a label where any command fails to translate - `iptables-translate` has
    no rendering for `-m ipv4options`, `--icmp-type 8/0` and a few others,
    so the answer key has a hole there, not us.

The temporary chains iptables needs for negation and logging are *not*
skipped.  They spread one rule's conditions over a jump rule and the rules
it jumps to, and nftables says the same thing in a single rule, so both
sides are compared as the union over their label.
"""

from __future__ import annotations

import argparse
import collections
import functools
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

# A rule reaches us as one text line per side.  These are the keywords that
# say what the rule *matches on*; everything else (values, sets, counters)
# is intentionally invisible to the comparison.
NFT_KEYWORDS = (
    'ct state',
    'ether saddr',
    'icmp code',
    'icmp type',
    'icmpv6 code',
    'icmpv6 type',
    'iif',
    'iifname',
    'ip daddr',
    'ip dscp',
    'ip frag-off',
    'ip protocol',
    'ip saddr',
    'ip6 daddr',
    'ip6 nexthdr',
    'ip6 saddr',
    'limit rate',
    'meta day',
    'meta hour',
    'meta l4proto',
    'meta mark',
    'meta skuid',
    'oif',
    'oifname',
    'sctp dport',
    'sctp sport',
    'tcp dport',
    'tcp flags',
    'tcp sport',
    'th dport',
    'th sport',
    'udp dport',
    'udp sport',
)

# Spellings the two sides may legitimately choose between.  Folding them
# together is what keeps the report down to the differences that mean
# something.
SYNONYMS = {
    'iif': 'iifname',
    'oif': 'oifname',
    'th dport': 'tcp dport',
    'th sport': 'tcp sport',
    'udp dport': 'tcp dport',
    'udp sport': 'tcp sport',
    'sctp dport': 'tcp dport',
    'sctp sport': 'tcp sport',
    'icmpv6 type': 'icmp type',
    'icmpv6 code': 'icmp code',
    'ip6 saddr': 'ip saddr',
    'ip6 daddr': 'ip daddr',
    'ip6 nexthdr': 'ip protocol',
    'meta l4proto': 'ip protocol',
}

KEYWORD_RE = re.compile(
    '|'.join(re.escape(k) for k in sorted(NFT_KEYWORDS, key=len, reverse=True))
)

# What a rule does, as opposed to what it matches.  Both compilers write the
# statements last, so the first one of these ends the match part.
STATEMENTS = (
    'accept',
    'counter',
    'drop',
    'goto',
    'jump',
    'log',
    'masquerade',
    'meta mark set',
    'meta priority set',
    'queue',
    'redirect',
    'reject',
    'return',
    'snat',
    'dnat',
)

LABEL_RE = re.compile(r'^\s*#\s*(Rule\s+.*?)\s*$')
IPT_CMD_RE = re.compile(r'^\s*\$(IP6?TABLES)\s+(.*)$')
# A command that is only complete once the firewall runs it.
RUNTIME_RE = re.compile(r'\$\{?[A-Za-z_][A-Za-z0-9_]*')


def section_of(args: str) -> str:
    """Return the table a command or rule belongs to."""
    match = re.search(r'-t\s+(\w+)', args)
    return match.group(1) if match else 'filter'


def read_ipt(path: Path) -> dict[tuple[str, str], list[tuple[str, bool]]]:
    """Return the iptables commands of *path*, grouped by table and label."""
    groups: dict[tuple[str, str], list[tuple[str, bool]]] = collections.defaultdict(
        list
    )
    label = ''
    for line in path.read_text(errors='replace').splitlines():
        label_match = LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            continue
        cmd_match = IPT_CMD_RE.match(line)
        if not cmd_match or not label:
            continue
        binary, args = cmd_match.groups()
        if not re.search(r'\s-[AI]\s', args):
            continue
        groups[(section_of(args), label)].append((args, binary == 'IP6TABLES'))
    return groups


def read_nft(path: Path) -> dict[tuple[str, str], list[str]]:
    """Return the nftables rules of *path*, grouped by table and label."""
    groups: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    label = ''
    section = 'filter'
    inside = False
    for line in path.read_text(errors='replace').splitlines():
        table = re.match(r'^table\s+\w+\s+(\S+)\s*\{\s*$', line)
        if table:
            # The table is named after the firewall: `fwf_filter`, `fwf_nat`.
            section, inside = table.group(1).rsplit('_', 1)[-1], True
            continue
        if line.startswith('}'):
            inside = False
            continue
        if not inside:
            continue
        label_match = LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            continue
        rule = line.strip()
        if not rule or rule.startswith(
            ('#', 'chain', 'type ', 'set ', 'counter ', '}')
        ):
            continue
        if label:
            groups[(section, label)].append(rule)
    return groups


@functools.cache
def translate(args: str, ipv6: bool) -> str | None:
    """Return what iptables-translate makes of one command, or None."""
    binary = 'ip6tables-translate' if ipv6 else 'iptables-translate'
    try:
        proc = subprocess.run(  # nosec B603
            [binary, *args.split()],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = proc.stdout.strip()
    # A command it has no rendering for comes back echoed as a comment
    # ("nft # -A INPUT -p icmp --icmp-type 8/0 ..."), with exit code 0.
    if proc.returncode != 0 or not out or out.startswith('nft #'):
        return None
    return out


def match_part(rule: str) -> str:
    """Return the part of an nftables rule before its first statement.

    Everything a rule *does* has to be cut off before the keywords are
    counted, or a verdict is read as a match: `reject with icmp type
    prot-unreachable` ends in the same two words as an ICMP type match, and
    a log prefix is user text that can contain anything at all.
    """
    cut = len(rule)
    for statement in STATEMENTS:
        match = re.search(rf'(?:^|\s){statement}(?:\s|$)', rule)
        if match:
            cut = min(cut, match.start())
    return rule[:cut]


def keywords(text: str) -> collections.Counter:
    """Return the match keywords of a rule, folded to one spelling each."""
    found = collections.Counter()
    for keyword in KEYWORD_RE.findall(match_part(text)):
        found[SYNONYMS.get(keyword, keyword)] += 1
    return found


def fold_implied_protocol(found: collections.Counter) -> set[str]:
    """Return the keywords of one side with the implied ones taken out.

    A port or ICMP-type clause carries its own protocol dependency in
    nftables, so an explicit `meta l4proto` next to it says nothing new.
    `iptables-translate` writes one because the iptables command needed a
    `-p` for its match module, we leave it out - the two rules match the
    same packets either way.
    """
    names = set(found)
    if names & {'tcp dport', 'tcp sport', 'icmp type', 'icmp code'}:
        names.discard('ip protocol')
    return names


def compare(
    script_ipt: Path, script_nft: Path
) -> list[tuple[str, str, list[str], list[str]]]:
    """Return (table, label, missing, extra) per label whose sides disagree."""
    report = []
    ipt_groups = read_ipt(script_ipt)
    nft_groups = read_nft(script_nft)

    for key, commands in sorted(ipt_groups.items()):
        section, label = key
        # A command completed at run time is not a command yet.
        if any(RUNTIME_RE.search(args) for args, _ in commands):
            continue
        expected = collections.Counter()
        for args, ipv6 in commands:
            # `-w` is an iptables-only lock option and `--wait` confuses the
            # translator; the table is passed separately below.
            clean = re.sub(r'-w\s+\d+\s*', '', args)
            translated = translate(clean, ipv6)
            if translated is None:
                expected = None
                break
            for line in translated.splitlines():
                expected += keywords(line)
        if expected is None:
            continue

        actual = collections.Counter()
        for rule in nft_groups.get(key, []):
            actual += keywords(rule)

        # Only presence matters, not how many rules a side spreads it over.
        want = fold_implied_protocol(expected)
        have = fold_implied_protocol(actual)
        missing = sorted(want - have)
        extra = sorted(have - want)
        if missing or extra:
            report.append((section, label, missing, extra))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        'outdir', type=Path, help='the directory compile-corpus.py wrote'
    )
    parser.add_argument('--fixture', help='only firewalls of this fixture')
    parser.add_argument(
        '--show', action='store_true', help='print the two sides of every difference'
    )
    args = parser.parse_args()

    if shutil.which('iptables-translate') is None:
        print('iptables-translate not installed', file=sys.stderr)
        return 2

    ipt_root = args.outdir / 'ipt'
    nft_root = args.outdir / 'nft'
    if not ipt_root.is_dir() or not nft_root.is_dir():
        print(f'{args.outdir} holds no ipt/ and nft/ output', file=sys.stderr)
        return 2

    checked = 0
    differing = 0
    counter: collections.Counter = collections.Counter()
    for script_ipt in sorted(ipt_root.rglob('*.fw')):
        relative = script_ipt.relative_to(ipt_root)
        if args.fixture and relative.parts[0] != args.fixture:
            continue
        script_nft = nft_root / relative
        if not script_nft.exists():
            continue
        checked += 1
        report = compare(script_ipt, script_nft)
        if report:
            differing += 1
            print(f'=== {relative}')
            for section, label, missing, extra in report:
                print(
                    f'  {section}/{label}: '
                    f'missing=[{", ".join(missing)}] extra=[{", ".join(extra)}]'
                )
                for keyword in missing:
                    counter[f'missing {keyword}'] += 1
                for keyword in extra:
                    counter[f'extra {keyword}'] += 1

    print('---')
    for name, count in counter.most_common():
        print(f'{count:5d}  {name}')
    print(f'{checked} firewalls compared, {differing} with at least one difference')
    return 0


if __name__ == '__main__':
    sys.exit(main())
