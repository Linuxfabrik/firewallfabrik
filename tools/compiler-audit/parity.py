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
    python tools/compiler-audit/parity.py /tmp/audit --values

The default comparison is deliberately coarse.  It looks at *which*
conditions a rule carries, not at their values or their order, because the
two compilers legitimately differ in how they spell a condition (`iif` vs
`iifname`, `th dport` vs `tcp dport`) and in how many rules they spread it
over.  What it does catch is a condition that is present on one side and
absent on the other, which is the failure mode that silently opens or
closes a firewall.

`--values` asks the other half of the question: a condition that is on
both sides but compares against something else - a wrong port, a wrong
mask, an inverted operator, a wrong ICMP type.  It is noisier, because the
two sides may say the same thing in different words, and the words it
already folds together are: hexadecimal against decimal, a protocol name
against its number, the flag list of a `tcp flags` match in any order, a
set against its elements one by one, the iptables spelling of a negation
(a temporary chain that RETURNs on the positive match) against `!=`, and
an address range against the CIDR blocks covering it.  What is left over
is worth reading: three findings of the 2026-08-19 round came out of it.

What that round left standing, all of it checked and none of it a bug:

  * an address table, a DNS name or a dynamic interface, which nftables
    matches through a named set (`ip saddr @cnn__rt_`) and iptables writes
    out address by address;
  * `meta day 1` against `meta day "Monday"` and `meta hour 32400-61200`
    against `meta hour "09:00:00"-"17:00:00"` - nftables takes both
    spellings and means the same by them;
  * `limit rate 10/minute burst 5 packets` against `limit rate 10/minute`
    - five is the default burst of both tools;
  * the name of a rate-limit table or a connection-limit set, which the
    two compilers derive differently;
  * `ip saddr timeout 1s` and `ct state new add @connlimit0 {`, which is
    the keyword scan cutting into a set definition rather than a match.

Blocks it skips, with the reason:

  * a label whose iptables commands are wrapped in a shell loop (an address
    table read at run time, a dynamic interface address) - the command line
    is not complete until the firewall runs it;
  * a label where any command fails to translate - `iptables-translate` has
    no rendering for `-m ipv4options`, `--icmp-type 8/0` and a few others,
    so the answer key has a hole there, not us.

Conditions it folds away in the default comparison:

  * `meta l4proto` next to a port or ICMP-type clause, which carries its
    own protocol dependency in nftables;
  * `meta l4proto !=`, which is how nftables writes "every protocol this
    negated element does not name" and iptables writes by leaving `-p` off
    the action rule of its temporary chain;
  * `-i +` / `-o +` against `meta iif != 0` / `meta oif != 0`, both of
    which ask whether the packet has an incoming (outgoing) device.
    `iptables-translate` throws the iptables half away, because it cannot
    know the rule is in a user chain, where the condition decides
    something.

The temporary chains iptables needs for negation and logging are *not*
skipped.  They spread one rule's conditions over a jump rule and the rules
it jumps to, and nftables says the same thing in a single rule, so both
sides are compared as the union over their label.
"""

from __future__ import annotations

import argparse
import collections
import functools
import ipaddress
import re
import shlex
import shutil
import socket
import subprocess  # nosec B404
import sys
from pathlib import Path

# A rule reaches us as one text line per side.  These are the keywords that
# say what the rule *matches on*; everything else (values, sets, counters)
# is intentionally invisible to the comparison.
NFT_KEYWORDS = (
    'ct count',
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
    'ip6 dscp',
    'ip frag-off',
    'ip protocol',
    'ip saddr',
    'ip6 daddr',
    'ip6 nexthdr',
    'ip6 saddr',
    'limit rate',
    'mark',
    'ct mark',
    'meta day',
    'meta hour',
    'meta l4proto',
    'meta mark',
    'meta skuid',
    'meta time',
    'meter',
    'oif',
    'skuid',
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
    'ip6 dscp': 'ip dscp',
    'meta l4proto': 'ip protocol',
    # The short spelling of `meta skuid`, and the one iptables-translate
    # writes.  Same trap as `mark` below: without it every NAT rule
    # naming a connection owner read as one condition we invented.
    'skuid': 'meta skuid',
    # `mark` is the short spelling of `meta mark`, and the one
    # iptables-translate writes.  `ct mark` is a different match and is in
    # the list above only so it wins the longest-match against `mark`.
    'mark': 'meta mark',
}

# Anchored on word boundaries, or a name inside the rule answers for a
# keyword: a chain called `mymark` contains `mark`, so firewall37 read as
# four rules missing a `meta mark` the nftables side has.  The chain name is
# part of the line iptables-translate produces
# (`add rule ip mangle mymark ...`), which is where it came from.
KEYWORD_RE = re.compile(
    r'\b(?:'
    + '|'.join(re.escape(k) for k in sorted(NFT_KEYWORDS, key=len, reverse=True))
    + r')\b'
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

# `# Rule 0 (global)`, `# Rule Policy:ipv4 16 (eth0,eth1)`, `# Rule 8`.  The
# warnings a rule collected are comments of the same shape ("# Rule 8 shadows
# Rule 28 below it: ..."), so the label has to end where the position and its
# optional interface list end.
LABEL_RE = re.compile(
    r'^\s*#\s*(Rule\s+[\w:.\[\]-]+(?:\s+[\w:.\[\]-]+)?(?:\s+\([^)]*\))?)\s*$'
)
# Not anchored: a command that reads an address at run time sits behind a
# `test -n "$i_ppp0" &&` on the same line, and those are exactly the labels
# that have to be recognised so they can be skipped.
IPT_CMD_RE = re.compile(r'\$(IP6?TABLES)\s+(.*)$')
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
        # A shell function boundary ends the label.  `script_body` is the
        # last thing in the file that carries rule labels, and the commands
        # of `block_action` and `stop_action` below it install rules too -
        # without this reset they are all counted against the file's last
        # labelled rule, which is why every dual-stack firewall read as
        # "missing ip daddr, tcp dport, tcp sport" for months.  The nft
        # reader resets on a chain boundary for the same reason.
        if line.startswith(('}', '#!')) or re.match(r'^\w+\(\)\s*\{', line):
            label = ''
            continue
        label_match = LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            continue
        cmd_match = IPT_CMD_RE.search(line)
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
            section, inside, label = table.group(1).rsplit('_', 1)[-1], True, ''
            continue
        stripped = line.strip()
        # A chain boundary ends the label.  Without this the automatic rules
        # at the top of the next chain are counted against the last labelled
        # rule of the previous one.
        if stripped.startswith(('chain ', 'set ', 'counter ')) or stripped == '}':
            label = ''
            if line.startswith('}'):
                inside = False
            continue
        if not inside:
            continue
        label_match = LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            continue
        if not stripped or stripped.startswith(('#', 'type ', 'elements', 'flags')):
            continue
        if label:
            groups[(section, label)].append(stripped)
    return groups


@functools.cache
def translate(args: str, ipv6: bool) -> str | None:
    """Return what iptables-translate makes of one command, or None.

    The command is read out of a shell script, so its arguments follow
    shell quoting: a log prefix is one argument with blanks in it.
    Splitting on whitespace hands `--log-prefix "RULE 13 -- DENY "` to the
    translator as six arguments, which it refuses - and every label
    carrying a log rule was then skipped instead of compared.
    """
    binary = 'ip6tables-translate' if ipv6 else 'iptables-translate'
    try:
        argv = shlex.split(args)
    except ValueError:
        # Unbalanced quoting: not a command line we can hand on.
        return None
    try:
        proc = subprocess.run(  # nosec B603
            [binary, *argv],
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


# The six TCP flags, in the order the header carries them, so a numeric
# value can be read back as the names nftables prints.
TCP_FLAG_NAMES = ('fin', 'syn', 'rst', 'psh', 'ack', 'urg')


@functools.cache
def protocol_number(name: str) -> str | None:
    """Return the IP protocol number of *name*, or None if it is not one."""
    try:
        return str(socket.getprotobyname(name))
    except OSError:
        return None


def norm_token(token: str) -> str:
    """Fold one value into the spelling both sides can be compared in."""
    token = token.strip().strip(',')
    if not token:
        return token
    number = protocol_number(token.lower())
    if number is not None:
        return number
    if re.fullmatch(r'0x[0-9a-fA-F]+|\d+', token):
        return str(int(token, 0))
    match = re.fullmatch(r'([0-9a-fA-F:.]+)/([0-9.]+)', token)
    if match:
        try:
            network = ipaddress.ip_network(f'{match[1]}/{match[2]}', strict=False)
        except ValueError:
            return token
        if network.prefixlen == network.max_prefixlen:
            return str(network.network_address)
        return str(network)
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return token


def norm_flags(value: str) -> str | None:
    """Fold a `tcp flags` value, or return None if this is not one.

    nftables prints the mask as `& (a | b)` and the value as a number or a
    name list, iptables-translate as `value / mask`.  Both become
    `<op> <sorted value> / <sorted mask>`.
    """
    value = value.strip()

    def flag_names(raw: str) -> str:
        """Return the flags of one side, sorted, whether named or a number."""
        if re.fullmatch(r'0x[0-9a-fA-F]+|\d+', raw):
            bits = int(raw, 0)
            names = [n for i, n in enumerate(TCP_FLAG_NAMES) if bits & (1 << i)]
        else:
            names = [part.strip() for part in raw.split(',')]
        return ','.join(sorted(name for name in names if name))

    match = re.fullmatch(r'&\s*\(([^)]*)\)\s*(==|!=)\s*(\S+)', value)
    if match:
        mask = ','.join(sorted(part.strip() for part in match[1].split('|')))
        return f'{match[2]} {flag_names(match[3])} / {mask}'
    match = re.fullmatch(r'([0-9a-zx,]*)\s*/\s*([0-9a-zx,]+)', value)
    if match:
        return f'== {flag_names(match[1])} / {flag_names(match[2])}'
    return None


def value_items(value: str, keyword: str = ''):
    """Yield one comparable item per value, a set as its elements.

    *keyword* is what the value belongs to, because the flag folding is
    only right for one of them: `5/second` is a rate and `norm_flags`
    happily reads it as the TCP flags `fin,rst` over the mask `second`,
    which turned every rate limit standing beside a flag match into a
    difference on both sides.
    """
    value = re.sub(r'\s+', ' ', value.strip())
    if keyword == 'tcp flags':
        flags = norm_flags(value)
        if flags is not None:
            yield flags
            return
    negation = ''
    match = re.fullmatch(r'(!=)\s*(.*)', value)
    if match:
        negation, value = '!= ', match[2]
    match = re.fullmatch(r'\{(.*)\}', value)
    if match:
        for token in match[1].split(','):
            if token.strip():
                yield negation + norm_token(token)
        return
    if value:
        yield negation + ' '.join(norm_token(part) for part in value.split())


def value_pairs(text: str) -> collections.Counter:
    """Return the (keyword, value) pairs of one rule."""
    part = match_part(text)
    found: collections.Counter = collections.Counter()
    hits = list(KEYWORD_RE.finditer(part))
    for index, hit in enumerate(hits):
        end = hits[index + 1].start() if index + 1 < len(hits) else len(part)
        keyword = SYNONYMS.get(hit.group(0), hit.group(0))
        for item in value_items(part[hit.end() : end], keyword):
            found[(keyword, item)] += 1
    return found


def fold_spellings(want: set, have: set) -> tuple[set, set]:
    """Drop the pairs whose two sides say the same thing in different words."""
    # iptables spells a negation as a temporary chain that RETURNs on the
    # positive match; nftables writes `!=`.  A `tcp flags` value carries its
    # operator inside the folded spelling `norm_flags` produces, so the
    # positive side of that pair reads `== <flags> / <mask>` rather than the
    # bare value every other keyword has.
    for keyword, value in list(have):
        if not value.startswith('!= '):
            continue
        for positive in (value[3:], f'== {value[3:]}'):
            if (keyword, positive) in want:
                have.discard((keyword, value))
                want.discard((keyword, positive))
                break
    # The iptables NAT pipeline writes an address range out as the CIDR
    # blocks covering it; nftables matches the range natively.
    for keyword, value in list(have):
        if '-' not in value or keyword not in ('ip saddr', 'ip daddr'):
            continue
        try:
            low, high = (ipaddress.ip_address(end) for end in value.split('-'))
        except ValueError:
            continue
        blocks = {str(net) for net in ipaddress.summarize_address_range(low, high)}
        blocks |= {str(ipaddress.ip_network(b).network_address) for b in blocks}
        same = {other for other in want if other[0] == keyword}
        if blocks >= {other[1] for other in same}:
            have.discard((keyword, value))
            want -= same
    return want, have


def compare_values(
    script_ipt: Path, script_nft: Path
) -> list[tuple[str, str, list[str], list[str]]]:
    """Return (table, label, ipt-only, nft-only) per label whose values differ."""
    report = []
    ipt_groups = read_ipt(script_ipt)
    nft_groups = read_nft(script_nft)

    for key, commands in sorted(ipt_groups.items()):
        if any(RUNTIME_RE.search(args) for args, _ in commands):
            continue
        expected: collections.Counter | None = collections.Counter()
        for args, ipv6 in commands:
            translated = translate(re.sub(r'-w\s+\d+\s*', '', args), ipv6)
            if translated is None:
                expected = None
                break
            for line in translated.splitlines():
                expected += value_pairs(line)
        if expected is None:
            continue

        actual: collections.Counter = collections.Counter()
        for rule in nft_groups.get(key, []):
            actual += value_pairs(rule)

        want, have = fold_spellings(set(expected), set(actual))
        # A keyword only one side carries at all is what the default
        # comparison reports; here only a *differing value* counts.
        keywords_want = {keyword for keyword, _ in want}
        keywords_have = {keyword for keyword, _ in have}
        ipt_only = sorted(f'{k} {v}' for k, v in want - have if k in keywords_have)
        nft_only = sorted(f'{k} {v}' for k, v in have - want if k in keywords_want)
        if ipt_only or nft_only:
            report.append((key[0], key[1], ipt_only, nft_only))
    return report


def fold_implied_protocol(found: collections.Counter) -> set[str]:
    """Return the keywords of one side with the implied ones taken out.

    A port, ICMP-type or TCP-flags clause carries its own protocol
    dependency in nftables, so an explicit `meta l4proto` next to it says
    nothing new: `tcp flags syn,ack / syn,ack` alone compiles to `meta load
    l4proto; cmp eq 6` and then the flag test, which `nft --debug=netlink`
    prints back.  `iptables-translate` writes the protocol out because the
    iptables command needed a `-p` for its match module, we leave it out -
    the two rules match the same packets either way.
    """
    names = set(found)
    if names & {'tcp dport', 'tcp sport', 'tcp flags', 'icmp type', 'icmp code'}:
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
        # "Every protocol this negated element does not name" is a condition
        # nftables has to write down (`meta l4proto != tcp`) and iptables
        # says by leaving `-p` off the action rule of its temporary chain.
        # Same rule, and only one side has a keyword for it.
        if 'ip protocol' in extra and any(
            'meta l4proto !=' in rule for rule in nft_groups.get(key, [])
        ):
            extra.remove('ip protocol')
        # "The packet has an incoming (outgoing) device", which a rule with
        # a direction and no interface of its own asks for.  iptables writes
        # `-i +` / `-o +` and nftables `meta iif != 0`, and
        # `iptables-translate` throws the iptables half away - it has no way
        # to know the rule is in a user chain, where the condition decides
        # something.  Same rule, and only one side has a keyword left.
        for option, keyword in (('-i +', 'iifname'), ('-o +', 'oifname')):
            if keyword in extra and any(option in args for args, _ in commands):
                extra.remove(keyword)
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
    parser.add_argument(
        '--values',
        action='store_true',
        help='compare what each condition matches, not only which conditions',
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
        report = (
            compare_values(script_ipt, script_nft)
            if args.values
            else compare(script_ipt, script_nft)
        )
        if not report:
            continue
        differing += 1
        print(f'=== {relative}')
        for section, label, missing, extra in report:
            if args.values:
                print(f'  {section}/{label}')
                for item in missing:
                    print(f'      ipt-only: {item}')
                    counter[f'ipt-only {item.split(" ")[0]}'] += 1
                for item in extra:
                    print(f'      nft-only: {item}')
                    counter[f'nft-only {item.split(" ")[0]}'] += 1
                continue
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
