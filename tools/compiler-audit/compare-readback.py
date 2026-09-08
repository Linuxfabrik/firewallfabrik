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

"""Is the ruleset a machine lists back the ruleset that was installed?

`load-nft.sh` asks whether a real kernel takes the ruleset and stops
there.  This one asks the next question: after the load, does
`nft list ruleset` still say what we wrote?

That is not a cosmetic question.  The listing is what an administrator
reads when auditing the firewall, and it is what a machine reloads:
`nft list ruleset > /etc/nftables.conf` is how nftables.service saves and
restores a ruleset.  A rule the listing renders as something weaker than
what was installed becomes that weaker rule at the next boot, and nothing
anywhere reports it - the ruleset loads, every replay passes, and every
other check in this directory compares the *written* text against the
tools rather than against what came back.

    python tools/compiler-audit/compare-readback.py /tmp/audit

The comparison is not made on the two texts.  nft prints a rule in its
own spelling - `meta l4proto 50` comes back as `meta l4proto esp`, a mark
in hex, a set with its elements sorted and its intervals merged, a rate
limit with the burst the parser fills in - and none of that is a
finding.  So both texts are handed back to `nft --debug=netlink`, which
prints the expression list each one linearises to, and *those* are
compared.  Two rulesets with the same expression lists are the same
ruleset, whatever either one looks like.

What it finds, in the round it was written for: every rule of a
dual-stack firewall whose family was pinned with a leading
`meta nfproto`.  nft reads that as a protocol dependency and releases it
as soon as a protocol expression follows (`meta_match_postprocess` and
`payload_dependency_kill`, netfilter nftables src/netlink_delinearize.c),
so `meta nfproto ipv4 meta l4proto 50` listed back as `meta l4proto 50` -
a rule that also matches an IPv6 packet whose last next-header is 50.

Two differences are folded away and nothing else is, both of them the
one thing nft does to an anonymous set on the way in: it stores it
sorted and merges its adjacent intervals.  `{ 192.168.1.0/24,
192.168.2.0/24 }` is one interval by the time the kernel has it and
comes back as `{ 192.168.1.0-192.168.2.255 }`, which nft then linearises
as a range rather than a set lookup.  Neither the order nor the merge
changes which addresses the rule matches, so the set declarations are
left out of the comparison and a set lookup and a range compare equal.
That is also the blind spot: an element genuinely lost inside a set
would not show up here.  `fill-nft-sets.sh` is what reads set contents.

Needs `nft` and `unshare`, and a host that grants an unprivileged user
namespace.  Everything happens in a private network namespace, so the
machine's own firewall is untouched.
"""

from __future__ import annotations

import argparse
import difflib
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

#: The heredoc the generated script pipes into nft.
HEREDOC_START = re.compile(r"<<-?'?NFT_RULES'?$")
HEREDOC_END = 'NFT_RULES'

#: A `meta skuid` / `meta skgid` names a user nft looks up with getpwnam
#: while it parses the rule, and it refuses the whole ruleset when the
#: answer is no.  The firewall those rules are for has that user; this
#: machine has no reason to.  Same reasoning as in check-nft.sh.
USER_MATCH = re.compile(r'meta sk(uid|gid) (?:!= )?([A-Za-z_][A-Za-z0-9._-]*)')

#: A line of `nft --debug=netlink` output that belongs to a set rather
#: than to a rule: the header of an anonymous set and its elements.  A
#: set is stored sorted and with its adjacent intervals merged, so its
#: declaration never comes back the way it went out.
SET_LINE = re.compile(r'^\s*element |^family \d+ __set%d ')

#: A lookup against an anonymous set and a range comparison.  An interval
#: set that merges down to a single interval is printed as a range and
#: linearises as one, so the two are the same condition here.
SET_OR_RANGE = re.compile(
    r'\[ (?:lookup reg (?P<lookup>\d+) set __set%d|range \w+ reg (?P<range>\d+))[^]]*\]'
)

#: The size of a named set, which the kernel fills in rather than
#: reporting what the ruleset said: a set a rule adds elements to and
#: that names no size is capped at 0xffff elements
#: (``nft_dynset_init``, linux/net/netfilter/nft_dynset.c).  This
#: compiler declares no size, so the number is always the kernel's.
SET_SIZE = re.compile(r'^(family \d+ \S+ \S+ \d+) size \d+$')

#: The declaration of a named set.  A meter names its set in the rule
#: that fills it and nft declares it there; the listing declares every
#: set at the top of its table, so the two differ in where the line sits
#: and in nothing else.  They are compared as a set of lines.
SET_DECLARATION = re.compile(r'^family \d+ \S+ \S+ \d+$')


def extract_ruleset(script: Path) -> str:
    """The nftables ruleset the generated script carries, or ``''``."""
    lines: list[str] = []
    inside = False
    for line in script.read_text().splitlines():
        if inside:
            if line == HEREDOC_END:
                break
            lines.append(line)
        elif HEREDOC_START.search(line):
            inside = True
    return '\n'.join(lines) + '\n' if lines else ''


def write_user_db(ruleset: str, workdir: Path) -> tuple[Path, Path]:
    """A passwd and a group file holding every name the ruleset looks up."""
    passwd = workdir / 'passwd'
    group = workdir / 'group'
    passwd.write_text(Path('/etc/passwd').read_text())
    group.write_text(Path('/etc/group').read_text())
    uid = 60000
    for kind, name in sorted(set(USER_MATCH.findall(ruleset))):
        target = passwd if kind == 'uid' else group
        if re.search(rf'^{re.escape(name)}:', target.read_text(), re.MULTILINE):
            continue
        with target.open('a') as handle:
            if kind == 'uid':
                handle.write(f'{name}:x:{uid}:{uid}::/nonexistent:/usr/sbin/nologin\n')
            else:
                handle.write(f'{name}:x:{uid}:\n')
        uid += 1
    return passwd, group


def in_namespace(command: str, passwd: Path, group: Path) -> tuple[int, str]:
    """Run *command* in a private network namespace with that user database."""
    proc = subprocess.run(  # nosec B603
        [
            shutil.which('unshare') or 'unshare',
            '-rnm',
            'bash',
            '-c',
            f"mount --bind '{passwd}' /etc/passwd\n"
            f"mount --bind '{group}' /etc/group\n"
            f'{command}',
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout


def linearise(ruleset: Path, passwd: Path, group: Path) -> list[str]:
    """The expression list nft turns *ruleset* into, one line per expression."""
    code, out = in_namespace(f"nft --debug=netlink --file '{ruleset}'", passwd, group)
    if code != 0:
        return []
    lines = []
    declarations = []
    for line in out.splitlines():
        if SET_LINE.match(line):
            continue
        line = SET_SIZE.sub(r'\1', line.rstrip())
        if SET_DECLARATION.match(line):
            declarations.append(line)
            continue
        lines.append(
            SET_OR_RANGE.sub(
                lambda m: f'[ set-or-range reg {m["lookup"] or m["range"]} ]',
                line,
            )
        )
    return lines + sorted(declarations)


def compare(script: Path, workdir: Path) -> list[str] | None:
    """The diff between installed and listed, ``None`` when there is none."""
    ruleset = extract_ruleset(script)
    if not ruleset:
        return None
    written = workdir / 'written.nft'
    written.write_text(ruleset)
    passwd, group = write_user_db(ruleset, workdir)

    code, listed = in_namespace(
        f"nft --file '{written}' && nft list ruleset", passwd, group
    )
    if code != 0:
        # The load is `load-nft.sh`'s question, and it reports it there.
        return None
    readback = workdir / 'readback.nft'
    readback.write_text(listed)

    before = linearise(written, passwd, group)
    after = linearise(readback, passwd, group)
    if not before or not after or before == after:
        return None

    return [
        line
        for line in difflib.unified_diff(
            before, after, 'installed', 'listed', n=1, lineterm=''
        )
        if line.startswith(('+', '-', '@'))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        'outdir', type=Path, help='the directory compile-corpus.py wrote'
    )
    args = parser.parse_args()

    for tool in ('nft', 'unshare'):
        if not shutil.which(tool):
            print(f'{tool} not installed', file=sys.stderr)
            return 2

    total = 0
    differ = 0
    for script in sorted(args.outdir.rglob('*.fw')):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            if not extract_ruleset(script):
                continue
            total += 1
            diff = compare(script, workdir)
        if diff:
            differ += 1
            print(f'=== {script.relative_to(args.outdir)}')
            for line in diff:
                print(f'  {line}')
    print('---')
    print(f'{total} rulesets listed back, {differ} that are not what was installed')
    return 0 if differ == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
