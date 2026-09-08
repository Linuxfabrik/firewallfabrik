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

"""Is compiling one address family alone the same as half a dual-stack run?

The `-4` / `-6` switch is meant to be a filter and not a different compile:
the IPv4 rules of a firewall compiled with `-4` have to be exactly the IPv4
rules the ordinary run produces, and the same for `-6`.  Anything else is
state carried from one pass into the other, or a decision taken on the
wrong family - and no other oracle here can see it.  Both halves parse,
both load, and every set-comparing tool is handed one tree at a time.

Only the iptables side is compared.  A dual-stack nftables firewall writes
one `inet` table where `-4` writes an `ip` one, so there the two are not
the same text by design; the iptables output names its family in the tool
it calls, which makes the split exact.

    python tools/compiler-audit/compile-corpus.py /tmp/audit
    python tools/compiler-audit/compile-corpus.py --address-family 4 /tmp/af4
    python tools/compiler-audit/compile-corpus.py --address-family 6 /tmp/af6
    python tools/compiler-audit/compare-address-families.py \\
        /tmp/audit /tmp/af4 /tmp/af6
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

# `$IPTABLES` and `$IP6TABLES` say which family a command installs into,
# which is the whole split this oracle needs.
TOOL_RE = re.compile(r'\$(IP6TABLES|IPTABLES)\b(.*)')


def rules_by_family(path: Path) -> dict[str, collections.Counter] | None:
    """Return the rule-installing lines of `script_body()`, per family.

    Only that function, for the reason `compare-reference.sh` gives: the
    reset helpers, the coexistence jump setup and the block and stop
    actions hold `$IPTABLES` too, exist in every script and differ by
    design.
    """
    if not path.exists():
        return None
    text = path.read_text(errors='replace')
    start = text.find('script_body()')
    if start < 0:
        return None
    end = text.find('\nrun_epilog_and_exit', start)
    body = text[start : end if end > 0 else len(text)]

    found: dict[str, collections.Counter] = {
        'IPv4': collections.Counter(),
        'IPv6': collections.Counter(),
    }
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        match = TOOL_RE.search(stripped)
        if match:
            family = 'IPv6' if match.group(1) == 'IP6TABLES' else 'IPv4'
            found[family][match.group(2).strip()] += 1
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dual', type=Path, help='the ordinary corpus output')
    parser.add_argument('ipv4', type=Path, help='the output of --address-family 4')
    parser.add_argument('ipv6', type=Path, help='the output of --address-family 6')
    args = parser.parse_args()

    compared = 0
    findings = 0
    for script in sorted(args.dual.glob('ipt/*/*.fw')):
        relative = script.relative_to(args.dual)
        dual = rules_by_family(script)
        halves = {
            'IPv4': rules_by_family(args.ipv4 / relative),
            'IPv6': rules_by_family(args.ipv6 / relative),
        }
        if dual is None or any(half is None for half in halves.values()):
            continue
        compared += 1
        for family, half in halves.items():
            if dual[family] == half[family]:
                continue
            findings += 1
            print(f'=== {relative} {family}')
            for line, count in (dual[family] - half[family]).items():
                print(f'  only in the dual-stack run ({count}): {line}')
            for line, count in (half[family] - dual[family]).items():
                print(f'  only in the {family} run ({count}): {line}')

    print('---')
    print(f'{compared} scripts compared, {findings} halves that differ')
    return 0 if findings == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
