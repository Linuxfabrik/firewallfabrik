#!/bin/bash
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
#
# Hand every generated nftables ruleset to a real kernel.
#
# This is not what check-nft.sh does.  "nft --check" parses and evaluates
# and then stops, so everything the *kernel* decides is invisible to it:
# whether a statement is allowed in the hook the chain is registered for,
# and whether the jumps between the chains form a cycle.  The second one
# costs the whole ruleset - nft loads atomically - and it is exactly the
# kind of finding no other oracle here can produce, because the shell
# parses such a script perfectly and iptables installs most of it.
#
# The load happens in an unprivileged private network namespace, so
# nothing touches the machine's own firewall and the ruleset is gone when
# the namespace is.
#
# Usage: load-nft.sh <output-directory>

set -u
OUT=${1:?usage: load-nft.sh <output-directory>}

command -v nft >/dev/null 2>&1 || { echo "nft not installed" >&2; exit 2; }
command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    rules=$(mktemp)
    # The ruleset is the heredoc the script pipes into nft.
    awk "/<<.?NFT_RULES.?\$/{flag=1;next}/^NFT_RULES\$/{flag=0}flag" "$script" >"$rules"
    if [ ! -s "$rules" ]; then
        rm -f "$rules"
        continue
    fi
    total=$((total + 1))
    # A fixture may name a host that does not resolve here; that is a
    # property of the corpus, not of the compiler.
    err=$(unshare -rn nft --file "$rules" 2>&1 |
        grep -v 'Name or service not known')
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$rules"
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total rulesets loaded, $failed rejected by the kernel"
[ "$failed" -eq 0 ]
