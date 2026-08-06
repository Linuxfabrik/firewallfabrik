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
# Run every generated nftables ruleset through the real nft parser and
# evaluator.  nft loads a ruleset atomically, so a single rule it rejects
# means the firewall keeps the rules it already had - this check finds that
# before a customer does.
#
# Plain "nft --check" fails in a normal shell with "cache initialization
# failed: Operation not permitted" because it cannot open a netlink socket.
# "unshare -rn" gives an unprivileged private network namespace where the
# calling user is root and holds CAP_NET_ADMIN, so parsing and evaluation
# both run.
#
# Usage: check-nft.sh <output-directory>

set -u
OUT=${1:?usage: check-nft.sh <output-directory>}

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
    err=$(unshare -rn nft --check --file "$rules" 2>&1 |
        grep -v 'Name or service not known')
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$rules"
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total rulesets checked, $failed rejected by nft"
[ "$failed" -eq 0 ]
