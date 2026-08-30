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
# Run the "block" and "stop" actions of every generated nftables script
# against a real kernel.
#
# Neither has ever been executed by an oracle here: `check-nft.sh` and
# `load-nft.sh` take the ruleset out of the heredoc and leave the script
# behind, so everything the script does *around* the load is untested -
# and these two are exactly the code paths an administrator reaches when
# something has already gone wrong.  `block_action` has to leave the
# machine with every hook at DROP, and it has to do that in the `inet`
# family, or one address family stays open.  `stop_action` has to leave
# nothing hooked at all.  The iptables half of this was covered in
# 2026-08-30 by running `replay-iptables.sh` against `block_action`.
#
# Everything runs in an unprivileged private network namespace, so
# nothing touches the machine's own firewall.
#
# Usage: replay-nft-actions.sh <output-directory>

set -u
OUT=${1:?usage: replay-nft-actions.sh <output-directory>}

command -v nft >/dev/null 2>&1 || { echo "nft not installed" >&2; exit 2; }
command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    grep -q '^block_action()' "$script" || continue
    total=$((total + 1))
    driver=$(mktemp)
    {
        # Everything above the case statement: the constants and the
        # shell functions, without running any of them.
        sed -e '/^# See how we were called/,$d' "$script"
        # The script looks its tools up in check_tools, which needs paths
        # this machine does not have to share.
        echo 'NFT=nft'
        echo 'check_tools() { :; }'
        echo 'log() { :; }'
        echo 'block_action'
        # A ruleset the kernel took but cannot list is a ruleset nothing
        # else here would notice.
        echo 'nft list ruleset >/dev/null'
        echo 'stop_action'
    } >"$driver"
    err=$(unshare -rn bash "$driver" 2>&1)
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$driver"
done < <(find "$OUT" -path '*/nft/*' -name '*.fw' | sort)

echo "---"
echo "$total scripts ran block_action and stop_action, $failed produced output"
[ "$failed" -eq 0 ]
