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
# Check the iptables-restore form of the generated scripts.  A firewall with
# "Use iptables-restore" writes its rules as echo lines inside a subshell
# piped into iptables-restore, which the plain replay does not exercise.
# Restore is atomic like nft: one rejected line and the whole table is
# refused, so the firewall keeps what it had.
#
# The block is executed with bash to expand the echo lines, then fed to
# "iptables-restore --test", which parses and checks without installing.
#
# Usage: check-iptables-restore.sh <output-directory>

set -u
OUT=$(cd "${1:?usage: check-iptables-restore.sh <output-directory>}" && pwd)
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DATA_DIR=${FWF_AUDIT_DATA_DIR:-$REPO_ROOT/tests/fixtures}

command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    grep -q 'IPTABLES_RESTORE' "$script" || continue
    for tool in IPTABLES_RESTORE IP6TABLES_RESTORE; do
        block=$(mktemp)
        awk -v tool="$tool" '
            $0 ~ "^[[:space:]]*\\($" {inblk=1; buf=""; next}
            inblk && index($0, ") | $" tool) {print buf; inblk=0; next}
            inblk {buf = buf $0 "\n"}
        ' "$script" >"$block"
        if [ ! -s "$block" ]; then
            rm -f "$block"
            continue
        fi
        total=$((total + 1))

        # Seed the address lists the block reads back, then stub the helpers.
        prelude=$(mktemp)
        grep -oE '^[[:space:]]*get(addr|net)6? [a-zA-Z0-9._*+-]+[[:space:]]+[a-zA-Z0-9_]+' "$script" |
            awk '{print $3}' | sort -u |
            while IFS= read -r var; do
                case "$var" in
                *v6*) echo "${var}_list='2001:db8::1'" ;;
                *network*) echo "${var}_list='192.0.2.0/24'" ;;
                *) echo "${var}_list='192.0.2.1'" ;;
                esac
            done >"$prelude"
        cat >>"$prelude" <<EOF
getinterfaces() { echo "\${1%[*+]}0"; }
getInterfaceVarName() { echo "\$1" | sed 's/[.*+]/_/g'; }
getaddr()  { eval "\${2}_list='192.0.2.9'"; }
getaddr6() { eval "\${2}_list='2001:db8::9'"; }
cd $DATA_DIR || exit 1
EOF

        rules=$(mktemp)
        bash -c "source $prelude; source $block" 2>/dev/null | grep -v '^#' >"$rules"
        if [ ! -s "$rules" ]; then
            rm -f "$block" "$prelude" "$rules"
            continue
        fi

        bin=iptables-restore
        [ "$tool" = IP6TABLES_RESTORE ] && bin=ip6tables-restore
        err=$(unshare -rn "$bin" --test <"$rules" 2>&1)
        if [ -n "$err" ]; then
            echo "=== ${script#"$OUT"/} ($bin)"
            echo "$err"
            failed=$((failed + 1))
        fi
        rm -f "$block" "$prelude" "$rules"
    done
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total restore blocks checked, $failed rejected"
[ "$failed" -eq 0 ]
