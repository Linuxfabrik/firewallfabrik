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
# Run `configure_interfaces` of every generated script against iproute2 and
# read what it leaves behind.  Nothing else in the audit does: the replay
# oracles stub the function out, because they are about rules, and
# `bash -n` parses a block that is syntactically perfect and semantically
# fail-open.  Yet it is the first thing a `start` runs, it runs as root, and
# it can take an address or a whole interface away from the machine.
#
# Three questions per script, and each has found something:
#
#   1. Does it run clean?  Anything the block prints besides its own
#      "# ..." progress lines is a command iproute2 refused - and
#      `update_addresses_of_interface` answers an interface that is not
#      there with `exit 1`, so the script stops before it installs a rule.
#   2. Is it idempotent?  A firewall is activated on every boot and every
#      change, so the second run has to be silent.
#   3. Is the bridge membership what the script asked for?
#
# The devices the script names are created as dummies beforehand.  A VLAN
# and a bonding interface are created that way too: the generated script
# does not build them (see issue #95), and without them every firewall that
# names one stops at the first `exit 1` and the rest of its block is never
# reached.
#
# Usage: replay-interfaces.sh <output-directory> [name-filter]

set -u
OUT=$(cd "${1:?usage: replay-interfaces.sh <output-directory> [name-filter]}" && pwd)
FILTER=${2:-}

command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    [ -n "$FILTER" ] && [[ "$script" != *"$FILTER"* ]] && continue
    total=$((total + 1))
    driver=$(mktemp)
    cat >"$driver" <<EOF
ip link set lo up 2>/dev/null

# Every device the block will touch: the interfaces it configures, the
# ones it looks an address up on, and the ports it puts into a bridge.
devs=\$( { grep -oE 'update_addresses_of_interface "[^ "]+' "$script" | sed 's/.*"//'
          grep -oE '^ *get(addr|addr6|net|net6) +[^ ]+' "$script" | awk '{print \$2}'
          grep -oE '^ *update_bridge +[^ ]+ +"[^"]*"' "$script" |
              sed -e 's/^ *update_bridge  *[^ ]*  *"//' -e 's/"\$//'
        } | tr ' ' '\n' | sort -u )
# Not the bridges: the script builds those itself, and a dummy standing
# where a bridge belongs answers every later command with "Operation not
# supported" - a finding about the harness, not about the script.
bridges=\$(grep -oE '^ *sync_bridge_interfaces +.*' "$script" |
              sed 's/^ *sync_bridge_interfaces  *//' | tr ' ' '\n' | sort -u)
for d in \$devs; do
    case \$d in lo|*'*'|*'+'|'') continue ;; esac
    printf '%s\n' "\$bridges" | grep -qx "\$d" && continue
    ip link add "\$d" type dummy 2>/dev/null && ip link set "\$d" up
done

# Everything above the command dispatch: the definitions, not the run.
eval "\$(sed -e '/^# See how we were called/,\$d' "$script")" 2>/dev/null
IP=\$(command -v ip)

# A firewall that configures none of its interfaces has no such function.
type configure_interfaces >/dev/null 2>&1 || { echo "@@SKIP"; exit 0; }

# In a subshell, because `update_addresses_of_interface` answers a missing
# interface with `exit 1` and that has to be reported rather than end the
# probe.  The commands it did run have already reached the kernel.
echo "@@FIRST"
( configure_interfaces ); echo "@@STATUS \$?"
echo "@@SECOND"
( configure_interfaces ); echo "@@STATUS \$?"
echo "@@BRIDGES"
for br in \$(ip -brief link show type bridge 2>/dev/null | awk '{print \$1}'); do
    echo "\$br: \$(ip link show master "\$br" 2>/dev/null |
        awk -F'[ :]+' '/^[0-9]/ {printf "%s ", \$2}')"
done
EOF
    out=$(unshare -rn bash "$driver" 2>&1)
    rm -f "$driver"
    if [[ "$out" == *"@@SKIP"* ]]; then
        total=$((total - 1))
        continue
    fi

    # A "# ..." line is the block's own progress report and says nothing -
    # except the one that names an interface the machine has not got, which
    # is the line `update_addresses_of_interface` prints before it exits.
    noise='^(@@|#( Adding| Removing| Deleting| Creating| Updating| Configure)|$)'
    first=$(printf '%s\n' "$out" | sed -n '/@@FIRST/,/@@SECOND/p' | grep -vE "$noise")
    second=$(printf '%s\n' "$out" | sed -n '/@@SECOND/,/@@BRIDGES/p' | grep -vE '^(@@|$)')
    bridges=$(printf '%s\n' "$out" | sed -n '/@@BRIDGES/,$p' | grep -vE '^@@')
    statuses=$(printf '%s\n' "$out" | sed -n 's/^@@STATUS //p' | tr '\n' ' ')

    problems=''
    [ -n "$first" ] && problems="the first run says:"$'\n'"$first"
    [ "$statuses" != "0 0 " ] &&
        problems="$problems"$'\n'"configure_interfaces returned [${statuses% }], not [0 0]"
    [ -n "$second" ] &&
        problems="$problems"$'\n'"not idempotent, the second run still says:"$'\n'"$second"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        want=$(grep -oE "^ *update_bridge +${line%%:*} +\"[^\"]*\"" "$script" |
               sed -e 's/^[^"]*"//' -e 's/"$//' | tr ' ' '\n' | sort | tr '\n' ' ')
        have=$(printf '%s' "${line#*: }" | tr ' ' '\n' | sort | tr '\n' ' ')
        [ "$want" != "$have" ] &&
            problems="$problems"$'\n'"bridge ${line%%:*}: asked for [${want% }], has [${have% }]"
    done <<<"$bridges"

    if [ -n "$problems" ]; then
        echo "=== ${script#"$OUT"/}"
        printf '%s\n' "$problems" | sed '/^$/d'
        failed=$((failed + 1))
    fi
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts configured their interfaces, $failed produced a finding"
