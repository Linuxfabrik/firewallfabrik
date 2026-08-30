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
# Hand every generated "ip route" command to iproute2.
#
# The routing block is the part of the script no other oracle here reads:
# compare-reference.sh counts $IPTABLES lines and a route installs none,
# replay-iptables.sh replaces $IP with a real binary but never runs
# update_routing.  And a failing route command is not a cosmetic problem -
# since the routing rollback landed, the first one that fails puts the
# previous routing table back and stops the activation, so the box ends up
# with the new packet filter and the old routes.
#
# Everything runs in an unprivileged private network namespace: a dummy
# interface per device the script names, the addresses the script
# configures on it, then the commands.  Nothing touches the machine's own
# routing table.
#
# Usage: replay-routes.sh <output-directory>

set -u
OUT=$(cd "${1:?usage: replay-routes.sh <output-directory>}" && pwd)

command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    # Only the routing block, and only the commands in it.  A multi-path
    # route spans several lines with a trailing backslash, so the
    # continuations are joined first - without that the command arrives
    # without its next hops and asks for something else entirely.
    commands=$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ta' -e '}' "$script" |
        grep -oE '\$IP (-6 )?(route|rule) add [^|]*' |
        sed -e 's/[[:space:]]\+/ /g' -e 's/[[:space:]]*$//')
    [ -n "$commands" ] || continue
    total=$((total + 1))

    # Every device a command names, and every address the script gives it.
    devices=$(printf '%s\n' "$commands" |
        grep -oE 'dev [A-Za-z0-9._:+-]+' | awk '{print $2}' | sort -u)
    # The script does not write "ip addr add": it hands the interface and
    # its addresses to update_addresses_of_interface, one line per device.
    addrs=$(grep -oE 'update_addresses_of_interface "[^"]+"' "$script" |
        sed -e 's/update_addresses_of_interface "//' -e 's/"$//' | sort -u)

    driver=$(mktemp)
    {
        echo 'ip link set lo up'
        for dev in $devices; do
            printf 'ip link add %s type dummy 2>/dev/null\n' "$dev"
            printf 'ip link set %s up\n' "$dev"
        done
        printf '%s\n' "$addrs" | while read -r dev rest; do
            [ -n "${rest:-}" ] || continue
            printf 'ip link add %s type dummy 2>/dev/null\n' "$dev"
            printf 'ip link set %s up\n' "$dev"
            for addr in $rest; do
                printf 'ip addr add %s dev %s 2>/dev/null\n' "$addr" "$dev"
            done
        done
        printf '%s\n' "$commands" | sed 's/^\$IP /ip /'
    } >"$driver"

    err=$(unshare -rn bash "$driver" 2>&1 >/dev/null | grep -vE '^[[:space:]]*$')
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$driver"
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts with routes replayed, $failed produced output on stderr"
echo 'Not every line is a compiler bug: "File exists" for a route to a'
echo 'network the script has just configured an address on is what the'
echo 'Firewall Builder reference does too.'
[ "$failed" -eq 0 ]
