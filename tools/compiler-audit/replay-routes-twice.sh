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
# Run the routing block twice and ask whether the second run is the first.
#
# replay-routes.sh hands the "ip route" commands to iproute2 once, in an
# empty namespace.  That is not what an administrator does: a firewall
# script is run again on every change, and the block in front of the route
# commands exists precisely so the second run starts from the table the
# first one found.  A route the block does not know how to delete is still
# there the second time, "ip route add" answers "RTNETLINK answers: File
# exists", and the "|| route_command_error" behind it puts the previous
# table back and stops the script with a non-zero status - the packet
# filter already installed and the epilog never run.  Every activation
# after the first fails that way, and no other oracle here can see it.
#
# The comparison is between the two runs and not against an empty list:
# a route to a network the script has just configured an address on
# answers "File exists" on the first run as well, which is what the
# Firewall Builder reference does too.  Only a line the second run
# produces and the first does not is a finding.
#
# Usage: replay-routes-twice.sh <output-directory>

set -u
OUT=$(cd "${1:?usage: replay-routes-twice.sh <output-directory>}" && pwd)

command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    # The whole block, from the table it saves to the last route command.
    # A multi-path route spans several lines with a trailing backslash, so
    # the continuations are joined first.
    joined=$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ta' -e '}' "$script")
    # Only what stands between the saved table and the first route
    # command: the copy into $OLD_ROUTES and the delete loop in front of
    # the rules.  The same two lines live inside route_command_error as
    # well, where they flush the whole table, so they are taken by their
    # place in the block rather than by their text.
    setup=$(printf '%s\n' "$joined" |
        sed -n '/# store previous routing configuration/,/Activating non-ecmp/p' |
        grep -E '^[[:space:]]*"\$IP" ' |
        sed -e 's/[[:space:]]\+/ /g' -e 's/[[:space:]]*$//')
    # The "|| route_command_error" tail is kept, unlike in
    # replay-routes.sh: it is what the script does about a route it
    # cannot install, and a stub below turns it into a line on stderr.
    commands=$(printf '%s\n' "$joined" |
        grep -oE '\$IP (-6 )?(route|rule) add .*' |
        sed -e 's/[[:space:]]\+/ /g' -e 's/[[:space:]]*$//')
    [ -n "$commands" ] || continue
    total=$((total + 1))

    devices=$(printf '%s\n' "$commands" |
        grep -oE 'dev [A-Za-z0-9._:+-]+' | awk '{print $2}' | sort -u)
    addrs=$(grep -oE 'update_addresses_of_interface "[^"]+"' "$script" |
        sed -e 's/update_addresses_of_interface "//' -e 's/"$//' | sort -u)

    driver=$(mktemp)
    {
        echo 'IP=$(command -v ip)'
        echo 'OLD_ROUTES=$(mktemp)'
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
        # A duplicate address is refused, and the kernel needs a moment
        # for duplicate address detection before an IPv6 route over the
        # device is accepted.
        echo 'sleep 1'
        echo 'route_command_error() { echo "route_command_error $1" >&2 ; }'
        echo 'activate() {'
        printf '%s\n' "$setup"
        printf '%s\n' "$commands"
        echo '}'
        echo 'activate 2>"$OLD_ROUTES.first"'
        echo 'activate 2>"$OLD_ROUTES.second"'
        echo 'comm -13 <(sort -u "$OLD_ROUTES.first") <(sort -u "$OLD_ROUTES.second") >&2'
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
echo "$total scripts with routes activated twice, $failed where the second run said"
echo "something the first did not"
[ "$failed" -eq 0 ]
