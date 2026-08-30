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
# Fill every named set of a generated nftables ruleset in a real kernel.
#
# Three kinds of object cannot be resolved while the policy is compiled -
# an address table, a run-time DNS name and a dynamic interface - so the
# nftables ruleset matches against an empty named set and the script fills
# it after the load, with `nft add element`.  Nothing else here ever runs
# that shell code: check-nft.sh and load-nft.sh take the ruleset out of the
# heredoc and leave the script behind, and a set that stays empty is a set
# no packet is in, which turns a Deny rule into one that blocks nothing
# and an Accept rule into one that lets nothing through.
#
# Everything runs in an unprivileged private network and mount namespace:
# a dummy interface per device the script names, a hosts file of our own
# for the names it resolves, then the ruleset and the loaders.
#
# Two things it has to get right or every ruleset reads as broken.  The
# namespace has no route to a resolver, so a name has to come out of
# /etc/hosts, which needs the mount namespace; and glibc's AI_ADDRCONFIG
# makes `getent ahostsv4` answer nothing at all unless some interface
# carries an address of that family, which is why a dummy is configured
# before anything is asked.
#
# Usage: fill-nft-sets.sh <output-directory> [data-directory]

set -u
OUT=$(cd "${1:?usage: fill-nft-sets.sh <output-directory> [data-directory]}" && pwd)
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# An address table names its file relative to the data file.
DATA=$(cd "${2:-${FWF_AUDIT_DATA_DIR:-$REPO_ROOT/tests/fixtures}}" && pwd)

command -v nft >/dev/null 2>&1 || { echo "nft not installed" >&2; exit 2; }
command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    grep -q '^load_address_tables() {' "$script" || continue
    rules=$(mktemp)
    awk "/<<.?NFT_RULES.?\$/{flag=1;next}/^NFT_RULES\$/{flag=0}flag" "$script" >"$rules"
    [ -s "$rules" ] || { rm -f "$rules"; continue; }
    total=$((total + 1))

    funcs=$(mktemp)
    awk '/^(load_address_table|load_dns_name|load_interface_address|load_address_tables)\(\) \{/{f=1}
         f{print}
         f&&/^\}$/{f=0}' "$script" >"$funcs"

    # Every device a loader names, with the glob part cut off.
    devices=$(grep -oE 'load_interface_address "[^"]*" "[^"]*" "[^"]*" "[^"]*"' "$script" |
        sed -E 's/.*" "([^"]*)"$/\1/' | sed 's/[*+].*//' | grep -v '^$' | sort -u)

    # Every name a load_dns_name call resolves, with two addresses per
    # family: the answer with several addresses in it is the case the set
    # exists for, because nft refuses a hostname that has more than one.
    hosts=$(mktemp)
    cat /etc/hosts >"$hosts"
    i=1
    for name in $(grep -oE 'load_dns_name "[^"]*" "[^"]*" "[^"]*" "[^"]*"' "$script" |
        sed -E 's/.*" "([^"]*)"$/\1/' | sort -u); do
        printf '203.0.113.%d %s\n203.0.113.%d %s\n' "$i" "$name" "$((i + 100))" "$name" >>"$hosts"
        printf '2001:db8::%d %s\n2001:db8::%d %s\n' "$i" "$name" "$((i + 100))" "$name" >>"$hosts"
        i=$((i + 1))
    done

    driver=$(mktemp)
    {
        echo "mount --bind '$hosts' /etc/hosts"
        echo 'NFT=nft'
        echo 'IP=ip'
        echo 'ip link set lo up'
        echo 'ip link add fwfprobe type dummy'
        echo 'ip link set fwfprobe up'
        echo 'ip addr add 10.99.0.1/24 dev fwfprobe'
        echo 'ip -6 addr add fd00:99::1/64 dev fwfprobe'
        n=2
        for device in $devices; do
            base=${device%%.*}
            if [ "$base" != "$device" ]; then
                echo "ip link add ${base} type dummy 2>/dev/null"
                echo "ip link set ${base} up 2>/dev/null"
                echo "ip link add link ${base} name ${device} type vlan id ${device##*.} 2>/dev/null"
            else
                echo "ip link add ${device} type dummy 2>/dev/null"
            fi
            echo "ip link set ${device} up"
            echo "ip addr add 10.99.${n}.1/24 dev ${device} 2>/dev/null"
            echo "ip -6 addr add fd00:99:${n}::1/64 dev ${device} 2>/dev/null"
            n=$((n + 1))
        done
        echo "nft --file '$rules' || exit 9"
        cat "$funcs"
        echo 'load_address_tables'
        # A set that stayed empty matches nothing, which is the silent half
        # of this.  A `flags dynamic` set is meant to start empty: the rule
        # that counts in it puts the elements there as it sees them.
        cat <<'PROBE'
nft --stateless list ruleset | awk '
    /^\t*set /   { name = $2; empty = 1; dynamic = 0 }
    /flags .*dynamic/ { dynamic = 1 }
    /elements =/ { empty = 0 }
    /^\t*}$/     { if (name != "" && empty && !dynamic) print "EMPTY SET " name; name = "" }
'
PROBE
    } >"$driver"

    err=$( (cd "$DATA" && unshare -rnm bash "$driver") 2>&1 )
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$rules" "$funcs" "$driver" "$hosts"
done < <(find "$OUT/nft" -name '*.fw' | sort)

echo "---"
echo "$total rulesets with named sets filled, $failed produced output"
[ "$failed" -eq 0 ]
