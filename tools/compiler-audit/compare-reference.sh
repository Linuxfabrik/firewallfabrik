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
# Compare the generated iptables rules against the Firewall Builder output
# checked in beside its regression suite (the ".fw.orig" files).  That output
# came from the known-good C++ compiler and is the definition of correct for
# the fixtures it covers.
#
# Read the two columns separately.  "missing" counts reference rules we do not
# produce and must never grow: a correct fix leaves it alone.  "extra" counts
# rules the reference never emitted, and dropping it is what progress looks
# like.  A single total hides that.
#
# The comparison normalises what carries no meaning: the lock timeout, the
# `2>/dev/null` on a chain creation, the generated chain names, the conntrack
# spelling of the state match, the trailing space inside an iptables-restore
# `echo`, and a few protocol numbers the two compilers write differently.
# Rules wrapped in a run-time loop (address tables, dynamic interfaces) are no
# longer plain command lines and count as missing, so the number is
# pessimistic by design.
#
# Usage: compare-reference.sh <output-directory> [reference-directory] [fixture-name]
#
# The reference directory defaults to $FWF_FWBUILDER_REFERENCE, which should
# point at "fwbuilder5/test/ipt" in a Firewall Builder checkout.  Without a
# fixture name every fixture directory under <output-directory>/ipt is
# searched, so the cluster members - whose scripts are named
# "<cluster>_<member>.fw", the way Firewall Builder names them - are
# compared along with the rest.

set -u
OUT=$(cd "${1:?usage: compare-reference.sh <output-directory> [reference-dir] [fixture]}" && pwd)
REFERENCE=${2:-${FWF_FWBUILDER_REFERENCE:-}}
FIXTURE=${3:-}

if [ -z "$REFERENCE" ] || [ ! -d "$REFERENCE" ]; then
    echo "No reference directory. Pass it as the second argument or set" >&2
    echo "FWF_FWBUILDER_REFERENCE to <fwbuilder>/fwbuilder5/test/ipt." >&2
    exit 2
fi

# Only `script_body()` installs the policy.  Both compilers put every rule
# there and nothing else: the reset helpers, the coexistence jump setup,
# `check_tools` and the block/stop actions exist in every script, differ by
# design, and hold `$IPTABLES` without installing a rule of the policy.
# Counting them added about 2000 to `missing` and 6800 to `extra`, both
# constant, both hiding the number that means something.
normalise() {
    awk '/^[a-zA-Z_][a-zA-Z0-9_]*\(\) *\{/{inb = ($1 == "script_body()")} inb' "$1" |
        grep -E '\$(IPTABLES|IP6TABLES)([^_A-Za-z]|$)|echo "-[AI] ' |
        sed -e 's/-w [0-9]*//' -e 's/-w //' \
            -e 's/ 2>\/dev\/null//' \
            -e 's/C[0-9a-fA-F]\{6,\}\.[0-9]*/CHAIN/g' \
            -e 's/Cid[0-9A-Za-z]*\.[0-9]*/CHAIN/g' \
            -e 's/-m conntrack --ctstate/-m state --state/' \
            -e 's/-p 0 /-p all /' -e 's/-p 51 /-p ah /' -e 's/-p 50 /-p esp /' \
            -e 's/-p 112 /-p vrrp /' \
            -e 's/[[:space:]]\+/ /g' -e 's/ *"$//' -e 's/^ //' -e 's/ $//' | sort
}

# Two reference files are member compiles saved under the bare member
# name: `linux-1.fw.orig` and `linux-2.fw.orig` carry the rules and the
# shared addresses of a cluster, but nothing in them says which one, and
# Firewall Builder writes a member compile as `<cluster>_<member>.fw`
# everywhere else.  The generated tree has a standalone compile of that
# member under the same name, so matching the two compares a firewall
# against a cluster and adds 262 to `missing` for nothing.
skip_reference() {
    case "$1" in
        linux-1 | linux-2) return 0 ;;
        *) return 1 ;;
    esac
}

compared=0
reference_rules=0
missing_total=0
extra_total=0
for ref in "$REFERENCE"/*.fw.orig; do
    [ -e "$ref" ] || continue
    name=$(basename "$ref" .fw.orig)
    if [ -z "$FIXTURE" ] && skip_reference "$name"; then
        continue
    fi
    if [ -n "$FIXTURE" ]; then
        ours="$OUT/ipt/$FIXTURE/$name.fw"
    else
        ours=$(find "$OUT/ipt" -mindepth 2 -maxdepth 2 -name "$name.fw" | head -1)
    fi
    [ -n "$ours" ] && [ -f "$ours" ] || continue
    compared=$((compared + 1))
    n=$(normalise "$ref" | wc -l)
    missing=$(diff <(normalise "$ref") <(normalise "$ours") | grep -c '^<')
    extra=$(diff <(normalise "$ref") <(normalise "$ours") | grep -c '^>')
    reference_rules=$((reference_rules + n))
    missing_total=$((missing_total + missing))
    extra_total=$((extra_total + extra))
    [ "$missing" -gt 0 ] || [ "$extra" -gt 0 ] &&
        printf '  %-40s missing %-5s extra %s\n' "$name" "$missing" "$extra"
done

if [ "$compared" -eq 0 ]; then
    echo "No generated script matched a reference file." >&2
    exit 2
fi

echo "---"
echo "firewalls compared      : $compared"
echo "reference rules         : $reference_rules"
echo "reproduced              : $((reference_rules - missing_total))"
echo "missing (must not grow) : $missing_total"
echo "extra                   : $extra_total"
