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
# Fill the ipsets of an iptables script the way its own `start` branch does,
# then install its rules, and ask whether the sets the rules name are there.
#
# `replay-iptables.sh` sources the script and calls `script_body` alone, so
# the block that creates the ipsets never runs and every `-m set` rule is
# refused with "Set <name> doesn't exist" - noise that hides the question
# this asks: does the set exist by the time the rule that names it is
# installed?  It is an ordering question, and an ipset does not survive a
# reboot, so getting it wrong costs every rule about an address table on
# the first activation after one while the script reports success.
#
# The nftables half of the same question is `fill-nft-sets.sh`.
#
# Usage: replay-address-tables.sh <output-directory> [name-filter]

set -u
OUT=$(cd "${1:?usage: replay-address-tables.sh <output-directory> [name-filter]}" && pwd)
FILTER=${2:-}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# An address table names its data file relative to the data file it is in.
DATA_DIR=${FWF_AUDIT_DATA_DIR:-$REPO_ROOT/tests/fixtures}

command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }
command -v ipset >/dev/null 2>&1 || { echo "ipset not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    [ -n "$FILTER" ] && [[ "$script" != *"$FILTER"* ]] && continue
    # Only a script that loads a run-time address table has anything to ask.
    grep -q '^ *reload_address_table "' "$script" || continue
    total=$((total + 1))

    # The names the script fills, so the run can be asked about each one.
    names=$(grep -oE '^ *reload_address_table "[^"]+"' "$script" |
        sed -E 's/.*"([^"]+)"/\1/' | sort -u | tr '\n' ' ')

    driver=$(mktemp)
    cat >"$driver" <<EOF
cd $DATA_DIR || exit 1
# Everything above the command dispatch: the definitions, not the run.
eval "\$(sed -e '/^# See how we were called/,\$d' "$script")"

IPTABLES=\$(command -v iptables)
IP6TABLES=\$(command -v ip6tables)
IPSET=\$(command -v ipset)
IP=\$(command -v ip)

getinterfaces() { echo "\${1%[*+]}0"; }
getaddr()  { eval "\${2}_list='192.0.2.9'"; }
getaddr6() { eval "\${2}_list='2001:db8::9'"; }
getnet()   { eval "\${2}_list='192.0.2.0/24'"; }
getnet6()  { eval "\${2}_list='2001:db8::/64'"; }
missing_address() { :; }
verify_interfaces() { :; }
configure_interfaces() { :; }
load_modules() { :; }
check_tools() { :; }

# The order the script's own start branch uses.  A set that is filled after
# the rule naming it is installed is exactly the defect this looks for.
load_run_time_address_table_files >/dev/null 2>&1
reset_all >/dev/null 2>&1
type setup_fwf_jumps_v4 >/dev/null 2>&1 && setup_fwf_jumps_v4 fwf >/dev/null 2>&1
type setup_fwf_jumps_v6 >/dev/null 2>&1 && setup_fwf_jumps_v6 fwf >/dev/null 2>&1
script_body >/dev/null 2>>"\$ERRFILE"

# Every set the script fills has to be there afterwards, with the two
# member sets the rules match through: the name a rule uses is a setlist
# holding <name>:ip and <name>:net, and an ipset -N that fails leaves the
# list empty, which is a set no packet is in.
for name in $names; do
    for s in "\$name" "\$name:ip" "\$name:net"; do
        "\$IPSET" --list "\$s" >/dev/null 2>&1 || echo "set \$s was not created" >>"\$ERRFILE"
    done
    # The name a rule matches through is a setlist; without both member
    # sets in it the list is empty, which is a set no packet is in - a
    # Deny rule against a block list that blocks nobody.
    members=\$("\$IPSET" --list "\$name" 2>/dev/null)
    for s in "\$name:ip" "\$name:net"; do
        echo "\$members" | grep -q "^\$s\$" || echo "set \$s is not in the list \$name" >>"\$ERRFILE"
    done
done
EOF
    errfile=$(mktemp)
    unshare -rn bash -c "ERRFILE='$errfile' bash '$driver'" >/dev/null 2>&1
    # Only what this oracle is about: a rule the tool refused over a set,
    # and a set the loading did not leave behind.  The `--set option
    # deprecated` note iptables prints for the pre-1.4.4 spelling is the
    # release the firewall pins, not a finding.
    err=$(grep -E "Set .* doesn't exist|was not created|match-set|ipset v" "$errfile" |
        grep -v 'option deprecated' | sort -u)
    rm -f "$errfile" "$driver"
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts with a run-time address table replayed, $failed produced a finding"
