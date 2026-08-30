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
# Run every generated iptables script against the real iptables in a private
# network namespace.  Anything the tool or the kernel rejects here would have
# failed on the firewall, where the activation stops at that command and the
# rules behind it are never installed.
#
# The whole script is sourced so the rules run in their original order, with
# the chain creation and the run-time loops around them.  Only the helpers
# that need real interfaces are replaced; picking the tool commands out with
# grep instead loses the "-N" ordering and drowns the output in "Chain does
# not exist".
#
# Usage: replay-iptables.sh <output-directory> [name-filter]

set -u
OUT=$(cd "${1:?usage: replay-iptables.sh <output-directory> [name-filter]}" && pwd)
FILTER=${2:-}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# An address table names its file relative to the data file.
DATA_DIR=${FWF_AUDIT_DATA_DIR:-$REPO_ROOT/tests/fixtures}

command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }

# Every user and group a `meta skuid` / `meta skgid` names has to exist
# where nft reads the ruleset: it looks the name up with `getpwnam` while
# it parses the rule and refuses the whole ruleset when the answer is no
# (netfilter nftables src/meta.c, `uid_type_parse`).  The firewall those
# rules are for has the user; this machine has no reason to, and without
# this the check would report the ruleset for a property of the host it
# runs on.  A passwd file of its own, bound over /etc/passwd for the
# length of the run, asks the question the check is actually about.
make_user_db() {
    local rules=$1 passwd_file=$2 group_file=$3
    local id=60000 name
    cp /etc/passwd "$passwd_file"
    cp /etc/group "$group_file"
    for name in $(grep -oE 'meta skuid (!= )?[A-Za-z_][A-Za-z0-9._-]*' "$rules" |
        awk '{print $NF}' | sort -u); do
        grep -q "^$name:" "$passwd_file" && continue
        echo "$name:x:$id:$id::/nonexistent:/usr/sbin/nologin" >>"$passwd_file"
        id=$((id + 1))
    done
    for name in $(grep -oE 'meta skgid (!= )?[A-Za-z_][A-Za-z0-9._-]*' "$rules" |
        awk '{print $NF}' | sort -u); do
        grep -q "^$name:" "$group_file" && continue
        echo "$name:x:$id:" >>"$group_file"
        id=$((id + 1))
    done
}

failed=0
total=0
while IFS= read -r script; do
    [ -n "$FILTER" ] && [[ "$script" != *"$FILTER"* ]] && continue
    total=$((total + 1))
    driver=$(mktemp)
    cat >"$driver" <<EOF
cd $DATA_DIR || exit 1
# Everything above the command dispatch: the definitions, not the run.
eval "\$(sed -e '/^# See how we were called/,\$d' "$script")"

# A firewall may configure its own path to the tools, and that path does not
# exist on this machine: every command then fails with "No such file or
# directory" and the rules are never tested at all.  One firewall of the
# reference corpus hid 393 commands that way, two of which were real
# findings.  The script's own variables are overwritten after it has been
# read, so the rules are handed to the iptables that is installed here.
IPTABLES=\$(command -v iptables)
IP6TABLES=\$(command -v ip6tables)
IPTABLES_RESTORE=\$(command -v iptables-restore)
IP6TABLES_RESTORE=\$(command -v ip6tables-restore)
IP=\$(command -v ip)

# A namespace has no real interfaces, and a corpus names ones that do not
# exist here.  Keep the answers plausible so the rules themselves get tested.
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

reset_all >/dev/null 2>&1
# A script that keeps its rules in its own chains creates them outside
# reset_all.
type setup_fwf_jumps_v4 >/dev/null 2>&1 && setup_fwf_jumps_v4 fwf >/dev/null 2>&1
type setup_fwf_jumps_v6 >/dev/null 2>&1 && setup_fwf_jumps_v6 fwf >/dev/null 2>&1
script_body
EOF
    # An nftables script reaches this loop too - the rules of both
    # platforms are in `script_body` - and its ruleset may name a user
    # this machine has not got.
    passwd_file=$(mktemp)
    group_file=$(mktemp)
    make_user_db "$script" "$passwd_file" "$group_file"
    err=$(unshare -rnm bash -c "mount --bind '$passwd_file' /etc/passwd
        mount --bind '$group_file' /etc/group
        bash '$driver'" 2>&1 >/dev/null | grep -vE '^[[:space:]]*$')
    rm -f "$passwd_file" "$group_file"
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$driver"
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts replayed, $failed produced output on stderr"
echo "Not every line is a compiler bug: a corpus may pin an iptables release"
echo "that current iptables no longer speaks, name a module this kernel does"
echo "not have, or use a uid that 'unshare -r' does not map."
[ "$failed" -eq 0 ]
