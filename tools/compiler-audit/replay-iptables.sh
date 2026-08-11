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
    err=$(unshare -rn bash "$driver" 2>&1 >/dev/null | grep -vE '^[[:space:]]*$')
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
