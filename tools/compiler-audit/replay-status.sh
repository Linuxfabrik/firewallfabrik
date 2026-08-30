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
# Activate every generated script the way its own "start" branch does, then
# ask it "status".  A firewall that answers "not configured" right after it
# installed its rules is read as dead by an init system and by a monitoring
# check, and nothing else in the audit can see it: `status_action` sits
# outside `script_body`, so neither the reference comparison nor the replay
# ever runs it.
#
# The start branch is taken out of the script rather than rebuilt here.
# Calling the helpers by hand instead reports the wrong answer in both
# directions: a full-flush script defines `setup_fwf_jumps_v4` and never
# calls it, and calling it anyway creates the very chains whose absence the
# question is about.
#
# Usage: replay-status.sh <output-directory> [name-filter]

set -u
OUT=$(cd "${1:?usage: replay-status.sh <output-directory> [name-filter]}" && pwd)
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
    start=$(sed -n '/^    start)/,/;;/p' "$script" | sed -e '1d' -e '$d')
    driver=$(mktemp)
    cat >"$driver" <<EOF
cd $DATA_DIR || exit 1
# Everything above the command dispatch: the definitions, not the run.
eval "\$(sed -e '/^# See how we were called/,\$d' "$script")"

# A firewall may configure its own path to the tools, and that path does
# not exist on this machine.  See replay-iptables.sh for what that costs.
IPTABLES=\$(command -v iptables)
IP6TABLES=\$(command -v ip6tables)
IPTABLES_RESTORE=\$(command -v iptables-restore)
IP6TABLES_RESTORE=\$(command -v ip6tables-restore)
NFT=\$(command -v nft)
IP=\$(command -v ip)

# A namespace has no real interfaces, and a corpus names ones that do not
# exist here.  Keep the answers plausible so the rules themselves get
# installed; everything the question is not about is stubbed out.
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
log() { :; }
check_run_time_address_table_files() { :; }
check_module_ipset() { :; }
prolog_commands() { :; }
epilog_commands() { :; }
ip_forward() { :; }
run_epilog_and_exit() { :; }

{
$start
} >/dev/null 2>&1

installed=\$( { \$IPTABLES -S; \$IP6TABLES -S; } 2>/dev/null | grep -cE '^-(A|N) ' )
nft_installed=\$(\$NFT list ruleset 2>/dev/null | grep -cE 'counter|accept|drop|reject')
# status_action ends the shell with "exit 3" when it says no, so it runs in
# a subshell of its own.
answer=\$(status_action 2>&1)
echo "\$((installed + nft_installed))|\$answer"
EOF
    line=$(unshare -rn bash "$driver" 2>/dev/null | tail -1)
    rm -f "$driver"
    installed=${line%%|*}
    answer=${line#*|}
    case "$installed" in '' | *[!0-9]*) installed=0 ;; esac
    if [ "$installed" -gt 0 ] && [ "$answer" != "Firewall is active" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$installed rules installed, status says: ${answer:-<nothing>}"
        failed=$((failed + 1))
    fi
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts activated, $failed report themselves inactive"
[ "$failed" -eq 0 ]
