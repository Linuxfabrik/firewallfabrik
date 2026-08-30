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
# Activate every generated script twice and compare the two rulesets.  A
# firewall is activated again and again over its life - on every boot, on
# every change, on every `reload` - so the second run has to leave the
# machine in the same state as the first.  A rule that survives the reset
# and is appended again grows the ruleset by one on every activation, and
# nothing else in the audit can see it: every other check reads one run.
#
# The start branch is taken out of the script rather than rebuilt here, for
# the reason replay-status.sh gives.
#
# Only lines that install something are compared.  An empty chain
# declaration is not a rule, and the iptables-nft backend creates and
# removes empty tables on its own, which otherwise reads as a difference on
# every coexistence-mode script.
#
# Two firewalls of the reference corpus differ for a reason that is not the
# compiler's: firewall33 and firewall33-1 name a DNS name that answers with
# its addresses in a different order each time.
#
# Usage: replay-twice.sh <output-directory> [name-filter]

set -u
OUT=$(cd "${1:?usage: replay-twice.sh <output-directory> [name-filter]}" && pwd)
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
set_kernel_variables() { :; }

snapshot() {
    { \$IPTABLES -S; \$IP6TABLES -S; \$IPTABLES -t nat -S; \$IPTABLES -t mangle -S; } \
        2>/dev/null | grep -E '^-A '
    \$NFT list ruleset 2>/dev/null |
        grep -vE '^(table|\\s*(chain|set|counter|map|elements|type|policy|flags|})|})' |
        grep -vE '^\\s*\$'
}

{ $start ; } >/dev/null 2>&1
snapshot >"\$TMPDIR_RUN/first"
{ $start ; } >/dev/null 2>&1
snapshot >"\$TMPDIR_RUN/second"
diff "\$TMPDIR_RUN/first" "\$TMPDIR_RUN/second" | head -12
EOF
    run_dir=$(mktemp -d)
    out=$(TMPDIR_RUN="$run_dir" unshare -rn bash "$driver" 2>/dev/null)
    rm -rf "$run_dir" "$driver"
    if [ -n "$out" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$out"
        failed=$((failed + 1))
    fi
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts activated twice, $failed differ on the second run"
