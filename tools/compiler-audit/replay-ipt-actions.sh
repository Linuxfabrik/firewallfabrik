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
# Run the "block" and "stop" actions of every generated iptables script
# against real iptables.
#
# `replay-iptables.sh` calls `script_body` and nothing else, so these two
# functions - the ones an administrator reaches once something has
# already gone wrong - have never been executed by a standing oracle on
# this platform; the nftables half has had `replay-nft-actions.sh` since
# 2026-08-31.  Three questions, and each of them has been wrong here:
#
#   * does every command succeed, and does the function answer 0?  A
#     "stop" that did its work and still exits non-zero is a broken
#     service to an init system and to a monitoring check.
#   * does "block" leave the machine shut?  Every built-in policy of
#     every family the script installs rules for has to be DROP.
#   * does either of them touch a family the script has no rules for?
#     A script that never set the IPv6 policies to DROP must not set them
#     to ACCEPT: something else on the machine did, and stopping this
#     firewall would open theirs.  The tool for that family is therefore
#     pointed at a path that does not exist, which is also the ordinary
#     state of a host that carries no ip6tables at all.
#
# Everything runs in an unprivileged private network namespace, so
# nothing touches the machine's own firewall.
#
# Usage: replay-ipt-actions.sh <output-directory>

set -u
OUT=${1:?usage: replay-ipt-actions.sh <output-directory>}

command -v iptables >/dev/null 2>&1 || { echo "iptables not installed" >&2; exit 2; }
command -v unshare >/dev/null 2>&1 || { echo "unshare not installed" >&2; exit 2; }

failed=0
total=0
while IFS= read -r script; do
    grep -q '^block_action()' "$script" || continue
    total=$((total + 1))

    # Which families this script installs a ruleset for, and which of
    # them it owns the built-in policies of.  `reset_all` is what the
    # script itself asks both questions with, so read its answer rather
    # than guessing from the rules: the full-flush helper sets the
    # policies, the coexistence one removes this script's own chains and
    # leaves everything else - including the policies - to whatever else
    # runs on the machine, which is the whole point of that mode.
    reset=$(sed -n '/^reset_all()/,/^}/p' "$script")
    grep -q 'reset_iptables_v6\|reset_fwf_chains_v6' <<<"$reset" && v6=1 || v6=0
    grep -q 'reset_iptables_v4' <<<"$reset" && owns_v4=1 || owns_v4=0
    grep -q 'reset_iptables_v6' <<<"$reset" && owns_v6=1 || owns_v6=0

    driver=$(mktemp)
    {
        # Everything above the case statement: the constants and the
        # shell functions, without running any of them.
        sed -e '/^# See how we were called/,$d' "$script"
        # The script looks its tools up in check_tools, which needs paths
        # this machine does not have to share.
        echo 'IPTABLES=iptables'
        echo 'IPTABLES_RESTORE=iptables-restore'
        if [ "$v6" -eq 1 ]; then
            echo 'IP6TABLES=ip6tables'
            echo 'IP6TABLES_RESTORE=ip6tables-restore'
        else
            # A family this script has no rules for must not be reached.
            echo 'IP6TABLES=/nonexistent/ip6tables'
            echo 'IP6TABLES_RESTORE=/nonexistent/ip6tables-restore'
        fi
        echo 'MODPROBE=modprobe'
        echo 'IP=ip'
        echo 'LOGGER=logger'
        echo 'check_tools() { :; }'
        echo 'log() { :; }'
        echo 'block_action'
        echo 'rc=$?; test "$rc" -eq 0 || echo "block_action answered $rc"'
        [ "$owns_v4" -eq 1 ] && cat <<'EOS'
for chain in INPUT FORWARD OUTPUT; do
    iptables -S "$chain" | head -1 | grep -q " DROP$" \
        || echo "block left the IPv4 $chain policy open"
done
EOS
        [ "$owns_v6" -eq 1 ] && cat <<'EOS'
for chain in INPUT FORWARD OUTPUT; do
    ip6tables -S "$chain" | head -1 | grep -q " DROP$" \
        || echo "block left the IPv6 $chain policy open"
done
EOS
        echo 'stop_action'
        echo 'rc=$?; test "$rc" -eq 0 || echo "stop_action answered $rc"'
        [ "$owns_v4" -eq 1 ] && cat <<'EOS'
for chain in INPUT FORWARD OUTPUT; do
    iptables -S "$chain" | head -1 | grep -q " ACCEPT$" \
        || echo "stop left the IPv4 $chain policy closed"
done
EOS
        [ "$owns_v6" -eq 1 ] && cat <<'EOS'
for chain in INPUT FORWARD OUTPUT; do
    ip6tables -S "$chain" | head -1 | grep -q " ACCEPT$" \
        || echo "stop left the IPv6 $chain policy closed"
done
EOS
        :
    } >"$driver"
    err=$(unshare -rn bash "$driver" 2>&1)
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$driver"
done < <(find "$OUT" -path '*/ipt/*' -name '*.fw' | sort)

echo "---"
echo "$total scripts ran block_action and stop_action, $failed produced output"
[ "$failed" -eq 0 ]
