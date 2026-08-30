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
# Hand every generated nftables ruleset to a real kernel.
#
# This is not what check-nft.sh does.  "nft --check" parses and evaluates
# and then stops, so everything the *kernel* decides is invisible to it:
# whether a statement is allowed in the hook the chain is registered for,
# and whether the jumps between the chains form a cycle.  The second one
# costs the whole ruleset - nft loads atomically - and it is exactly the
# kind of finding no other oracle here can produce, because the shell
# parses such a script perfectly and iptables installs most of it.
#
# The load happens in an unprivileged private network namespace, so
# nothing touches the machine's own firewall and the ruleset is gone when
# the namespace is.
#
# Usage: load-nft.sh <output-directory>

set -u
OUT=${1:?usage: load-nft.sh <output-directory>}

command -v nft >/dev/null 2>&1 || { echo "nft not installed" >&2; exit 2; }
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
    rules=$(mktemp)
    # The ruleset is the heredoc the script pipes into nft.
    awk "/<<.?NFT_RULES.?\$/{flag=1;next}/^NFT_RULES\$/{flag=0}flag" "$script" >"$rules"
    if [ ! -s "$rules" ]; then
        rm -f "$rules"
        continue
    fi
    total=$((total + 1))
    # A fixture may name a host that does not resolve here; that is a
    # property of the corpus, not of the compiler.
    passwd_file=$(mktemp)
    group_file=$(mktemp)
    make_user_db "$rules" "$passwd_file" "$group_file"
    err=$(unshare -rnm bash -c "mount --bind '$passwd_file' /etc/passwd
        mount --bind '$group_file' /etc/group
        nft --file '$rules'" 2>&1 |
        grep -v 'Name or service not known')
    rm -f "$passwd_file" "$group_file"
    if [ -n "$err" ]; then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
    rm -f "$rules"
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total rulesets loaded, $failed rejected by the kernel"
[ "$failed" -eq 0 ]
