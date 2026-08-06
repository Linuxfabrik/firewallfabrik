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
# Parse every generated script.  A script the shell refuses does not run at
# all - not one line of it - and the only symptom is a parse error at
# activation time, so this cheap check is worth running first.
#
# Usage: check-shell-syntax.sh <output-directory>

set -u
OUT=${1:?usage: check-shell-syntax.sh <output-directory>}

failed=0
total=0
while IFS= read -r script; do
    total=$((total + 1))
    if ! err=$(bash -n "$script" 2>&1); then
        echo "=== ${script#"$OUT"/}"
        echo "$err"
        failed=$((failed + 1))
    fi
done < <(find "$OUT" -name '*.fw' | sort)

echo "---"
echo "$total scripts parsed, $failed rejected by the shell"
[ "$failed" -eq 0 ]
