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

"""BaseCompiler: error/warning tracking for all compilers."""

from __future__ import annotations

import sys
from enum import IntEnum


class CompilerStatus(IntEnum):
    """Compiler exit status codes."""

    FWCOMPILER_SUCCESS = 0
    FWCOMPILER_WARNING = 1
    FWCOMPILER_ERROR = 2


class BaseCompiler:
    """Base class providing error/warning tracking for all compilers."""

    def __init__(self) -> None:
        self._status: CompilerStatus = CompilerStatus.FWCOMPILER_SUCCESS
        self._errors: list[str] = []
        self._warnings: list[str] = []
        self._rule_errors: dict[str, list[str]] = {}
        self._aborted: bool = False

    @property
    def status(self) -> CompilerStatus:
        return self._status

    def error(self, rule_or_msg, msg: str | None = None) -> None:
        """Record an error, optionally associated with a rule."""
        if msg is None:
            self._errors.append(str(rule_or_msg))
        else:
            label = getattr(rule_or_msg, 'label', '')
            text = f'Rule {label}: {msg}' if label else msg
            self._errors.append(text)
            if label:
                self._rule_errors.setdefault(label, []).append(text)
        self._status = CompilerStatus.FWCOMPILER_ERROR

    def warning(self, rule_or_msg, msg: str | None = None) -> None:
        """Record a warning, optionally associated with a rule."""
        if msg is None:
            self._warnings.append(str(rule_or_msg))
        else:
            label = getattr(rule_or_msg, 'label', '')
            text = f'Rule {label}: {msg}' if label else msg
            self._warnings.append(text)
            if label:
                self._rule_errors.setdefault(label, []).append(text)
        if self._status == CompilerStatus.FWCOMPILER_SUCCESS:
            self._status = CompilerStatus.FWCOMPILER_WARNING

    def info(self, msg: str) -> None:
        """Print an informational message to stderr."""
        print(msg, file=sys.stderr)

    def get_errors(self) -> list[str]:
        return list(self._errors)

    def get_warnings(self) -> list[str]:
        return list(self._warnings)

    def get_errors_for_rule(self, rule, comment_sep: str = '# ') -> str:
        """Return errors/warnings for a specific rule, formatted for inline comments."""
        label = getattr(rule, 'label', '') or ''
        msgs = self._rule_errors.get(label, [])
        if not msgs:
            return ''
        seen: set[str] = set()
        lines = []
        for m in sorted(msgs):
            if m not in seen:
                lines.append(f'{comment_sep}{m}')
                seen.add(m)
        return '\n'.join(lines)

    def abort(self, rule_or_msg=None, msg: str | None = None) -> None:
        """Abort compilation, optionally recording an error."""
        self._aborted = True
        if rule_or_msg is not None:
            self.error(rule_or_msg, msg)

    def is_aborted(self) -> bool:
        return self._aborted
