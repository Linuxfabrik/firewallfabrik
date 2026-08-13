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

import contextlib
import re
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
        # Every (rule label, message) this compiler has already recorded.
        # A message is a statement about the rule the administrator wrote,
        # and one such rule reaches the printer as several: the service
        # split gives an ICMP and a TCP half a rule each, the negation
        # expansion builds three, the chain decisions split on top of that.
        # Recording the same sentence once per copy says nothing further
        # and buries the rest of the report.  This is per compiler, so the
        # iptables filter and mangle passes still report separately, the
        # way the Firewall Builder output does.
        self._reported: set[tuple[str, str]] = set()
        self._aborted: bool = False
        self._muted: int = 0

    @contextlib.contextmanager
    def muted(self):
        """Record nothing while the block runs.

        A processor that renders a rule only to look at the result - the
        dedup pass builds every command a second time to compare it - would
        otherwise record every message of that rule twice and set the
        compiler status on a rule it is about to drop.  Nesting is counted,
        so an inner block does not unmute the outer one.
        """
        self._muted += 1
        try:
            yield
        finally:
            self._muted -= 1

    @property
    def status(self) -> CompilerStatus:
        return self._status

    @property
    def muted_now(self) -> bool:
        """Whether messages are being discarded right now.

        A check that reports a problem only once has to ask: marking the
        subject as reported inside a muted block would swallow the message
        for good.
        """
        return self._muted > 0

    @staticmethod
    def _format_rule_id(rule) -> str:
        """Format rule identifier using the compiler label, else the position.

        The compiler prolog builds the label as ``[<rule set> ]N (<where>)``
        -- "3 (global)" in the top rule set, "mail_in 3 (eth0)" in a branch.
        A rule that carries a name from the data file instead keeps that
        name, and "color2" says nothing about which rule failed, so such a
        label is replaced by the position.

        The rule set part has to survive: every rule set numbers its rules
        from 0, so "Rule 0" in a firewall with a branch names three
        different rules at once, and the reader has no way to tell which.
        """
        pos = getattr(rule, 'position', None)
        label = getattr(rule, 'label', '') or ''
        if pos is not None:
            built_by_the_prolog = re.search(rf'(?:^|\s){pos} \(', label)
            return label if built_by_the_prolog else str(pos)
        return label or '?'

    def error(self, rule_or_msg, msg: str | None = None) -> None:
        """Record an error, optionally associated with a rule."""
        if self._muted:
            return
        if msg is None:
            self._errors.append(str(rule_or_msg))
        else:
            label = getattr(rule_or_msg, 'label', '')
            rid = self._format_rule_id(rule_or_msg)
            text = f'Rule {rid}: {msg}'
            if self._already_reported(label, text):
                return
            self._errors.append(text)
            if label:
                self._rule_errors.setdefault(label, []).append(text)
        self._status = CompilerStatus.FWCOMPILER_ERROR

    def warning(self, rule_or_msg, msg: str | None = None) -> None:
        """Record a warning, optionally associated with a rule."""
        if self._muted:
            return
        if msg is None:
            self._warnings.append(str(rule_or_msg))
        else:
            label = getattr(rule_or_msg, 'label', '')
            rid = self._format_rule_id(rule_or_msg)
            text = f'Rule {rid}: {msg}'
            if self._already_reported(label, text):
                return
            self._warnings.append(text)
            if label:
                self._rule_errors.setdefault(label, []).append(text)
        if self._status == CompilerStatus.FWCOMPILER_SUCCESS:
            self._status = CompilerStatus.FWCOMPILER_WARNING

    def _already_reported(self, label: str, text: str) -> bool:
        """Whether this exact sentence has been said about this rule before.

        The status is deliberately left alone by the caller when this
        answers true: it was set by the first occurrence, and a repeat of
        the same message says nothing that would change it.
        """
        key = (label, text)
        if key in self._reported:
            return True
        self._reported.add(key)
        return False

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
