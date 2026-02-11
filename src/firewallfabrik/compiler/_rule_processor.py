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

"""Rule processor pipeline base classes.

Implements the pull-based chain pattern:
- Each processor has a tmp_queue and a prev_processor reference.
- get_next_rule() calls process_next() until tmp_queue is non-empty.
- slurp() consumes entire upstream pipeline into tmp_queue at once.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from firewallfabrik.compiler._comp_rule import CompRule
    from firewallfabrik.compiler._compiler import Compiler


class BasicRuleProcessor:
    """Base class for all rule processors in the compilation pipeline."""

    def __init__(self, name: str = '') -> None:
        self.compiler: Compiler | None = None
        self.prev_processor: BasicRuleProcessor | None = None
        self.tmp_queue: deque[CompRule] = deque()
        self.name: str = name
        self._do_once: bool = False

    def set_context(self, compiler: Compiler) -> None:
        """Set the compiler context for this processor."""
        self.compiler = compiler

    def set_data_source(self, src: BasicRuleProcessor) -> None:
        """Link this processor to its upstream data source."""
        self.prev_processor = src

    def get_next_rule(self) -> CompRule | None:
        """Pull-based: keep calling process_next() until queue has data."""
        while not self.tmp_queue and self.process_next():
            pass
        if self.tmp_queue:
            return self.tmp_queue.popleft()
        return None

    def process_next(self) -> bool:
        """Process next rule(s). Must be overridden by subclasses.

        Returns True if more rules may be available, False when done.
        Implementation should put processed rules into self.tmp_queue.
        """
        raise NotImplementedError

    def slurp(self) -> bool:
        """Consume ALL upstream rules into tmp_queue at once.

        Used by processors that need the entire rule set before
        processing (e.g. shadowing detection, global reordering).
        Only executes once (idempotent).
        """
        if not self._do_once:
            assert self.prev_processor is not None
            rule = self.prev_processor.get_next_rule()
            while rule is not None:
                self.tmp_queue.append(rule)
                rule = self.prev_processor.get_next_rule()
            self._do_once = True
            return len(self.tmp_queue) > 0
        return False


class Debug(BasicRuleProcessor):
    """Generic rule debugger.

    Prints the name of the previous processor, then for each rule
    matching compiler.debug_rule calls compiler.debug_print_rule().
    Uses slurp() to buffer all upstream rules.

    Automatically inserted after every processor by Compiler.add()
    when rule_debug_on is True (except after SimplePrintProgress).
    """

    def process_next(self) -> bool:
        assert self.compiler is not None
        assert self.prev_processor is not None

        self.slurp()
        if not self.tmp_queue:
            return False

        if self.compiler.rule_debug_on:
            n = self.prev_processor.name
            pad = '-' * max(1, 74 - len(n))
            self.compiler.info(f'\n--- {n} {pad}')
            for rule in self.tmp_queue:
                if rule.position == self.compiler.debug_rule:
                    self.compiler.info(self.compiler.debug_print_rule(rule))
                    self.compiler.info('')

        return True


class PolicyRuleProcessor(BasicRuleProcessor):
    """Convenience base for processors that handle PolicyRule CompRules."""

    def get_next(self) -> CompRule | None:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return None
        if rule.type == 'PolicyRule':
            return rule
        return None


class NATRuleProcessor(BasicRuleProcessor):
    """Convenience base for processors that handle NATRule CompRules."""

    def get_next(self) -> CompRule | None:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return None
        if rule.type == 'NATRule':
            return rule
        return None


class RoutingRuleProcessor(BasicRuleProcessor):
    """Convenience base for processors that handle RoutingRule CompRules."""

    def get_next(self) -> CompRule | None:
        assert self.prev_processor is not None
        rule = self.prev_processor.get_next_rule()
        if rule is None:
            return None
        if rule.type == 'RoutingRule':
            return rule
        return None
