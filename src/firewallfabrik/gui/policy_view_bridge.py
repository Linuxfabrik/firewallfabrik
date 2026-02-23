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

"""Typed bridge between PolicyView and the main window.

Eliminates ``self.window()`` + ``hasattr()`` lookups by providing
explicit callable references that :class:`PolicyView` can invoke
directly.  If a method is missing, you get a clear ``TypeError`` at
bridge construction time instead of a silent no-op at runtime.
"""

from collections.abc import Callable


class PolicyViewBridge:
    """Callable references to main-window functionality used by PolicyView."""

    def __init__(
        self,
        *,
        compile_single_rule: Callable,
        open_action_editor: Callable,
        open_comment_editor: Callable,
        open_direction_editor: Callable,
        open_metric_editor: Callable,
        open_object_editor: Callable,
        open_rule_options: Callable,
        reveal_in_tree: Callable,
        show_any_editor: Callable,
        show_where_used: Callable,
    ):
        self.compile_single_rule = compile_single_rule
        self.open_action_editor = open_action_editor
        self.open_comment_editor = open_comment_editor
        self.open_direction_editor = open_direction_editor
        self.open_metric_editor = open_metric_editor
        self.open_object_editor = open_object_editor
        self.open_rule_options = open_rule_options
        self.reveal_in_tree = reveal_in_tree
        self.show_any_editor = show_any_editor
        self.show_where_used = show_where_used
