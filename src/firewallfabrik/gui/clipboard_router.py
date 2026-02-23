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

"""Clipboard routing based on explicit focus registration.

Instead of querying ``QApplication.focusWidget()`` on every clipboard
operation, the main window connects ``QApplication.focusChanged`` to
:meth:`ClipboardRouter.on_focus_changed` once.  The router then tracks
which logical component owns focus and routes clipboard operations
without additional ``focusWidget()`` calls.
"""

from enum import Enum, auto

import shiboken6
from PySide6.QtWidgets import QApplication, QLineEdit, QTextEdit


class FocusOwner(Enum):
    """Logical component that currently owns keyboard focus."""

    NONE = auto()
    POLICY = auto()
    TEXT = auto()
    TREE = auto()


class ClipboardRouter:
    """Routes clipboard operations to object tree or policy view.

    The routing rule mirrors fwbuilder: if the object tree has keyboard
    focus the operation targets tree objects; otherwise it targets the
    active policy (rule-set) view.  Text-input widgets (QTextEdit,
    QLineEdit, etc.) always get native clipboard handling.
    """

    def __init__(self, object_tree, get_active_policy_view):
        """Initialise the router.

        Args:
            object_tree: :class:`ObjectTree` instance.
            get_active_policy_view: Callable returning the active
                :class:`PolicyView` or *None*.
        """
        self._object_tree = object_tree
        self._get_active_policy_view = get_active_policy_view
        self._focus_owner: FocusOwner = FocusOwner.NONE

    def on_focus_changed(self, _old, new):
        """Update the logical focus owner when Qt focus changes.

        Connect this to ``QApplication.instance().focusChanged``.

        The handler is wrapped in a try/except because Qt may fire
        ``focusChanged`` while widgets are being destroyed (e.g. during
        ``QTreeWidget.clear()``).  Accessing the already-deleted C++
        object via Shiboken raises ``RuntimeError``.
        """
        if new is None or not shiboken6.isValid(new):
            self._focus_owner = FocusOwner.NONE
            return
        if isinstance(new, (QLineEdit, QTextEdit)):
            self._focus_owner = FocusOwner.TEXT
            return
        tree_widget = self._object_tree._tree
        if new is tree_widget or tree_widget.isAncestorOf(new):
            self._focus_owner = FocusOwner.TREE
            return
        self._focus_owner = FocusOwner.POLICY

    def copy(self):
        """Route a *copy* operation."""
        if self._focus_owner == FocusOwner.TEXT:
            widget = QApplication.focusWidget()
            if widget is not None:
                widget.copy()
            return
        if self._focus_owner == FocusOwner.TREE:
            self._object_tree._actions._shortcut_copy()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.copy_object()

    def cut(self):
        """Route a *cut* operation."""
        if self._focus_owner == FocusOwner.TEXT:
            widget = QApplication.focusWidget()
            if widget is not None:
                widget.cut()
            return
        if self._focus_owner == FocusOwner.TREE:
            self._object_tree._actions._shortcut_cut()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.cut_object()

    def delete(self):
        """Route a *delete* operation."""
        if self._focus_owner == FocusOwner.TREE:
            self._object_tree._actions._shortcut_delete()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.delete_selection()

    def paste(self):
        """Route a *paste* operation."""
        if self._focus_owner == FocusOwner.TEXT:
            widget = QApplication.focusWidget()
            if widget is not None:
                widget.paste()
            return
        if self._focus_owner == FocusOwner.TREE:
            self._object_tree._actions._shortcut_paste()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.paste_object()
