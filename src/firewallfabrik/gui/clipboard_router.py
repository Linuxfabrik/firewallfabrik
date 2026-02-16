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

from PySide6.QtWidgets import QApplication


class ClipboardRouter:
    """Routes clipboard operations to object tree or policy view based on focus.

    The routing rule mirrors fwbuilder: if the object tree has keyboard
    focus the operation targets tree objects; otherwise it targets the
    active policy (rule-set) view.
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

    def _tree_has_focus(self):
        """Return True if the object tree widget has keyboard focus.

        Specifically checks for the tree widget itself (not the filter
        QLineEdit) so that Ctrl+C in the filter field still copies text.
        """
        focus = QApplication.focusWidget()
        if focus is None:
            return False
        tree_widget = self._object_tree._tree
        return focus is tree_widget or tree_widget.isAncestorOf(focus)

    def copy(self):
        """Route a *copy* operation."""
        if self._tree_has_focus():
            self._object_tree._shortcut_copy()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.copy_object()

    def cut(self):
        """Route a *cut* operation."""
        if self._tree_has_focus():
            self._object_tree._shortcut_cut()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.cut_object()

    def delete(self):
        """Route a *delete* operation."""
        if self._tree_has_focus():
            self._object_tree._shortcut_delete()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.delete_selection()

    def paste(self):
        """Route a *paste* operation."""
        if self._tree_has_focus():
            self._object_tree._shortcut_paste()
            return
        view = self._get_active_policy_view()
        if view is not None:
            view.paste_object()
