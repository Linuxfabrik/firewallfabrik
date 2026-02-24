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

"""Shared clipboard for object references between tree and policy view."""


class ClipboardStore:
    """Single clipboard shared between the object tree and policy views.

    Replaces the former static ``PolicyView._object_clipboard`` class
    variable and the ``TreeActionHandler._tree_clipboard`` instance
    variable with one injectable object that both components receive.

    When used across multiple windows, the ``source_db_manager`` parameter
    on :meth:`set_object` and :meth:`set_tree` records which database the
    copied objects came from so that paste handlers can detect cross-file
    operations.
    """

    def __init__(self):
        self._object: dict | None = None
        self._object_source_db = None
        self._tree: list[dict] | None = None
        self._tree_source_db = None

    # --- Object clipboard (single-item, used for rule cell paste) ---

    @property
    def object_entry(self) -> dict | None:
        """Return the current object clipboard entry or *None*."""
        return self._object

    @property
    def object_source_db(self):
        """Return the DatabaseManager the object was copied from, or *None*."""
        return self._object_source_db

    def set_object(
        self, obj_id: str, name: str, obj_type: str, *, source_db_manager=None
    ):
        """Store a single object reference for rule cell paste."""
        self._object = {'id': obj_id, 'name': name, 'type': obj_type}
        self._object_source_db = source_db_manager

    # --- Tree clipboard (multi-item, used for tree paste) ---

    @property
    def tree_entries(self) -> list[dict] | None:
        """Return the current tree clipboard entries or *None*."""
        return self._tree

    @property
    def tree_source_db(self):
        """Return the DatabaseManager the tree entries were copied from, or *None*."""
        return self._tree_source_db

    def set_tree(self, entries: list[dict], *, source_db_manager=None):
        """Store a list of object references for tree paste."""
        self._tree = entries
        self._tree_source_db = source_db_manager

    def clear_tree(self):
        """Clear the tree clipboard (e.g. after a cut-paste)."""
        self._tree = None
        self._tree_source_db = None
