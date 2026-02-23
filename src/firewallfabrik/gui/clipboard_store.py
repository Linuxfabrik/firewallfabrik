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
    """

    def __init__(self):
        self._object: dict | None = None
        self._tree: list[dict] | None = None

    # --- Object clipboard (single-item, used for rule cell paste) ---

    @property
    def object_entry(self) -> dict | None:
        """Return the current object clipboard entry or *None*."""
        return self._object

    def set_object(self, obj_id: str, name: str, obj_type: str):
        """Store a single object reference for rule cell paste."""
        self._object = {'id': obj_id, 'name': name, 'type': obj_type}

    # --- Tree clipboard (multi-item, used for tree paste) ---

    @property
    def tree_entries(self) -> list[dict] | None:
        """Return the current tree clipboard entries or *None*."""
        return self._tree

    def set_tree(self, entries: list[dict]):
        """Store a list of object references for tree paste."""
        self._tree = entries

    def clear_tree(self):
        """Clear the tree clipboard (e.g. after a cut-paste)."""
        self._tree = None
