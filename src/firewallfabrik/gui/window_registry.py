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

"""Singleton registry tracking all open FWWindow instances.

Mirrors fwbuilder's global window list used by ``FWWindow::alreadyOpened()``
and the Window menu's open-files section.
"""

import contextlib
from pathlib import Path

from firewallfabrik.gui.clipboard_store import ClipboardStore


class WindowRegistry:
    """Singleton that tracks every open :class:`FWWindow`.

    Usage::

        registry = WindowRegistry.instance()
        registry.register(window)
        registry.unregister(window)
    """

    _instance: 'WindowRegistry | None' = None

    @classmethod
    def instance(cls) -> 'WindowRegistry':
        """Return the singleton instance, creating it on first call."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._windows: list = []
        self.shared_clipboard = ClipboardStore()

    def register(self, window):
        """Add *window* to the registry."""
        if window not in self._windows:
            self._windows.append(window)

    def unregister(self, window):
        """Remove *window* from the registry."""
        with contextlib.suppress(ValueError):
            self._windows.remove(window)

    def all_windows(self) -> list:
        """Return a list of all registered FWWindow instances."""
        return list(self._windows)

    def already_opened(self, file_path: Path):
        """Return the FWWindow that has *file_path* loaded, or *None*.

        Mirrors fwbuilder's ``FWWindow::alreadyOpened()``.
        Compares resolved paths so that symlinks and relative paths match.
        """
        resolved = file_path.resolve()
        for win in self._windows:
            display = getattr(win, '_display_file', None)
            current = getattr(win, '_current_file', None)
            for candidate in (display, current):
                if candidate is not None and candidate.resolve() == resolved:
                    return win
        return None

    def window_count(self) -> int:
        """Return the number of open windows."""
        return len(self._windows)
