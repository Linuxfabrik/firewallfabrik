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

"""Editor panel dialog for CustomService objects."""

import socket

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog
from firewallfabrik.gui.platform_settings import get_enabled_platforms

_PROTOCOL_CHOICES = ('any', 'icmp', 'ipv6-icmp', 'tcp', 'udp')


class CustomServiceDialog(BaseObjectDialog):
    """Editor for CustomService objects.

    Maintains a per-platform code map so switching the platform combo
    preserves previously entered code strings (matching fwbuilder).
    """

    def __init__(self, parent=None):
        super().__init__('customservicedialog_q.ui', parent)
        self._all_codes = {}
        self._current_platform = ''

        # Populate protocol combo with standard choices.
        for proto in _PROTOCOL_CHOICES:
            self.protocol.addItem(proto)

        self.platform.currentIndexChanged.connect(self._on_platform_changed)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')

        # Build the per-platform code map from the model.
        self._all_codes = dict(self._obj.codes or {})

        # Refresh platform combo with currently enabled platforms.
        self.platform.blockSignals(True)
        self.platform.clear()
        for key, display in sorted(
            get_enabled_platforms().items(), key=lambda t: t[1].casefold()
        ):
            self.platform.addItem(display, key)
        # Default to nftables if enabled, otherwise first entry.
        idx = self.platform.findData('nftables')
        if idx >= 0:
            self.platform.setCurrentIndex(idx)
        self.platform.blockSignals(False)

        self._current_platform = self.platform.currentData() or ''
        self.code.setText(self._all_codes.get(self._current_platform, ''))

        # Protocol
        proto = self._obj.protocol or 'any'
        idx = self.protocol.findText(proto)
        if idx >= 0:
            self.protocol.setCurrentIndex(idx)
        else:
            self.protocol.setEditText(proto)

        # Address family
        af = self._obj.custom_address_family
        if af == socket.AF_INET6:
            self.ipv6.setChecked(True)
        else:
            self.ipv4.setChecked(True)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()

        # Save current platform code before writing back.
        self._save_current_code()
        self._obj.codes = dict(self._all_codes) if self._all_codes else None

        self._obj.protocol = self.protocol.currentText() or 'any'
        self._obj.custom_address_family = (
            socket.AF_INET6 if self.ipv6.isChecked() else socket.AF_INET
        )

    def _on_platform_changed(self, _index):
        """Save the code for the old platform, load for the new one."""
        if self._loading:
            return
        self._save_current_code()
        self._current_platform = self.platform.currentData() or ''
        self.code.setText(self._all_codes.get(self._current_platform, ''))

    def _save_current_code(self):
        """Store the current code text into the per-platform map."""
        if self._current_platform:
            text = self.code.text()
            if text:
                self._all_codes[self._current_platform] = text
            else:
                self._all_codes.pop(self._current_platform, None)
