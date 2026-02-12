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

"""Linux host OS settings dialog."""

from pathlib import Path

from PySide6.QtCore import QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'linuxsettingsdialog_q.ui'

# Combo box widget names — all use "No change" / "On" / "Off" text values.
_COMBOS = [
    'linux24_ip_forward',
    'linux24_ipv6_forward',
    'linux24_rp_filter',
    'linux24_icmp_echo_ignore_broadcasts',
    'linux24_icmp_echo_ignore_all',
    'linux24_accept_source_route',
    'linux24_accept_redirects',
    'linux24_icmp_ignore_bogus_error_responses',
    'linux24_ip_dynaddr',
    'linux24_log_martians',
    'linux24_tcp_window_scaling',
    'linux24_tcp_sack',
    'linux24_tcp_fack',
    'linux24_tcp_ecn',
    'linux24_tcp_syncookies',
    'linux24_tcp_timestamps',
    'conntrack_tcp_be_liberal',
]

# SpinBox widget names that map to integer option keys.
_SPINBOXES = [
    'linux24_tcp_fin_timeout',
    'linux24_tcp_keepalive_interval',
    'conntrack_max',
    'conntrack_hashsize',
]

# Line-edit widget names for path settings.
_LINE_EDITS = [
    'linux24_path_iptables',
    'linux24_path_ip6tables',
    'linux24_path_ip',
    'linux24_path_logger',
    'linux24_path_vconfig',
    'linux24_path_brctl',
    'linux24_path_ifenslave',
    'linux24_path_modprobe',
    'linux24_path_lsmod',
    'linux24_path_ipset',
    'linux24_path_iptables_restore',
    'linux24_path_ip6tables_restore',
    'linux24_data_dir',
]

# Mapping from combo text to stored option value.
_COMBO_TEXT_TO_VALUE = {
    'No change': '',
    'On': '1',
    'Off': '0',
}

# Reverse mapping from stored option value to combo text.
_VALUE_TO_COMBO_TEXT = {v: k for k, v in _COMBO_TEXT_TO_VALUE.items()}


class LinuxSettingsDialog(QDialog):
    """Modal dialog for Linux host OS settings."""

    def __init__(self, firewall_obj, parent=None):
        super().__init__(parent)
        self._fw = firewall_obj

        loader = FWFUiLoader(self)
        loader.load(str(_UI_PATH))

        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

        self._populate()
        self.accepted.connect(self._save_settings)

    def _populate(self):
        opts = self._fw.options or {}

        # Combo boxes
        for name in _COMBOS:
            widget = getattr(self, name, None)
            if widget is None:
                continue
            val = opts.get(name, '')
            text = _VALUE_TO_COMBO_TEXT.get(str(val), 'No change')
            idx = widget.findText(text)
            widget.setCurrentIndex(max(idx, 0))

        # Spin boxes
        for name in _SPINBOXES:
            widget = getattr(self, name, None)
            if widget is None:
                continue
            try:
                widget.setValue(int(opts.get(name, 0)))
            except (ValueError, TypeError):
                widget.setValue(0)

        # Line edits
        for name in _LINE_EDITS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setText(opts.get(name, ''))

    def _save_settings(self):
        opts = dict(self._fw.options or {})

        # Combo boxes
        for name in _COMBOS:
            widget = getattr(self, name, None)
            if widget is None:
                continue
            opts[name] = _COMBO_TEXT_TO_VALUE.get(widget.currentText(), '')

        # Spin boxes
        for name in _SPINBOXES:
            widget = getattr(self, name, None)
            if widget is None:
                continue
            opts[name] = str(widget.value())

        # Line edits
        for name in _LINE_EDITS:
            widget = getattr(self, name, None)
            if widget is not None:
                opts[name] = widget.text()

        # Reassign to trigger SQLAlchemy JSON mutation detection.
        self._fw.options = opts

    @Slot()
    def help(self):
        QDesktopServices.openUrl(
            QUrl(
                'https://github.com/Linuxfabrik/firewallfabrik/tree/main/docs/user-guide'
            ),
        )
