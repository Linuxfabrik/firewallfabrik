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
from typing import ClassVar

from PySide6.QtCore import QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'linuxsettingsdialog_q.ui'

# Combo box widgets: maps widget name to typed column name.
# All use "No change" / "On" / "Off" text values.
_COMBOS: dict[str, str] = {
    'linux24_ip_forward': 'opt_ip_forward',
    'linux24_ipv6_forward': 'opt_ipv6_forward',
    'linux24_rp_filter': 'opt_rp_filter',
    'linux24_icmp_echo_ignore_broadcasts': 'opt_icmp_echo_ignore_broadcasts',
    'linux24_icmp_echo_ignore_all': 'opt_icmp_echo_ignore_all',
    'linux24_accept_source_route': 'opt_accept_source_route',
    'linux24_accept_redirects': 'opt_accept_redirects',
    'linux24_icmp_ignore_bogus_error_responses': 'opt_icmp_ignore_bogus_error_responses',
    'linux24_ip_dynaddr': 'opt_ip_dynaddr',
    'linux24_log_martians': 'opt_log_martians',
    'linux24_tcp_window_scaling': 'opt_tcp_window_scaling',
    'linux24_tcp_sack': 'opt_tcp_sack',
    'linux24_tcp_fack': 'opt_tcp_fack',
    'linux24_tcp_ecn': 'opt_tcp_ecn',
    'linux24_tcp_syncookies': 'opt_tcp_syncookies',
    'linux24_tcp_timestamps': 'opt_tcp_timestamps',
    # Widget named 'conntrack_tcp_be_liberal' but column strips linux24_ prefix
    'conntrack_tcp_be_liberal': 'opt_conntrack_tcp_be_liberal',
}

# SpinBox widgets: maps widget name to typed column name.
_SPINBOXES: dict[str, str] = {
    'linux24_tcp_fin_timeout': 'opt_tcp_fin_timeout',
    'linux24_tcp_keepalive_interval': 'opt_tcp_keepalive_interval',
    'conntrack_max': 'opt_conntrack_max',
    'conntrack_hashsize': 'opt_conntrack_hashsize',
}

# Line-edit widgets: maps widget name to typed column name.
_LINE_EDITS: dict[str, str] = {
    'linux24_path_iptables': 'opt_path_iptables',
    'linux24_path_ip6tables': 'opt_path_ip6tables',
    'linux24_path_ip': 'opt_path_ip',
    'linux24_path_logger': 'opt_path_logger',
    'linux24_path_vconfig': 'opt_path_vconfig',
    'linux24_path_brctl': 'opt_path_brctl',
    'linux24_path_ifenslave': 'opt_path_ifenslave',
    'linux24_path_modprobe': 'opt_path_modprobe',
    'linux24_path_lsmod': 'opt_path_lsmod',
    'linux24_path_ipset': 'opt_path_ipset',
    'linux24_path_iptables_restore': 'opt_path_iptables_restore',
    'linux24_path_ip6tables_restore': 'opt_path_ip6tables_restore',
    'linux24_data_dir': 'opt_data_dir',
}

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

    # Combo boxes on the Options tab that are not supported by nftables.
    _NFTABLES_UNSUPPORTED_COMBOS: ClassVar[list[str]] = [
        'linux24_rp_filter',
        'linux24_icmp_echo_ignore_broadcasts',
        'linux24_icmp_echo_ignore_all',
        'linux24_accept_source_route',
        'linux24_accept_redirects',
        'linux24_icmp_ignore_bogus_error_responses',
        'linux24_ip_dynaddr',
        'linux24_log_martians',
    ]

    # Labels that accompany the unsupported combos (from the .ui file).
    _NFTABLES_UNSUPPORTED_LABELS: ClassVar[list[str]] = [
        'label369',
        'label370',
        'label386',
        'label371',
        'label373',
        'label374',
        'label375',
        'label380',
    ]

    def __init__(self, firewall_obj, *, platform='', parent=None):
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
        if platform == 'nftables':
            self._disable_for_nftables()
        self.accepted.connect(self._save_settings)

    def _disable_for_nftables(self):
        """Disable widgets that are not supported by the nftables compiler."""
        # Disable unsupported combo boxes and their labels on the Options tab.
        for name in self._NFTABLES_UNSUPPORTED_COMBOS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(False)
        for name in self._NFTABLES_UNSUPPORTED_LABELS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(False)

        # Disable entire tabs: TCP (1), Path (2), conntrack (3), Data (4).
        for idx in (1, 2, 3, 4):
            self.tabWidget.setTabEnabled(idx, False)

    def _populate(self):
        # Combo boxes — read directly from typed columns.
        for widget_name, col in _COMBOS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            val = getattr(self._fw, col) or ''
            text = _VALUE_TO_COMBO_TEXT.get(str(val), 'No change')
            idx = widget.findText(text)
            widget.setCurrentIndex(max(idx, 0))

        # Spin boxes — read directly from typed columns.
        for widget_name, col in _SPINBOXES.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            val = getattr(self._fw, col)
            try:
                widget.setValue(int(val))
            except (ValueError, TypeError):
                widget.setValue(0)

        # Line edits — read directly from typed columns.
        for widget_name, col in _LINE_EDITS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            widget.setText(str(getattr(self._fw, col) or ''))

    def _save_settings(self):
        # Combo boxes — write directly to typed columns.
        for widget_name, col in _COMBOS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            setattr(self._fw, col, _COMBO_TEXT_TO_VALUE.get(widget.currentText(), ''))

        # Spin boxes — write directly to typed columns.
        for widget_name, col in _SPINBOXES.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            setattr(self._fw, col, widget.value())

        # Line edits — write directly to typed columns.
        for widget_name, col in _LINE_EDITS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            setattr(self._fw, col, widget.text())

    @Slot()
    def help(self):
        QDesktopServices.openUrl(
            QUrl(
                'https://github.com/Linuxfabrik/firewallfabrik/tree/main/docs/user-guide'
            ),
        )
