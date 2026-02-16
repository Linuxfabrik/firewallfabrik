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

from firewallfabrik.core.options import LinuxOption
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'linuxsettingsdialog_q.ui'

# Combo box widgets: maps widget name to canonical option key.
# All use "No change" / "On" / "Off" text values.
_COMBOS: dict[str, str] = {
    'linux24_ip_forward': LinuxOption.IP_FORWARD,
    'linux24_ipv6_forward': LinuxOption.IPV6_FORWARD,
    'linux24_rp_filter': LinuxOption.RP_FILTER,
    'linux24_icmp_echo_ignore_broadcasts': LinuxOption.ICMP_ECHO_IGNORE_BROADCASTS,
    'linux24_icmp_echo_ignore_all': LinuxOption.ICMP_ECHO_IGNORE_ALL,
    'linux24_accept_source_route': LinuxOption.ACCEPT_SOURCE_ROUTE,
    'linux24_accept_redirects': LinuxOption.ACCEPT_REDIRECTS,
    'linux24_icmp_ignore_bogus_error_responses': LinuxOption.ICMP_IGNORE_BOGUS_ERROR_RESPONSES,
    'linux24_ip_dynaddr': LinuxOption.IP_DYNADDR,
    'linux24_log_martians': LinuxOption.LOG_MARTIANS,
    'linux24_tcp_window_scaling': LinuxOption.TCP_WINDOW_SCALING,
    'linux24_tcp_sack': LinuxOption.TCP_SACK,
    'linux24_tcp_fack': LinuxOption.TCP_FACK,
    'linux24_tcp_ecn': LinuxOption.TCP_ECN,
    'linux24_tcp_syncookies': LinuxOption.TCP_SYNCOOKIES,
    'linux24_tcp_timestamps': LinuxOption.TCP_TIMESTAMPS,
    # Widget named 'conntrack_tcp_be_liberal' but key includes linux24_ prefix
    'conntrack_tcp_be_liberal': LinuxOption.CONNTRACK_TCP_BE_LIBERAL,
}

# SpinBox widgets: maps widget name to canonical option key.
_SPINBOXES: dict[str, str] = {
    'linux24_tcp_fin_timeout': LinuxOption.TCP_FIN_TIMEOUT,
    'linux24_tcp_keepalive_interval': LinuxOption.TCP_KEEPALIVE_INTERVAL,
    # Widgets named without linux24_ prefix but keys include it
    'conntrack_max': LinuxOption.CONNTRACK_MAX,
    'conntrack_hashsize': LinuxOption.CONNTRACK_HASHSIZE,
}

# Line-edit widgets: maps widget name to canonical option key.
_LINE_EDITS: dict[str, str] = {
    'linux24_path_iptables': LinuxOption.PATH_IPTABLES,
    'linux24_path_ip6tables': LinuxOption.PATH_IP6TABLES,
    'linux24_path_ip': LinuxOption.PATH_IP,
    'linux24_path_logger': LinuxOption.PATH_LOGGER,
    'linux24_path_vconfig': LinuxOption.PATH_VCONFIG,
    'linux24_path_brctl': LinuxOption.PATH_BRCTL,
    'linux24_path_ifenslave': LinuxOption.PATH_IFENSLAVE,
    'linux24_path_modprobe': LinuxOption.PATH_MODPROBE,
    'linux24_path_lsmod': LinuxOption.PATH_LSMOD,
    'linux24_path_ipset': LinuxOption.PATH_IPSET,
    'linux24_path_iptables_restore': LinuxOption.PATH_IPTABLES_RESTORE,
    'linux24_path_ip6tables_restore': LinuxOption.PATH_IP6TABLES_RESTORE,
    'linux24_data_dir': LinuxOption.DATA_DIR,
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
        opts = self._fw.options or {}

        # Combo boxes — read canonical key, fall back to widget name for
        # backward compat with old .fwf files that stored widget names.
        for widget_name, key in _COMBOS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key in opts:
                val = opts[key]
            elif widget_name in opts:
                val = opts[widget_name]
            else:
                val = ''
            text = _VALUE_TO_COMBO_TEXT.get(str(val), 'No change')
            idx = widget.findText(text)
            widget.setCurrentIndex(max(idx, 0))

        # Spin boxes — read canonical key, fall back to widget name.
        for widget_name, key in _SPINBOXES.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key in opts:
                val = opts[key]
            elif widget_name in opts:
                val = opts[widget_name]
            else:
                val = 0
            try:
                widget.setValue(int(val))
            except (ValueError, TypeError):
                widget.setValue(0)

        # Line edits — read canonical key, fall back to widget name.
        for widget_name, key in _LINE_EDITS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key in opts:
                widget.setText(str(opts[key]))
            elif widget_name in opts:
                widget.setText(str(opts[widget_name]))
            else:
                widget.setText('')

    def _save_settings(self):
        opts = dict(self._fw.options or {})

        # Combo boxes — always write under canonical key; remove stale
        # widget-name key if it differs from the canonical key.
        for widget_name, key in _COMBOS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = _COMBO_TEXT_TO_VALUE.get(widget.currentText(), '')
            # Clean up stale widget-name key.
            if widget_name != key:
                opts.pop(widget_name, None)

        # Spin boxes — always write under canonical key.
        for widget_name, key in _SPINBOXES.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = str(widget.value())
            if widget_name != key:
                opts.pop(widget_name, None)

        # Line edits — always write under canonical key.
        for widget_name, key in _LINE_EDITS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = widget.text()
            if widget_name != key:
                opts.pop(widget_name, None)

        # Reassign to trigger SQLAlchemy JSON mutation detection.
        self._fw.options = opts

    @Slot()
    def help(self):
        QDesktopServices.openUrl(
            QUrl(
                'https://github.com/Linuxfabrik/firewallfabrik/tree/main/docs/user-guide'
            ),
        )
