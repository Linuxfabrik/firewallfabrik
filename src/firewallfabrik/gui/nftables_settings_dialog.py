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

"""Nftables platform settings dialog."""

from pathlib import Path

from PySide6.QtCore import QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'nftablessettingsdialog_q.ui'

# Checkbox widget → canonical compiler option key.
# The compiler reads options by the canonical key (right-hand side).
_CHECKBOX_MAP: dict[str, str] = {
    'assumeFwIsPartOfAny': 'firewall_is_part_of_any_and_networks',
    'acceptSessions': 'accept_new_tcp_with_no_syn',
    'acceptESTBeforeFirst': 'accept_established',
    'dropInvalid': 'drop_invalid',
    'logInvalid': 'log_invalid',
    'localNAT': 'local_nat',
    'shadowing': 'check_shading',
    'emptyGroups': 'ignore_empty_groups',
    'clampMSStoMTU': 'clamp_mss_to_mtu',
    'bridge': 'bridging_fw',
    'ipv6NeighborDiscovery': 'ipv6_neighbor_discovery',
    'mgmt_ssh': 'mgmt_ssh',
    'add_mgmt_ssh_rule_when_stoped': 'add_mgmt_ssh_rule_when_stoped',
    'useModuleSet': 'use_m_set',
    'useKernelTz': 'use_kerneltz',
    'logTCPseq': 'log_tcp_seq',
    'logTCPopt': 'log_tcp_opt',
    'logIPopt': 'log_ip_opt',
    'logNumsyslog': 'use_numeric_log_levels',
    'logAll': 'log_all',
    'loadModules': 'load_modules',
    'iptDebug': 'debug',
    'verifyInterfaces': 'verify_interfaces',
    'configureInterfaces': 'configure_interfaces',
    'clearUnknownInterfaces': 'clear_unknown_interfaces',
    'configure_vlan_interfaces': 'configure_vlan_interfaces',
    'configure_bridge_interfaces': 'configure_bridge_interfaces',
    'configure_bonding_interfaces': 'configure_bonding_interfaces',
    'addVirtualsforNAT': 'manage_virtual_addr',
    'iptablesRestoreActivation': 'use_iptables_restore',
}

# Line-edit widget → canonical compiler option key.
_LINE_EDIT_MAP: dict[str, str] = {
    'compiler': 'compiler',
    'compilerArgs': 'cmdline',
    'outputFileName': 'output_file',
    'fileNameOnFw': 'script_name_on_firewall',
    'mgmt_addr': 'mgmt_addr',
    'logprefix': 'log_prefix',
    'ipt_fw_dir': 'firewall_dir',
    'ipt_user': 'admUser',
    'altAddress': 'altAddress',
    'activationCmd': 'activationCmd',
    'sshArgs': 'sshArgs',
    'scpArgs': 'scpArgs',
    'installScript': 'installScript',
    'installScriptArgs': 'installScriptArgs',
}

# LOG level syslog names matching the C++ dialog.
_LOG_LEVELS = [
    '',
    'alert',
    'crit',
    'debug',
    'emerg',
    'error',
    'info',
    'notice',
    'warning',
]

# Logging limit suffix options.
_LOG_LIMIT_SUFFIXES = ['/second', '/minute', '/hour', '/day']

# Reject action options.
_ACTION_ON_REJECT = [
    'ICMP unreachable',
    'ICMP net unreachable',
    'ICMP host unreachable',
    'ICMP port unreachable',
    'ICMP net prohibited',
    'ICMP host prohibited',
    'TCP RST',
]

# Prolog placement combo values matching the .ui order.
_PROLOG_PLACES = [
    'top',
    'after_interfaces',
    'after_flush',
]


class NftablesSettingsDialog(QDialog):
    """Modal dialog for nftables firewall settings."""

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

        # Populate combo boxes with fixed option lists.
        self.actionOnReject.addItems(_ACTION_ON_REJECT)
        self.logLevel.addItems(_LOG_LEVELS)
        self.logLimitSuffix.addItems(_LOG_LIMIT_SUFFIXES)

        self._populate()
        self.accepted.connect(self._save_settings)

    def _populate(self):
        opts = self._fw.options or {}

        # Checkboxes — read canonical key, fall back to widget name for
        # backward compat with old .fwf files that stored widget names.
        for widget_name, key in _CHECKBOX_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key in opts:
                val = str(opts[key]).lower() == 'true'
            elif widget_name in opts:
                val = str(opts[widget_name]).lower() == 'true'
            else:
                val = False
            # acceptSessions checkbox has inverted semantics:
            if key == 'accept_new_tcp_with_no_syn':
                widget.setChecked(not val)
            else:
                widget.setChecked(val)

        # Line edits — read canonical key, fall back to widget name.
        for widget_name, key in _LINE_EDIT_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key in opts:
                widget.setText(str(opts[key]))
            elif widget_name in opts:
                widget.setText(str(opts[widget_name]))
            else:
                widget.setText('')

        # Text edits (prolog / epilog)
        self.prolog_script.setPlainText(opts.get('prolog_script', ''))
        self.epilog_script.setPlainText(opts.get('epilog_script', ''))

        # Prolog placement combo
        place = opts.get('prolog_place', 'top')
        try:
            idx = _PROLOG_PLACES.index(place)
        except ValueError:
            idx = 0
        self.prologPlace.setCurrentIndex(idx)

        # LOG, ULOG, and NFLOG radio buttons
        if str(opts.get('use_ULOG', '')).lower() == 'true':
            self.useULOG.setChecked(True)
        elif str(opts.get('use_NFLOG', '')).lower() == 'true':
            self.useNFLOG.setChecked(True)
        else:
            self.useLOG.setChecked(True)
        self._update_log_stack()

        # Log level combo
        level = opts.get('log_level', '')
        idx = self.logLevel.findText(level)
        self.logLevel.setCurrentIndex(max(idx, 0))

        # Logging limit
        limit_val = opts.get('limit_value', '0')
        try:
            self.logLimitVal.setValue(int(limit_val))
        except (ValueError, TypeError):
            self.logLimitVal.setValue(0)

        limit_suffix = opts.get('limit_suffix', '/second')
        idx = self.logLimitSuffix.findText(limit_suffix)
        self.logLimitSuffix.setCurrentIndex(max(idx, 0))

        # Action on reject combo
        action = opts.get('action_on_reject', '')
        idx = self.actionOnReject.findText(action)
        self.actionOnReject.setCurrentIndex(max(idx, 0))

        # ULOG spin boxes
        self.cprange.setValue(int(opts.get('ulog_cprange', 0)))
        self.qthreshold.setValue(int(opts.get('ulog_qthreshold', 1)))
        self.nlgroup.setValue(int(opts.get('ulog_nlgroup', 1)))

        # IPv4 before IPv6 combo
        if str(opts.get('ipv4_6_order', '')).lower() == 'ipv6_first':
            self.ipv4before.setCurrentIndex(1)
        else:
            self.ipv4before.setCurrentIndex(0)

    def _save_settings(self):
        opts = dict(self._fw.options or {})

        # Checkboxes — always write under canonical key; remove stale
        # widget-name key if it differs from the canonical key.
        for widget_name, key in _CHECKBOX_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            # Store as Python bool (not string) so that raw
            # ``options.get(key, False)`` in the compiler works correctly.
            # acceptSessions has inverted semantics.
            if key == 'accept_new_tcp_with_no_syn':
                opts[key] = not widget.isChecked()
            else:
                opts[key] = widget.isChecked()
            # Clean up stale widget-name key.
            if widget_name != key:
                opts.pop(widget_name, None)

        # Line edits — always write under canonical key.
        for widget_name, key in _LINE_EDIT_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = widget.text()
            if widget_name != key:
                opts.pop(widget_name, None)

        # Text edits
        opts['prolog_script'] = self.prolog_script.toPlainText()
        opts['epilog_script'] = self.epilog_script.toPlainText()

        # Prolog placement
        idx = self.prologPlace.currentIndex()
        opts['prolog_place'] = (
            _PROLOG_PLACES[idx] if idx < len(_PROLOG_PLACES) else 'top'
        )

        # LOG / ULOG / NFLOG
        opts['use_ULOG'] = self.useULOG.isChecked()
        opts['use_NFLOG'] = self.useNFLOG.isChecked()

        # Log options
        opts['log_level'] = self.logLevel.currentText()
        opts['limit_value'] = str(self.logLimitVal.value())
        opts['limit_suffix'] = self.logLimitSuffix.currentText()
        opts['action_on_reject'] = self.actionOnReject.currentText()

        # ULOG options
        opts['ulog_cprange'] = str(self.cprange.value())
        opts['ulog_qthreshold'] = str(self.qthreshold.value())
        opts['ulog_nlgroup'] = str(self.nlgroup.value())

        # IPv4/IPv6 order
        opts['ipv4_6_order'] = (
            'ipv6_first' if self.ipv4before.currentIndex() == 1 else 'ipv4_first'
        )

        # Reassign to trigger SQLAlchemy JSON mutation detection.
        self._fw.options = opts

    def _update_log_stack(self):
        self.logTargetStack.setCurrentIndex(0 if self.useLOG.isChecked() else 1)

    # -- Slots declared in the .ui file --

    @Slot()
    def switchLOG_ULOG(self):
        self._update_log_stack()

    @Slot()
    def editProlog(self):
        self.prolog_script.setFocus()

    @Slot()
    def editEpilog(self):
        self.epilog_script.setFocus()

    @Slot()
    def help(self):
        QDesktopServices.openUrl(
            QUrl(
                'https://github.com/Linuxfabrik/firewallfabrik/tree/main/docs/user-guide'
            ),
        )
