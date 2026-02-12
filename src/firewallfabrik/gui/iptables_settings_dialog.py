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

"""Iptables platform settings dialog."""

from pathlib import Path

from PySide6.QtCore import QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'iptablessettingsdialog_q.ui'

# Checkbox widget names that map directly to boolean option keys.
_CHECKBOXES = [
    'assumeFwIsPartOfAny',
    'acceptSessions',
    'acceptESTBeforeFirst',
    'dropInvalid',
    'logInvalid',
    'localNAT',
    'shadowing',
    'emptyGroups',
    'clampMSStoMTU',
    'bridge',
    'ipv6NeighborDiscovery',
    'mgmt_ssh',
    'add_mgmt_ssh_rule_when_stoped',
    'useModuleSet',
    'useKernelTz',
    'logTCPseq',
    'logTCPopt',
    'logIPopt',
    'logNumsyslog',
    'logAll',
    'loadModules',
    'iptDebug',
    'verifyInterfaces',
    'configureInterfaces',
    'clearUnknownInterfaces',
    'configure_vlan_interfaces',
    'configure_bridge_interfaces',
    'configure_bonding_interfaces',
    'addVirtualsforNAT',
    'iptablesRestoreActivation',
]

# Line-edit widget names that map directly to string option keys.
_LINE_EDITS = [
    'compiler',
    'compilerArgs',
    'outputFileName',
    'fileNameOnFw',
    'mgmt_addr',
    'logprefix',
    'ipt_fw_dir',
    'ipt_user',
    'altAddress',
    'activationCmd',
    'sshArgs',
    'scpArgs',
    'installScript',
    'installScriptArgs',
]

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


class IptablesSettingsDialog(QDialog):
    """Modal dialog for iptables firewall settings."""

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

        # Checkboxes
        for name in _CHECKBOXES:
            widget = getattr(self, name, None)
            if widget is not None:
                val = opts.get(name, '')
                widget.setChecked(str(val).lower() == 'true')

        # Line edits
        for name in _LINE_EDITS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setText(opts.get(name, ''))

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

        # LOG vs. ULOG radio buttons
        if str(opts.get('use_ULOG', '')).lower() == 'true':
            self.useULOG.setChecked(True)
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
        if str(opts.get('ipv4_6_order', '')).lower() == 'ipv6_before_ipv4':
            self.ipv4before.setCurrentIndex(1)
        else:
            self.ipv4before.setCurrentIndex(0)

    def _save_settings(self):
        opts = dict(self._fw.options or {})

        # Checkboxes
        for name in _CHECKBOXES:
            widget = getattr(self, name, None)
            if widget is not None:
                opts[name] = str(widget.isChecked())

        # Line edits
        for name in _LINE_EDITS:
            widget = getattr(self, name, None)
            if widget is not None:
                opts[name] = widget.text()

        # Text edits
        opts['prolog_script'] = self.prolog_script.toPlainText()
        opts['epilog_script'] = self.epilog_script.toPlainText()

        # Prolog placement
        idx = self.prologPlace.currentIndex()
        opts['prolog_place'] = (
            _PROLOG_PLACES[idx] if idx < len(_PROLOG_PLACES) else 'top'
        )

        # LOG / ULOG
        opts['use_ULOG'] = str(self.useULOG.isChecked())

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
            'ipv6_before_ipv4'
            if self.ipv4before.currentIndex() == 1
            else 'ipv4_before_ipv6'
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
