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

from firewallfabrik.core.options import FirewallOption
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'iptablessettingsdialog_q.ui'

# Checkbox widget → canonical compiler option key.
# The compiler reads options by the canonical key (right-hand side).
_CHECKBOX_MAP: dict[str, str] = {
    'assumeFwIsPartOfAny': FirewallOption.FIREWALL_IS_PART_OF_ANY,
    'acceptSessions': FirewallOption.ACCEPT_NEW_TCP_WITH_NO_SYN,
    'acceptESTBeforeFirst': FirewallOption.ACCEPT_ESTABLISHED,
    'dropInvalid': FirewallOption.DROP_INVALID,
    'logInvalid': FirewallOption.LOG_INVALID,
    'localNAT': FirewallOption.LOCAL_NAT,
    'shadowing': FirewallOption.CHECK_SHADING,
    'emptyGroups': FirewallOption.IGNORE_EMPTY_GROUPS,
    'clampMSStoMTU': FirewallOption.CLAMP_MSS_TO_MTU,
    'bridge': FirewallOption.BRIDGING_FW,
    'ipv6NeighborDiscovery': FirewallOption.IPV6_NEIGHBOR_DISCOVERY,
    'mgmt_ssh': FirewallOption.MGMT_SSH,
    'add_mgmt_ssh_rule_when_stoped': FirewallOption.ADD_MGMT_SSH_RULE_WHEN_STOPPED,
    'useModuleSet': FirewallOption.USE_M_SET,
    'useKernelTz': FirewallOption.USE_KERNELTZ,
    'logTCPseq': FirewallOption.LOG_TCP_SEQ,
    'logTCPopt': FirewallOption.LOG_TCP_OPT,
    'logIPopt': FirewallOption.LOG_IP_OPT,
    'logNumsyslog': FirewallOption.USE_NUMERIC_LOG_LEVELS,
    'logAll': FirewallOption.LOG_ALL,
    'loadModules': FirewallOption.LOAD_MODULES,
    'iptDebug': FirewallOption.DEBUG,
    'verifyInterfaces': FirewallOption.VERIFY_INTERFACES,
    'configureInterfaces': FirewallOption.CONFIGURE_INTERFACES,
    'clearUnknownInterfaces': FirewallOption.CLEAR_UNKNOWN_INTERFACES,
    'configure_vlan_interfaces': FirewallOption.CONFIGURE_VLAN_INTERFACES,
    'configure_bridge_interfaces': FirewallOption.CONFIGURE_BRIDGE_INTERFACES,
    'configure_bonding_interfaces': FirewallOption.CONFIGURE_BONDING_INTERFACES,
    'addVirtualsforNAT': FirewallOption.MANAGE_VIRTUAL_ADDR,
    'iptablesRestoreActivation': FirewallOption.USE_IPTABLES_RESTORE,
}

# Line-edit widget → canonical compiler option key.
_LINE_EDIT_MAP: dict[str, str] = {
    'compiler': FirewallOption.COMPILER,
    'compilerArgs': FirewallOption.CMDLINE,
    'outputFileName': FirewallOption.OUTPUT_FILE,
    'fileNameOnFw': FirewallOption.SCRIPT_NAME_ON_FIREWALL,
    'mgmt_addr': FirewallOption.MGMT_ADDR,
    'logprefix': FirewallOption.LOG_PREFIX,
    'ipt_fw_dir': FirewallOption.FIREWALL_DIR,
    'ipt_user': FirewallOption.ADM_USER,
    'altAddress': FirewallOption.ALT_ADDRESS,
    'activationCmd': FirewallOption.ACTIVATION_CMD,
    'sshArgs': FirewallOption.SSH_ARGS,
    'scpArgs': FirewallOption.SCP_ARGS,
    'installScript': FirewallOption.INSTALL_SCRIPT,
    'installScriptArgs': FirewallOption.INSTALL_SCRIPT_ARGS,
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

# Widgets for options that are not supported by the iptables compiler.
# These are disabled in the UI to prevent users from setting options
# that would be silently ignored.
_UNSUPPORTED_WIDGETS = (
    # Compiler tab — not implemented / hardcoded off
    'acceptSessions',
    'useKernelTz',
    'mgmt_ssh',
    'mgmt_addr',
    'add_mgmt_ssh_rule_when_stoped',
    # Logging tab — warns only
    'logTCPseq',
    'logTCPopt',
    'logIPopt',
    'logNumsyslog',
    'logAll',
    # Script tab — warns only
    'configure_bridge_interfaces',
)


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
        self._disable_unsupported()
        self.accepted.connect(self._save_settings)

    def _disable_unsupported(self):
        """Disable widgets for options not supported by the iptables compiler."""
        for name in _UNSUPPORTED_WIDGETS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(False)

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
            if key == FirewallOption.ACCEPT_NEW_TCP_WITH_NO_SYN:
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
        self.prolog_script.setPlainText(opts.get(FirewallOption.PROLOG_SCRIPT, ''))
        self.epilog_script.setPlainText(opts.get(FirewallOption.EPILOG_SCRIPT, ''))

        # Prolog placement combo
        place = opts.get(FirewallOption.PROLOG_PLACE, 'top')
        try:
            idx = _PROLOG_PLACES.index(place)
        except ValueError:
            idx = 0
        self.prologPlace.setCurrentIndex(idx)

        # LOG, ULOG, and NFLOG radio buttons
        if str(opts.get(FirewallOption.USE_ULOG, '')).lower() == 'true':
            self.useULOG.setChecked(True)
        elif str(opts.get(FirewallOption.USE_NFLOG, '')).lower() == 'true':
            self.useNFLOG.setChecked(True)
        else:
            self.useLOG.setChecked(True)
        self._update_log_stack()

        # Log level combo
        level = opts.get(FirewallOption.LOG_LEVEL, '')
        idx = self.logLevel.findText(level)
        self.logLevel.setCurrentIndex(max(idx, 0))

        # Logging limit
        limit_val = opts.get(FirewallOption.LIMIT_VALUE, '0')
        try:
            self.logLimitVal.setValue(int(limit_val))
        except (ValueError, TypeError):
            self.logLimitVal.setValue(0)

        limit_suffix = opts.get(FirewallOption.LIMIT_SUFFIX, '/second')
        idx = self.logLimitSuffix.findText(limit_suffix)
        self.logLimitSuffix.setCurrentIndex(max(idx, 0))

        # Action on reject combo
        action = opts.get(FirewallOption.ACTION_ON_REJECT, '')
        idx = self.actionOnReject.findText(action)
        self.actionOnReject.setCurrentIndex(max(idx, 0))

        # ULOG spin boxes
        self.cprange.setValue(int(opts.get(FirewallOption.ULOG_CPRANGE, 0)))
        self.qthreshold.setValue(int(opts.get(FirewallOption.ULOG_QTHRESHOLD, 1)))
        self.nlgroup.setValue(int(opts.get(FirewallOption.ULOG_NLGROUP, 1)))

        # IPv4 before IPv6 combo
        if str(opts.get(FirewallOption.IPV4_6_ORDER, '')).lower() == 'ipv6_first':
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
            if key == FirewallOption.ACCEPT_NEW_TCP_WITH_NO_SYN:
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
        opts[FirewallOption.PROLOG_SCRIPT] = self.prolog_script.toPlainText()
        opts[FirewallOption.EPILOG_SCRIPT] = self.epilog_script.toPlainText()

        # Prolog placement
        idx = self.prologPlace.currentIndex()
        opts[FirewallOption.PROLOG_PLACE] = (
            _PROLOG_PLACES[idx] if idx < len(_PROLOG_PLACES) else 'top'
        )

        # LOG / ULOG / NFLOG
        opts[FirewallOption.USE_ULOG] = self.useULOG.isChecked()
        opts[FirewallOption.USE_NFLOG] = self.useNFLOG.isChecked()

        # Log options
        opts[FirewallOption.LOG_LEVEL] = self.logLevel.currentText()
        opts[FirewallOption.LIMIT_VALUE] = str(self.logLimitVal.value())
        opts[FirewallOption.LIMIT_SUFFIX] = self.logLimitSuffix.currentText()
        opts[FirewallOption.ACTION_ON_REJECT] = self.actionOnReject.currentText()

        # ULOG options
        opts[FirewallOption.ULOG_CPRANGE] = str(self.cprange.value())
        opts[FirewallOption.ULOG_QTHRESHOLD] = str(self.qthreshold.value())
        opts[FirewallOption.ULOG_NLGROUP] = str(self.nlgroup.value())

        # IPv4/IPv6 order
        opts[FirewallOption.IPV4_6_ORDER] = (
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
