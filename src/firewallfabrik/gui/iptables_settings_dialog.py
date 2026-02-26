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

from firewallfabrik.core.options._metadata import HOST_COMPILER_DEFAULTS
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'iptablessettingsdialog_q.ui'

# Checkbox widget → typed column name on the Firewall ORM object.
_CHECKBOX_MAP: dict[str, str] = {
    'assumeFwIsPartOfAny': 'opt_firewall_is_part_of_any_and_networks',
    'acceptSessions': 'opt_accept_new_tcp_with_no_syn',
    'acceptESTBeforeFirst': 'opt_accept_established',
    'dropInvalid': 'opt_drop_invalid',
    'logInvalid': 'opt_log_invalid',
    'localNAT': 'opt_local_nat',
    'shadowing': 'opt_check_shading',
    'emptyGroups': 'opt_ignore_empty_groups',
    'clampMSStoMTU': 'opt_clamp_mss_to_mtu',
    'bridge': 'opt_bridging_fw',
    'ipv6NeighborDiscovery': 'opt_ipv6_neighbor_discovery',
    'mgmt_ssh': 'opt_mgmt_ssh',
    'add_mgmt_ssh_rule_when_stoped': 'opt_add_mgmt_ssh_rule_when_stoped',
    'useModuleSet': 'opt_use_m_set',
    'useKernelTz': 'opt_use_kerneltz',
    'logTCPseq': 'opt_log_tcp_seq',
    'logTCPopt': 'opt_log_tcp_opt',
    'logIPopt': 'opt_log_ip_opt',
    'logNumsyslog': 'opt_use_numeric_log_levels',
    'logAll': 'opt_log_all',
    'loadModules': 'opt_load_modules',
    'iptDebug': 'opt_debug',
    'verifyInterfaces': 'opt_verify_interfaces',
    'configureInterfaces': 'opt_configure_interfaces',
    'clearUnknownInterfaces': 'opt_clear_unknown_interfaces',
    'configure_vlan_interfaces': 'opt_configure_vlan_interfaces',
    'configure_bridge_interfaces': 'opt_configure_bridge_interfaces',
    'configure_bonding_interfaces': 'opt_configure_bonding_interfaces',
    'addVirtualsforNAT': 'opt_manage_virtual_addr',
    'iptablesRestoreActivation': 'opt_use_iptables_restore',
}

# Line-edit widget → typed column name on the Firewall ORM object.
_LINE_EDIT_MAP: dict[str, str] = {
    'compiler': 'opt_compiler',
    'compilerArgs': 'opt_cmdline',
    'outputFileName': 'opt_output_file',
    'fileNameOnFw': 'opt_script_name_on_firewall',
    'mgmt_addr': 'opt_mgmt_addr',
    'logprefix': 'opt_log_prefix',
    'ipt_fw_dir': 'opt_firewall_dir',
    'ipt_user': 'opt_admuser',
    'altAddress': 'opt_altaddress',
    'activationCmd': 'opt_activationcmd',
    'sshArgs': 'opt_sshargs',
    'scpArgs': 'opt_scpargs',
    'installScript': 'opt_installscript',
    'installScriptArgs': 'opt_installscriptargs',
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

        # Show compiler defaults as placeholder text so the user knows
        # what value will be used when the field is left empty.
        self.ipt_fw_dir.setPlaceholderText(HOST_COMPILER_DEFAULTS['opt_firewall_dir'])
        self.ipt_fw_dir.setToolTip(
            'Directory on the firewall where the script will be installed.\n'
            f'Leave empty to use the compiler default ({HOST_COMPILER_DEFAULTS["opt_firewall_dir"]}).'
        )
        self.ipt_user.setPlaceholderText(HOST_COMPILER_DEFAULTS['opt_admuser'])
        self.ipt_user.setToolTip(
            'User account for SCP/SSH installation.\n'
            f'Leave empty to use the default ({HOST_COMPILER_DEFAULTS["opt_admuser"]}).'
        )

        self.accepted.connect(self._save_settings)

    def _disable_unsupported(self):
        """Disable widgets for options not supported by the iptables compiler."""
        for name in _UNSUPPORTED_WIDGETS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(False)

    def _populate(self):
        # Checkboxes — read directly from typed columns.
        for widget_name, col in _CHECKBOX_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            val = bool(getattr(self._fw, col))
            # acceptSessions checkbox has inverted semantics:
            if col == 'opt_accept_new_tcp_with_no_syn':
                widget.setChecked(not val)
            else:
                widget.setChecked(val)

        # Line edits — read directly from typed columns.
        for widget_name, col in _LINE_EDIT_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            widget.setText(str(getattr(self._fw, col) or ''))

        # Text edits (prolog / epilog)
        self.prolog_script.setPlainText(self._fw.opt_prolog_script or '')
        self.epilog_script.setPlainText(self._fw.opt_epilog_script or '')

        # Prolog placement combo
        place = self._fw.opt_prolog_place or HOST_COMPILER_DEFAULTS['opt_prolog_place']
        try:
            idx = _PROLOG_PLACES.index(place)
        except ValueError:
            idx = 0
        self.prologPlace.setCurrentIndex(idx)

        # LOG, ULOG, and NFLOG radio buttons
        if self._fw.opt_use_ulog:
            self.useULOG.setChecked(True)
        elif self._fw.opt_use_nflog:
            self.useNFLOG.setChecked(True)
        else:
            self.useLOG.setChecked(True)
        self._update_log_stack()

        # Log level combo
        level = self._fw.opt_log_level or ''
        idx = self.logLevel.findText(level)
        self.logLevel.setCurrentIndex(max(idx, 0))

        # Logging limit
        self.logLimitVal.setValue(self._fw.opt_limit_value or 0)

        limit_suffix = (
            self._fw.opt_limit_suffix or HOST_COMPILER_DEFAULTS['opt_limit_suffix']
        )
        idx = self.logLimitSuffix.findText(limit_suffix)
        self.logLimitSuffix.setCurrentIndex(max(idx, 0))

        # Action on reject combo
        action = self._fw.opt_action_on_reject or ''
        idx = self.actionOnReject.findText(action)
        self.actionOnReject.setCurrentIndex(max(idx, 0))

        # ULOG spin boxes
        self.cprange.setValue(self._fw.opt_ulog_cprange or 0)
        self.qthreshold.setValue(self._fw.opt_ulog_qthreshold or 1)
        self.nlgroup.setValue(self._fw.opt_ulog_nlgroup or 1)

        # IPv4 before IPv6 combo
        if (self._fw.opt_ipv4_6_order or '').lower() == 'ipv6_first':
            self.ipv4before.setCurrentIndex(1)
        else:
            self.ipv4before.setCurrentIndex(0)

    def _save_settings(self):
        # Checkboxes — write directly to typed columns.
        for widget_name, col in _CHECKBOX_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            # acceptSessions has inverted semantics.
            if col == 'opt_accept_new_tcp_with_no_syn':
                setattr(self._fw, col, not widget.isChecked())
            else:
                setattr(self._fw, col, widget.isChecked())

        # Line edits — write directly to typed columns.
        for widget_name, col in _LINE_EDIT_MAP.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            setattr(self._fw, col, widget.text())

        # Text edits
        self._fw.opt_prolog_script = self.prolog_script.toPlainText()
        self._fw.opt_epilog_script = self.epilog_script.toPlainText()

        # Prolog placement
        idx = self.prologPlace.currentIndex()
        self._fw.opt_prolog_place = (
            _PROLOG_PLACES[idx] if idx < len(_PROLOG_PLACES) else 'top'
        )

        # LOG / ULOG / NFLOG
        self._fw.opt_use_ulog = self.useULOG.isChecked()
        self._fw.opt_use_nflog = self.useNFLOG.isChecked()

        # Log options
        self._fw.opt_log_level = self.logLevel.currentText()
        self._fw.opt_limit_value = self.logLimitVal.value()
        self._fw.opt_limit_suffix = self.logLimitSuffix.currentText()
        self._fw.opt_action_on_reject = self.actionOnReject.currentText()

        # ULOG options
        self._fw.opt_ulog_cprange = self.cprange.value()
        self._fw.opt_ulog_qthreshold = self.qthreshold.value()
        self._fw.opt_ulog_nlgroup = self.nlgroup.value()

        # IPv4/IPv6 order
        self._fw.opt_ipv4_6_order = (
            'ipv6_first' if self.ipv4before.currentIndex() == 1 else 'ipv4_first'
        )

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
