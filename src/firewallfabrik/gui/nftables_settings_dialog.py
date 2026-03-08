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
from PySide6.QtWidgets import QDialog, QLineEdit

from firewallfabrik.gui.ui_loader import FWFUiLoader
from firewallfabrik.platforms._defaults import get_platform_defaults

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'nftablessettingsdialog_q.ui'

# Load the full option schema once at import time.
_SCHEMA = get_platform_defaults('nftables')

# Build widget → canonical key maps from the YAML schema.
_CHECKBOX_MAP: dict[str, str] = {}
_LINE_EDIT_MAP: dict[str, str] = {}
_UNSUPPORTED_WIDGETS: list[str] = []

for _key, _entry in _SCHEMA.items():
    _widget = _entry.get('widget')
    if not _widget:
        continue
    _typ = _entry['type']
    if _typ == 'bool':
        _CHECKBOX_MAP[_widget] = _key
    elif _typ == 'str':
        _LINE_EDIT_MAP[_widget] = _key
    if not _entry.get('supported', True):
        _UNSUPPORTED_WIDGETS.append(_widget)

# Additional non-widget UI elements to disable for unsupported options.
_UNSUPPORTED_WIDGETS.extend(['textLabel6'])


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

        # Populate combo boxes from YAML schema values.
        self.actionOnReject.addItems(
            _SCHEMA['action_on_reject'].get('values', []),
        )
        self.logLevel.addItems(_SCHEMA['log_level'].get('values', []))
        self.logLimitSuffix.addItems(
            _SCHEMA['limit_suffix'].get('values', []),
        )

        self._apply_tooltips()
        self._apply_placeholders()
        self._populate()
        self._disable_unsupported()
        self.accepted.connect(self._save_settings)

    def _apply_tooltips(self):
        """Set tooltip text on every widget from the YAML descriptions."""
        for entry in _SCHEMA.values():
            widget_name = entry.get('widget')
            if not widget_name:
                continue
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.setToolTip(entry.get('description', ''))

    def _apply_placeholders(self):
        """Set placeholder text on QLineEdits showing the YAML default."""
        for entry in _SCHEMA.values():
            if entry['type'] != 'str':
                continue
            widget_name = entry.get('widget')
            if not widget_name:
                continue
            widget = getattr(self, widget_name, None)
            if isinstance(widget, QLineEdit):
                text = entry.get('placeholder') or entry.get('default', '')
                if text:
                    widget.setPlaceholderText(str(text))

    def _disable_unsupported(self):
        """Disable widgets for options not supported by the nftables compiler."""
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
            entry = _SCHEMA.get(key, {})
            default = entry.get('default', False)
            if key in opts:
                val = str(opts[key]).lower() == 'true'
            elif widget_name in opts:
                val = str(opts[widget_name]).lower() == 'true'
            else:
                val = bool(default)
            # acceptSessions checkbox has inverted semantics:
            if entry.get('inverted', False):
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
        prolog_values = _SCHEMA['prolog_place'].get('values', ['top'])
        place = opts.get('prolog_place', _SCHEMA['prolog_place']['default'])
        try:
            idx = prolog_values.index(place)
        except ValueError:
            idx = 0
        self.prologPlace.setCurrentIndex(idx)

        # LOG / NFLOG radio buttons (legacy use_ULOG falls back to LOG)
        if str(opts.get('use_NFLOG', '')).lower() == 'true':
            self.useNFLOG.setChecked(True)
        else:
            self.useLOG.setChecked(True)
        self._update_log_stack()

        # Log level combo
        level = opts.get('log_level', _SCHEMA['log_level']['default'])
        idx = self.logLevel.findText(level)
        self.logLevel.setCurrentIndex(max(idx, 0))

        # Logging limit
        default_limit = _SCHEMA['limit_value']['default']
        limit_val = opts.get('limit_value', default_limit)
        try:
            self.logLimitVal.setValue(int(limit_val))
        except (ValueError, TypeError):
            self.logLimitVal.setValue(int(default_limit))

        default_suffix = _SCHEMA['limit_suffix']['default']
        limit_suffix = opts.get('limit_suffix', default_suffix)
        idx = self.logLimitSuffix.findText(limit_suffix)
        self.logLimitSuffix.setCurrentIndex(max(idx, 0))

        # Action on reject combo
        action = opts.get('action_on_reject', '')
        idx = self.actionOnReject.findText(action)
        self.actionOnReject.setCurrentIndex(max(idx, 0))

        # NFLOG spin boxes
        self.cprange.setValue(
            int(opts.get('ulog_cprange', _SCHEMA['ulog_cprange']['default'])),
        )
        self.qthreshold.setValue(
            int(
                opts.get('ulog_qthreshold', _SCHEMA['ulog_qthreshold']['default']),
            ),
        )
        self.nlgroup.setValue(
            int(opts.get('ulog_nlgroup', _SCHEMA['ulog_nlgroup']['default'])),
        )

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
            entry = _SCHEMA.get(key, {})
            # Store as Python bool (not string) so that raw
            # ``options.get(key, False)`` in the compiler works correctly.
            if entry.get('inverted', False):
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
        prolog_values = _SCHEMA['prolog_place'].get('values', ['top'])
        idx = self.prologPlace.currentIndex()
        opts['prolog_place'] = prolog_values[idx] if idx < len(prolog_values) else 'top'

        # LOG / NFLOG
        opts['use_ULOG'] = False
        opts['use_NFLOG'] = self.useNFLOG.isChecked()

        # Log options
        opts['log_level'] = self.logLevel.currentText()
        opts['limit_value'] = str(self.logLimitVal.value())
        opts['limit_suffix'] = self.logLimitSuffix.currentText()
        opts['action_on_reject'] = self.actionOnReject.currentText()

        # NFLOG options
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
    def switchLogTarget(self):
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
