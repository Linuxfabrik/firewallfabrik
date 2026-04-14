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

from PySide6.QtWidgets import QDialog, QLineEdit

from firewallfabrik.gui.ui_loader import FWFUiLoader
from firewallfabrik.platforms._defaults import get_os_defaults

_UI_PATH = Path(__file__).resolve().parent / 'ui' / 'linuxsettingsdialog_q.ui'

# Load the full option schema once at import time.
_SCHEMA = get_os_defaults('linux24')

# Build typed widget maps from the YAML schema.
# canonical_key → widget_name (widget may differ from canonical key)
_COMBOS: dict[str, str] = {}
_SPINBOXES: dict[str, str] = {}
_LINE_EDITS: dict[str, str] = {}
_NFTABLES_UNSUPPORTED_WIDGETS: list[str] = []
_NFTABLES_UNSUPPORTED_LABELS: list[str] = []

for _key, _entry in _SCHEMA.items():
    _widget = _entry.get('widget')
    if not _widget:
        continue
    _typ = _entry['type']
    if _typ == 'tristate':
        _COMBOS[_key] = _widget
    elif _typ == 'int':
        _SPINBOXES[_key] = _widget
    elif _typ == 'str':
        _LINE_EDITS[_key] = _widget
    if not _entry.get('nftables_supported', True):
        _NFTABLES_UNSUPPORTED_WIDGETS.append(_widget)
        _label = _entry.get('label')
        if _label:
            _NFTABLES_UNSUPPORTED_LABELS.append(_label)

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

        self._apply_tooltips()
        self._apply_placeholders()
        self._populate()
        if platform == 'nftables':
            self._disable_for_nftables()
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
        """Set placeholder text on QLineEdits from the YAML ``placeholder``.

        Only schema entries that explicitly declare a ``placeholder`` key
        produce hint text. The ``default`` value is used at compile/
        install time, not as a hint in the dialog — otherwise empty
        fields look pre-filled in Qt's muted placeholder colour and are
        easily mistaken for disabled fields.
        """
        for entry in _SCHEMA.values():
            if entry['type'] != 'str':
                continue
            widget_name = entry.get('widget')
            if not widget_name:
                continue
            widget = getattr(self, widget_name, None)
            if isinstance(widget, QLineEdit):
                text = entry.get('placeholder', '')
                if text:
                    widget.setPlaceholderText(str(text))

    def _disable_for_nftables(self):
        """Disable widgets that are not supported by the nftables compiler."""
        for name in _NFTABLES_UNSUPPORTED_WIDGETS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(False)
        for name in _NFTABLES_UNSUPPORTED_LABELS:
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setEnabled(False)

        # Disable entire tabs: TCP (1), Path (2), conntrack (3), Data (4).
        for idx in (1, 2, 3, 4):
            self.tabWidget.setTabEnabled(idx, False)

    def _populate(self):
        opts = self._fw.options or {}

        # Combo boxes
        for key, widget_name in _COMBOS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            # Read canonical key first, fall back to widget name for
            # backward compat, then to YAML default.
            if key in opts:
                val = opts[key]
            elif widget_name in opts and widget_name != key:
                val = opts[widget_name]
            else:
                val = _SCHEMA[key]['default']
            text = _VALUE_TO_COMBO_TEXT.get(str(val), 'No change')
            idx = widget.findText(text)
            widget.setCurrentIndex(max(idx, 0))

        # Spin boxes
        for key, widget_name in _SPINBOXES.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key in opts:
                raw = opts[key]
            elif widget_name in opts and widget_name != key:
                raw = opts[widget_name]
            else:
                raw = _SCHEMA[key]['default']
            try:
                widget.setValue(int(raw))
            except (ValueError, TypeError):
                widget.setValue(int(_SCHEMA[key]['default']))

        # Line edits
        for key, widget_name in _LINE_EDITS.items():
            widget = getattr(self, widget_name, None)
            if widget is not None:
                if key in opts:
                    widget.setText(opts[key])
                elif widget_name in opts and widget_name != key:
                    widget.setText(opts[widget_name])
                else:
                    widget.setText('')

    def _save_settings(self):
        opts = dict(self._fw.options or {})

        # Combo boxes — always write under canonical key.
        for key, widget_name in _COMBOS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = _COMBO_TEXT_TO_VALUE.get(widget.currentText(), '')
            # Clean up stale widget-name key.
            if widget_name != key:
                opts.pop(widget_name, None)

        # Spin boxes — always write under canonical key.
        for key, widget_name in _SPINBOXES.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = str(widget.value())
            if widget_name != key:
                opts.pop(widget_name, None)

        # Line edits — always write under canonical key.
        for key, widget_name in _LINE_EDITS.items():
            widget = getattr(self, widget_name, None)
            if widget is not None:
                opts[key] = widget.text()
                if widget_name != key:
                    opts.pop(widget_name, None)

        # Reassign to trigger SQLAlchemy JSON mutation detection.
        self._fw.options = opts
