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

"""Rule Options dialog for iptables policy rules."""

from pathlib import Path

from PySide6.QtWidgets import QDialog

from firewallfabrik.gui.ui_loader import FWFUiLoader

# Widget name → options key mapping.
# Combo boxes store the selected *text*; spin boxes store the *value*;
# check boxes store a boolean; line edits store a string.
_COMBO_WIDGETS = {
    'ipt_assume_fw_is_part_of_any': 'firewall_is_part_of_any_and_networks',
    'ipt_hashlimit_suffix': 'hashlimit_suffix',
    'ipt_limitSuffix': 'limit_suffix',
    'ipt_logLevel': 'log_level',
}

_CHECKBOX_WIDGETS = {
    'cb_dstip': 'hashlimit_dstip',
    'cb_dstport': 'hashlimit_dstport',
    'cb_srcip': 'hashlimit_srcip',
    'cb_srcport': 'hashlimit_srcport',
    'ipt_connlimit_above_not': 'connlimit_above_not',
    'ipt_hashlimit_dstlimit': 'hashlimit_dstlimit',
    'ipt_limit_not': 'limit_value_not',
    'ipt_stateless': 'stateless',
}

_LINEEDIT_WIDGETS = {
    'ipt_hashlimit_name': 'hashlimit_name',
    'ipt_logPrefix': 'log_prefix',
}

_SPINBOX_WIDGETS = {
    'ipt_burst': 'limit_burst',
    'ipt_connlimit': 'connlimit_value',
    'ipt_connlimit_masklen': 'connlimit_masklen',
    'ipt_hashlimit': 'hashlimit_value',
    'ipt_hashlimit_burst': 'hashlimit_burst',
    'ipt_hashlimit_expire': 'hashlimit_expire',
    'ipt_hashlimit_gcinterval': 'hashlimit_gcinterval',
    'ipt_hashlimit_max': 'hashlimit_max',
    'ipt_hashlimit_size': 'hashlimit_size',
    'ipt_limit': 'limit_value',
    'ipt_nlgroup': 'ulog_nlgroup',
}

# The combo box for "assume fw is part of any" uses index → stored value.
_FW_PART_OF_ANY_VALUES = {0: '', 1: '1', 2: '0'}
_FW_PART_OF_ANY_REVERSE = {'': 0, '1': 1, '0': 2}


class RuleOptionsDialog(QDialog):
    """Modal dialog to edit iptables rule options."""

    def __init__(self, parent, model, index):
        super().__init__(parent)
        self._model = model
        self._index = index

        ui_path = Path(__file__).resolve().parent / 'ui' / 'ruleoptionsdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self.adjustSize()

        if parent is not None:
            parent_center = parent.window().geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

        self._load_options()
        self.accepted.connect(self._save_options)

    def _load_options(self):
        """Populate widgets from the current rule options."""
        row_data = self._model.get_row_data(self._index)
        if row_data is None:
            return

        # Reconstruct options from the database.
        opts = self._read_rule_options()

        # Combo boxes.
        for widget_name, key in _COMBO_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key == 'firewall_is_part_of_any_and_networks':
                idx = _FW_PART_OF_ANY_REVERSE.get(str(opts.get(key, '')), 0)
                widget.setCurrentIndex(idx)
            else:
                val = str(opts.get(key, ''))
                idx = widget.findText(val)
                if idx >= 0:
                    widget.setCurrentIndex(idx)
                else:
                    widget.setCurrentIndex(0)

        # Check boxes.
        for widget_name, key in _CHECKBOX_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            widget.setChecked(_to_bool(opts.get(key)))

        # Line edits.
        for widget_name, key in _LINEEDIT_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            widget.setText(str(opts.get(key, '')))

        # Spin boxes.
        for widget_name, key in _SPINBOX_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            widget.setValue(_to_int(opts.get(key, 0)))

    def _save_options(self):
        """Collect values from widgets and persist to the model."""
        opts = self._read_rule_options()

        # Combo boxes.
        for widget_name, key in _COMBO_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            if key == 'firewall_is_part_of_any_and_networks':
                opts[key] = _FW_PART_OF_ANY_VALUES.get(widget.currentIndex(), '')
            else:
                opts[key] = widget.currentText()

        # Check boxes.
        for widget_name, key in _CHECKBOX_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = widget.isChecked()

        # Line edits.
        for widget_name, key in _LINEEDIT_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = widget.text()

        # Spin boxes.
        for widget_name, key in _SPINBOX_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[key] = widget.value()

        # Clean out empty/zero values to keep storage lean.
        cleaned = {}
        for k, v in opts.items():
            if v is None or v == '' or v == 0 or v is False:
                continue
            cleaned[k] = v

        self._model.set_options(self._index, cleaned)

    def _read_rule_options(self):
        """Read the full options dict from the database rule."""
        row_data = self._model.get_row_data(self._index)
        if row_data is None:
            return {}
        from firewallfabrik.core.objects import PolicyRule

        with self._model._db_manager.session() as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                return dict(rule.options or {})
        return {}


def _to_bool(val):
    """Convert a value to bool, handling string representations."""
    if isinstance(val, str):
        return val.lower() in ('true', '1')
    return bool(val)


def _to_int(val):
    """Convert a value to int, returning 0 on failure."""
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0
