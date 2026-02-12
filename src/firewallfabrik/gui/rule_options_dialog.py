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

"""Rule Options editor panel for iptables policy rules."""

import uuid
from pathlib import Path

from PySide6.QtWidgets import QWidget

from firewallfabrik.gui.ui_loader import FWFUiLoader

# Widget name → options key mapping.
# Combo boxes store the selected *text*; spin boxes store the *value*;
# check boxes store a boolean; line edits store a string.
_CHECKBOX_WIDGETS = {
    'cb_dstip': 'hashlimit_dstip',
    'cb_dstport': 'hashlimit_dstport',
    'cb_srcip': 'hashlimit_srcip',
    'cb_srcport': 'hashlimit_srcport',
    'ipt_connlimit_above_not': 'connlimit_above_not',
    'ipt_continue': 'ipt_continue',
    'ipt_hashlimit_dstlimit': 'hashlimit_dstlimit',
    'ipt_limit_not': 'limit_value_not',
    'ipt_mark_connections': 'ipt_mark_connections',
    'ipt_stateless': 'stateless',
    'ipt_tee': 'ipt_tee',
}

_COMBO_WIDGETS = {
    'ipt_assume_fw_is_part_of_any': 'firewall_is_part_of_any_and_networks',
    'ipt_hashlimit_suffix': 'hashlimit_suffix',
    'ipt_iif': 'ipt_iif',
    'ipt_limitSuffix': 'limit_suffix',
    'ipt_logLevel': 'log_level',
    'ipt_oif': 'ipt_oif',
}

_LINEEDIT_WIDGETS = {
    'classify_str': 'classify_str',
    'ipt_gw': 'ipt_gw',
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


class RuleOptionsPanel(QWidget):
    """Editor-pane widget for iptables rule options (non-modal)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        ui_path = Path(__file__).resolve().parent / 'ui' / 'ruleoptionsdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._model = None
        self._index = None
        self._rule_id = None
        self._loading = False
        self._signals_connected = False

        # Route tab interaction: "Continue" disables iif and tee.
        if hasattr(self, 'ipt_continue'):
            self.ipt_continue.toggled.connect(self._on_continue_toggled)

    def load_rule(self, model, index):
        """Populate the panel from the rule at *index*."""
        self._disconnect_signals()
        self._model = model
        self._index = index
        row_data = model.get_row_data(index)
        self._rule_id = row_data.rule_id if row_data is not None else None
        self._load_options()
        self._connect_signals()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_options(self):
        """Read options from the database and populate all widgets."""
        self._loading = True
        try:
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

            # Tag drop area.
            drop = getattr(self, 'iptTagDropArea', None)
            if drop is not None:
                drop.delete_object()
                tag_id = opts.get('tagobject_id', '')
                if tag_id:
                    self._load_tag_object(drop, tag_id)

            # Apply Route-tab interaction state.
            self._apply_continue_state()
        finally:
            self._loading = False

    def _save_options(self):
        """Collect values from all widgets and persist via the model."""
        if self._model is None or self._index is None:
            return
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

        # Tag drop area.
        drop = getattr(self, 'iptTagDropArea', None)
        if drop is not None:
            tag_obj_id = drop.get_object_id()
            if tag_obj_id is not None:
                opts['tagobject_id'] = str(tag_obj_id)
                opts['tagging'] = True
            else:
                opts.pop('tagobject_id', None)
                opts.pop('tagging', None)

        # Clean out empty/zero/false values to keep storage lean.
        cleaned = {}
        for k, v in opts.items():
            if v is None or v == '' or v == 0 or v is False:
                continue
            cleaned[k] = v

        self._model.set_options(self._index, cleaned)
        # set_options() calls reload(), invalidating all QModelIndex objects.
        # Re-resolve so subsequent saves use a valid index.
        if self._rule_id is not None:
            self._index = self._model.index_for_rule(self._rule_id)

    def _on_widget_changed(self):
        """Auto-save whenever any widget value changes."""
        if self._loading:
            return
        self._save_options()

    def _on_continue_toggled(self, checked):
        """Disable ipt_iif and ipt_tee when 'Continue' is checked."""
        self._apply_continue_state()
        if checked:
            iif = getattr(self, 'ipt_iif', None)
            if iif is not None:
                iif.setCurrentIndex(0)
            tee = getattr(self, 'ipt_tee', None)
            if tee is not None:
                tee.setChecked(False)
        self._on_widget_changed()

    def _load_tag_object(self, drop, tag_id):
        """Populate the tag drop area from the stored object id."""
        from firewallfabrik.core.objects import Service

        try:
            obj_uuid = uuid.UUID(tag_id)
        except (TypeError, ValueError):
            return
        with self._model._db_manager.session() as session:
            obj = session.get(Service, obj_uuid)
            if obj is not None:
                drop.insert_object(obj.id, obj.name, obj.type)

    def _apply_continue_state(self):
        """Apply the enabled/disabled state based on ipt_continue."""
        cont = getattr(self, 'ipt_continue', None)
        if cont is None:
            return
        disabled = cont.isChecked()
        iif = getattr(self, 'ipt_iif', None)
        if iif is not None:
            iif.setEnabled(not disabled)
        tee = getattr(self, 'ipt_tee', None)
        if tee is not None:
            tee.setEnabled(not disabled)

    def _read_rule_options(self):
        """Read the full options dict from the database rule."""
        if self._model is None or self._index is None:
            return {}
        row_data = self._model.get_row_data(self._index)
        if row_data is None:
            return {}
        from firewallfabrik.core.objects import PolicyRule

        with self._model._db_manager.session() as session:
            rule = session.get(PolicyRule, row_data.rule_id)
            if rule is not None:
                return dict(rule.options or {})
        return {}

    # ------------------------------------------------------------------
    # Signal management
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect change signals on all widgets to auto-save."""
        if self._signals_connected:
            return
        for widget_name in _COMBO_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.currentIndexChanged.connect(self._on_widget_changed)

        for widget_name in _CHECKBOX_WIDGETS:
            if widget_name == 'ipt_continue':
                continue  # Handled by dedicated slot.
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.toggled.connect(self._on_widget_changed)

        for widget_name in _LINEEDIT_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.editingFinished.connect(self._on_widget_changed)

        for widget_name in _SPINBOX_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.valueChanged.connect(self._on_widget_changed)

        drop = getattr(self, 'iptTagDropArea', None)
        if drop is not None:
            drop.objectInserted.connect(self._on_widget_changed)
            drop.objectDeleted.connect(self._on_widget_changed)

        self._signals_connected = True

    def _disconnect_signals(self):
        """Disconnect all change signals to avoid stale callbacks."""
        if not self._signals_connected:
            return
        for widget_name in _COMBO_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.currentIndexChanged.disconnect(self._on_widget_changed)

        for widget_name in _CHECKBOX_WIDGETS:
            if widget_name == 'ipt_continue':
                continue
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.toggled.disconnect(self._on_widget_changed)

        for widget_name in _LINEEDIT_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.editingFinished.disconnect(self._on_widget_changed)

        for widget_name in _SPINBOX_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.valueChanged.disconnect(self._on_widget_changed)

        drop = getattr(self, 'iptTagDropArea', None)
        if drop is not None:
            drop.objectInserted.disconnect(self._on_widget_changed)
            drop.objectDeleted.disconnect(self._on_widget_changed)

        self._signals_connected = False


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
