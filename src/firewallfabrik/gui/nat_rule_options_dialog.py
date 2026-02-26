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

"""NAT Rule Options editor panel for iptables NAT rules."""

from pathlib import Path

from PySide6.QtWidgets import QWidget

from firewallfabrik.gui.ui_loader import FWFUiLoader

# Widget name → typed column name on the Rule ORM object.
_CHECKBOX_WIDGETS = {
    'ipt_nat_persistent': 'opt_ipt_nat_persistent',
    'ipt_nat_random': 'opt_ipt_nat_random',
    'ipt_use_masq': 'opt_ipt_use_masq',
    'ipt_use_snat_instead_of_masq': 'opt_ipt_use_snat_instead_of_masq',
}


class NATRuleOptionsPanel(QWidget):
    """Editor-pane widget for iptables NAT rule options (non-modal)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        ui_path = Path(__file__).resolve().parent / 'ui' / 'natruleoptionsdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._model = None
        self._index = None
        self._rule_id = None
        self._loading = False
        self._signals_connected = False

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
            rule = self._get_rule()

            for widget_name, col in _CHECKBOX_WIDGETS.items():
                widget = getattr(self, widget_name, None)
                if widget is None:
                    continue
                widget.setChecked(getattr(rule, col, False) if rule else False)
        finally:
            self._loading = False

    def _save_options(self):
        """Collect values from all widgets and persist via the model."""
        if self._model is None or self._index is None:
            return
        opts = {}

        for widget_name, col in _CHECKBOX_WIDGETS.items():
            widget = getattr(self, widget_name, None)
            if widget is None:
                continue
            opts[col] = widget.isChecked()

        self._model.set_options(self._index, opts)
        # set_options() calls reload(), invalidating all QModelIndex objects.
        # Re-resolve so subsequent saves use a valid index.
        if self._rule_id is not None:
            self._index = self._model.index_for_rule(self._rule_id)

    def _on_widget_changed(self):
        """Auto-save whenever any widget value changes."""
        if self._loading:
            return
        self._save_options()

    def _get_rule(self):
        """Return the ORM NATRule object for the current index, or None."""
        if self._model is None or self._index is None:
            return None
        row_data = self._model.get_row_data(self._index)
        if row_data is None:
            return None
        from firewallfabrik.core.objects import NATRule

        with self._model._db_manager.session() as session:
            return session.get(NATRule, row_data.rule_id)

    # ------------------------------------------------------------------
    # Signal management
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect change signals on all widgets to auto-save."""
        if self._signals_connected:
            return
        for widget_name in _CHECKBOX_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.toggled.connect(self._on_widget_changed)
        self._signals_connected = True

    def _disconnect_signals(self):
        """Disconnect all change signals to avoid stale callbacks."""
        if not self._signals_connected:
            return
        for widget_name in _CHECKBOX_WIDGETS:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                widget.toggled.disconnect(self._on_widget_changed)
        self._signals_connected = False
