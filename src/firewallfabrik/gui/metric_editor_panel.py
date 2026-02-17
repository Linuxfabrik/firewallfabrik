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

"""Metric editor panel for iptables routing rules."""

from pathlib import Path

from PySide6.QtWidgets import QWidget

from firewallfabrik.gui.ui_loader import FWFUiLoader


class MetricEditorPanel(QWidget):
    """Editor-pane widget for routing rule metric (non-modal)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        ui_path = Path(__file__).resolve().parent / 'ui' / 'metriceditorpanel_q.ui'
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
        self._load_metric()
        self._connect_signals()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_metric(self):
        """Read metric from the model and populate the spin box."""
        self._loading = True
        try:
            row_data = (
                self._model.get_row_data(self._index)
                if self._model is not None and self._index is not None
                else None
            )
            value = row_data.metric if row_data is not None else 0
            self.spin_box.setValue(value)
        finally:
            self._loading = False

    def _save_metric(self):
        """Persist the current spin box value via the model."""
        if self._model is None or self._index is None:
            return
        self._model.set_metric(self._index, self.spin_box.value())
        # set_metric() calls reload(), invalidating all QModelIndex objects.
        # Re-resolve so subsequent saves use a valid index.
        if self._rule_id is not None:
            self._index = self._model.index_for_rule(self._rule_id)

    def _on_value_changed(self):
        """Auto-save whenever the spin box value changes."""
        if self._loading:
            return
        self._save_metric()

    # ------------------------------------------------------------------
    # Signal management
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect change signals on the spin box to auto-save."""
        if self._signals_connected:
            return
        self.spin_box.valueChanged.connect(self._on_value_changed)
        self._signals_connected = True

    def _disconnect_signals(self):
        """Disconnect all change signals to avoid stale callbacks."""
        if not self._signals_connected:
            return
        self.spin_box.valueChanged.disconnect(self._on_value_changed)
        self._signals_connected = False
