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

"""Action parameters editor panel for iptables policy rules."""

from pathlib import Path

from PySide6.QtWidgets import QWidget

from firewallfabrik.core.objects import PolicyAction
from firewallfabrik.core.options import RuleOption
from firewallfabrik.gui.ui_loader import FWFUiLoader

# Reject type combo box items: (display_text, stored_value).
# The stored value is saved in options['action_on_reject'].
_REJECT_ITEMS = (
    ('', ''),
    ('ICMP admin prohibited', 'ICMP admin prohibited'),
    ('ICMP host prohibited', 'ICMP host prohibited'),
    ('ICMP host unreachable', 'ICMP host unreachable'),
    ('ICMP net prohibited', 'ICMP net prohibited'),
    ('ICMP net unreachable', 'ICMP net unreachable'),
    ('ICMP port unreachable', 'ICMP port unreachable'),
    ('ICMP protocol unreachable', 'ICMP protocol unreachable'),
    ('TCP RST', 'TCP RST'),
)

# Map action enum → stacked-widget page name.
_ACTION_PAGE = {
    PolicyAction.Accept: 'NonePage',
    PolicyAction.Accounting: 'AccountingStrPage',
    PolicyAction.Branch: 'BranchChainPage',
    PolicyAction.Continue: 'NonePage',
    PolicyAction.Custom: 'CustomStrPage',
    PolicyAction.Deny: 'NonePage',
    PolicyAction.Pipe: 'NonePage',
    PolicyAction.Reject: 'RejectPage',
}


class ActionsPanel(QWidget):
    """Editor-pane widget for action parameters (non-modal)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        ui_path = Path(__file__).resolve().parent / 'ui' / 'actionsdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self._model = None
        self._index = None
        self._rule_id = None
        self._loading = False
        self._signals_connected = False

        # Populate reject combo box.
        if hasattr(self, 'rejectvalue'):
            self.rejectvalue.clear()
            for display, _stored in _REJECT_ITEMS:
                self.rejectvalue.addItem(display)

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
            row_data = self._get_row_data()
            action_int = row_data.action_int if row_data is not None else 0

            # Switch to the correct page.
            try:
                action = PolicyAction(action_int)
            except (TypeError, ValueError):
                action = PolicyAction.Accept
            page_name = _ACTION_PAGE.get(action, 'NonePage')
            page = getattr(self, page_name, None)
            if page is not None and hasattr(self, 'widgetStack'):
                self.widgetStack.setCurrentWidget(page)

            # Reject page.
            if hasattr(self, 'rejectvalue'):
                val = str(opts.get(RuleOption.ACTION_ON_REJECT, ''))
                idx = self.rejectvalue.findText(val)
                self.rejectvalue.setCurrentIndex(idx if idx >= 0 else 0)

            # Accounting page.
            if hasattr(self, 'accountingvalue_str'):
                self.accountingvalue_str.setText(
                    str(opts.get(RuleOption.RULE_NAME_ACCOUNTING, '')),
                )

            # Custom page.
            if hasattr(self, 'custom_str'):
                self.custom_str.setText(str(opts.get(RuleOption.CUSTOM_STR, '')))

            # Branch page.
            if hasattr(self, 'ipt_branch_in_mangle'):
                self.ipt_branch_in_mangle.setChecked(
                    _to_bool(opts.get(RuleOption.IPT_BRANCH_IN_MANGLE)),
                )
        finally:
            self._loading = False

    def _save_options(self):
        """Collect values from all widgets and persist via the model."""
        if self._model is None or self._index is None:
            return
        opts = self._read_rule_options()

        # Reject.
        if hasattr(self, 'rejectvalue'):
            opts[RuleOption.ACTION_ON_REJECT] = self.rejectvalue.currentText()

        # Accounting.
        if hasattr(self, 'accountingvalue_str'):
            opts[RuleOption.RULE_NAME_ACCOUNTING] = self.accountingvalue_str.text()

        # Custom.
        if hasattr(self, 'custom_str'):
            opts[RuleOption.CUSTOM_STR] = self.custom_str.text()

        # Branch.
        if hasattr(self, 'ipt_branch_in_mangle'):
            opts[RuleOption.IPT_BRANCH_IN_MANGLE] = (
                self.ipt_branch_in_mangle.isChecked()
            )

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

    def _get_row_data(self):
        """Return the row data for the current index."""
        if self._model is None or self._index is None:
            return None
        return self._model.get_row_data(self._index)

    def _read_rule_options(self):
        """Read the full options dict from the database rule."""
        if self._model is None or self._index is None:
            return {}
        row_data = self._get_row_data()
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
        if hasattr(self, 'rejectvalue'):
            self.rejectvalue.currentIndexChanged.connect(self._on_widget_changed)
        if hasattr(self, 'accountingvalue_str'):
            self.accountingvalue_str.editingFinished.connect(self._on_widget_changed)
        if hasattr(self, 'custom_str'):
            self.custom_str.editingFinished.connect(self._on_widget_changed)
        if hasattr(self, 'ipt_branch_in_mangle'):
            self.ipt_branch_in_mangle.toggled.connect(self._on_widget_changed)
        self._signals_connected = True

    def _disconnect_signals(self):
        """Disconnect all change signals to avoid stale callbacks."""
        if not self._signals_connected:
            return
        if hasattr(self, 'rejectvalue'):
            self.rejectvalue.currentIndexChanged.disconnect(self._on_widget_changed)
        if hasattr(self, 'accountingvalue_str'):
            self.accountingvalue_str.editingFinished.disconnect(
                self._on_widget_changed,
            )
        if hasattr(self, 'custom_str'):
            self.custom_str.editingFinished.disconnect(self._on_widget_changed)
        if hasattr(self, 'ipt_branch_in_mangle'):
            self.ipt_branch_in_mangle.toggled.disconnect(self._on_widget_changed)
        self._signals_connected = False


def _to_bool(val):
    """Convert a value to bool, handling string representations."""
    if isinstance(val, str):
        return val.lower() in ('true', '1')
    return bool(val)
