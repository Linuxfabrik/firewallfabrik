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

import uuid
from pathlib import Path

from PySide6.QtWidgets import QWidget

from firewallfabrik.core._options import option_is_true
from firewallfabrik.core.objects import NATAction, PolicyAction
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

# What a Branch rule may point at.  fwbuilder resolves a policy branch
# through `Policy::TYPENAME` and a NAT branch through `NAT::TYPENAME`
# (`PolicyRule::getBranch`, `NATRule::getBranch`), so a rule set of the
# wrong kind is not a branch target at all.
_BRANCH_TARGET_TYPES = frozenset({'NAT', 'Policy'})

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

# The same, for a NAT rule: its action is a different enum in a column of
# its own, and only the branch has parameters.
_NAT_ACTION_PAGE = {
    NATAction.Branch: 'BranchChainPage',
    NATAction.Translate: 'NonePage',
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

        # The branch drop area takes a rule set and nothing else: that is
        # what a Branch rule points at.  Which kind follows from the rule
        # being edited and is set in `load_rule`.
        if hasattr(self, 'iptBranchDropArea'):
            self.iptBranchDropArea.set_helper_text('Drop a rule set here')
            self.iptBranchDropArea.set_accepted_types(_BRANCH_TARGET_TYPES)

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

            # Switch to the correct page.  A NAT rule carries its action in
            # a column of its own and in an enum of its own, so the page it
            # needs cannot be looked up with the policy one.
            page_name = self._page_for_rule(row_data)
            page = getattr(self, page_name, None)
            if page is not None and hasattr(self, 'widgetStack'):
                self.widgetStack.setCurrentWidget(page)

            if hasattr(self, 'iptBranchDropArea'):
                self.iptBranchDropArea.set_accepted_types(
                    {'NAT'} if self._is_nat_rule() else {'Policy'}
                )

            # Reject page.
            if hasattr(self, 'rejectvalue'):
                val = str(opts.get('action_on_reject', ''))
                idx = self.rejectvalue.findText(val)
                self.rejectvalue.setCurrentIndex(idx if idx >= 0 else 0)

            # Accounting page.
            if hasattr(self, 'accountingvalue_str'):
                self.accountingvalue_str.setText(
                    str(opts.get('rule_name_accounting', '')),
                )

            # Custom page.
            if hasattr(self, 'custom_str'):
                self.custom_str.setText(str(opts.get('custom_str', '')))

            # Branch page.
            if hasattr(self, 'ipt_branch_in_mangle'):
                self.ipt_branch_in_mangle.setChecked(
                    _to_bool(opts.get('ipt_branch_in_mangle')),
                )
            if hasattr(self, 'iptBranchDropArea'):
                self._load_branch_target(opts)
        finally:
            self._loading = False

    def _save_options(self):
        """Collect values from all widgets and persist via the model."""
        if self._model is None or self._index is None:
            return
        opts = self._read_rule_options()

        # Reject.
        if hasattr(self, 'rejectvalue'):
            opts['action_on_reject'] = self.rejectvalue.currentText()

        # Accounting.
        if hasattr(self, 'accountingvalue_str'):
            opts['rule_name_accounting'] = self.accountingvalue_str.text()

        # Custom.
        if hasattr(self, 'custom_str'):
            opts['custom_str'] = self.custom_str.text()

        # Branch.  The id is what identifies the rule set - the name does
        # not, because a branch may point at a rule set of another firewall
        # object and almost every one of them owns a "Policy".  The name is
        # written beside it because that is the chain the rule jumps to and
        # what the rule summary shows.
        if hasattr(self, 'ipt_branch_in_mangle'):
            opts['ipt_branch_in_mangle'] = self.ipt_branch_in_mangle.isChecked()
        if hasattr(self, 'iptBranchDropArea'):
            target_id = self.iptBranchDropArea.get_object_id()
            opts['branch_id'] = str(target_id) if target_id else ''
            opts['branch_name'] = self.iptBranchDropArea.get_object_name() or ''

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

    def _is_nat_rule(self):
        """Whether the rule being edited belongs to a NAT rule set."""
        return getattr(self._model, 'rule_set_type', '') == 'NAT'

    def _page_for_rule(self, row_data):
        """Return the name of the stacked-widget page this rule needs."""
        if row_data is None:
            return 'NonePage'
        if self._is_nat_rule():
            try:
                nat_action = NATAction(row_data.nat_action_int)
            except (TypeError, ValueError):
                return 'NonePage'
            return _NAT_ACTION_PAGE.get(nat_action, 'NonePage')
        try:
            action = PolicyAction(row_data.action_int)
        except (TypeError, ValueError):
            action = PolicyAction.Accept
        return _ACTION_PAGE.get(action, 'NonePage')

    def _load_branch_target(self, opts):
        """Show the rule set the branch points at, or clear the area.

        The stored value is the rule set's id.  A file written before the
        reference was resolved carries the Firewall Builder XML id there,
        which resolves to nothing; the name beside it is then all there is
        and the area stays empty rather than showing something that is not
        the target.
        """
        from firewallfabrik.core.objects import RuleSet

        ref = str(opts.get('branch_id') or '')
        target = None
        if ref and self._model is not None:
            try:
                target_id = uuid.UUID(ref)
            except ValueError:
                target_id = None
            if target_id is not None:
                with self._model._db_manager.session() as session:
                    rule_set = session.get(RuleSet, target_id)
                    if rule_set is not None:
                        target = (rule_set.id, rule_set.name, rule_set.type)
        if target is None:
            self.iptBranchDropArea.delete_object()
        else:
            self.iptBranchDropArea.insert_object(*target)

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
        from firewallfabrik.core.objects import Rule

        # `Rule`, not `PolicyRule`: the panel is opened for a NAT rule too,
        # and asking for the wrong subclass answers None - the options then
        # read as empty and the next save writes that emptiness back over
        # everything the rule carries.
        with self._model._db_manager.session() as session:
            rule = session.get(Rule, row_data.rule_id)
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
        if hasattr(self, 'iptBranchDropArea'):
            self.iptBranchDropArea.objectInserted.connect(self._on_widget_changed)
            self.iptBranchDropArea.objectDeleted.connect(self._on_widget_changed)
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
        if hasattr(self, 'iptBranchDropArea'):
            self.iptBranchDropArea.objectInserted.disconnect(self._on_widget_changed)
            self.iptBranchDropArea.objectDeleted.disconnect(self._on_widget_changed)
        self._signals_connected = False


def _to_bool(val):
    """Convert a value to bool, handling string representations."""
    if isinstance(val, str):
        return option_is_true(val)
    return bool(val)
