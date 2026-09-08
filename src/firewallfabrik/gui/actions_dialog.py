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
from firewallfabrik.gui.platform_settings import get_enabled_platforms
from firewallfabrik.gui.ui_loader import FWFUiLoader
from firewallfabrik.platforms.linux._netfilter import (
    CUSTOM_ACTION_LEGACY_OPTION,
    CUSTOM_ACTION_OPTION,
    custom_action_is_iptables_syntax,
)

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
        # One Custom action statement per packet filter, kept here while
        # the panel is open so switching the combo does not lose the one
        # that is no longer shown.  Same shape as the Custom Service
        # editor's per-platform code map.
        self._custom_statements: dict[str, str] = {}
        self._custom_platform = ''

        # The branch drop area takes a rule set and nothing else: that is
        # what a Branch rule points at.  Which kind follows from the rule
        # being edited and is set in `load_rule`.
        if hasattr(self, 'iptBranchDropArea'):
            self.iptBranchDropArea.set_helper_text('Drop a rule set here')
            self.iptBranchDropArea.set_accepted_types(_BRANCH_TARGET_TYPES)

        # The Custom action platform combo.  It is filled once: which
        # packet filters exist is a preference, not a property of the rule.
        if hasattr(self, 'custom_str_platform'):
            self.custom_str_platform.clear()
            for key, display in sorted(
                get_enabled_platforms().items(), key=lambda t: t[1].casefold()
            ):
                self.custom_str_platform.addItem(display, key)

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
                is_nat = self._is_nat_rule()
                self.iptBranchDropArea.set_accepted_types(
                    {'NAT'} if is_nat else {'Policy'}
                )
                # fwbuilder's own dialog is policy-only - it hardcodes
                # `addAcceptedTypes("Policy")` and has the NAT line
                # commented out (ActionsDialog.cpp:72) - so its label can
                # say "Policy" and be right.  This panel is opened for a
                # NAT rule as well, and a NAT rule branches into a NAT rule
                # set, so the label has to say which kind is meant.
                if hasattr(self, 'textLabel1_3'):
                    self.textLabel1_3.setText(
                        'NAT ruleset object:' if is_nat else 'Policy ruleset object:'
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
                self._load_custom_statements(opts)

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

        # Custom.  Both statements are written, and the platform-less
        # field a Firewall Builder file carries is dropped: it has been
        # read into the map for the platform whose syntax it is in, so
        # keeping it beside the two would be a third answer to the same
        # question.
        if hasattr(self, 'custom_str') and self._custom_platform:
            self._save_current_custom_statement()
            for platform, statement in self._custom_statements.items():
                opts[CUSTOM_ACTION_OPTION.format(platform=platform)] = statement
            opts[CUSTOM_ACTION_LEGACY_OPTION] = ''
        elif hasattr(self, 'custom_str'):
            opts[CUSTOM_ACTION_LEGACY_OPTION] = self.custom_str.text()

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

    def _load_custom_statements(self, opts):
        """Fill the per-platform map and show the firewall's own platform.

        A rule written before the field was split carries one statement
        under `custom_str` and nothing says which syntax it is in, so it is
        read off the text: an iptables target begins with a `-`.  Reading
        it into the right half is what keeps such a rule compiling after
        the first save from this panel, which drops the old key.
        """
        legacy = str(opts.get(CUSTOM_ACTION_LEGACY_OPTION, '') or '')
        if not hasattr(self, 'custom_str_platform'):
            # No combo means no per-platform field to fill; the panel then
            # edits the platform-less statement the way it always did.
            self._custom_statements = {}
            self._custom_platform = ''
            self.custom_str.setText(legacy)
            return
        legacy_platform = (
            'iptables' if custom_action_is_iptables_syntax(legacy) else 'nftables'
        )
        self._custom_statements = {}
        for index in range(self.custom_str_platform.count()):
            platform = self.custom_str_platform.itemData(index)
            stored = str(
                opts.get(CUSTOM_ACTION_OPTION.format(platform=platform), '') or ''
            )
            if not stored and legacy.strip() and platform == legacy_platform:
                stored = legacy
            self._custom_statements[platform] = stored

        # The rule belongs to one firewall and that firewall compiles for
        # one packet filter, so that is the half the administrator means.
        wanted = self._firewall_platform()
        index = self.custom_str_platform.findData(wanted) if wanted else -1
        if index < 0:
            index = self.custom_str_platform.findData('nftables')
        if index >= 0:
            self.custom_str_platform.setCurrentIndex(index)
        self._custom_platform = self.custom_str_platform.currentData() or ''
        self.custom_str.setText(self._custom_statements.get(self._custom_platform, ''))

    def _save_current_custom_statement(self):
        """Take what is in the field into the map of the shown platform."""
        if self._custom_platform:
            self._custom_statements[self._custom_platform] = self.custom_str.text()

    def _on_custom_platform_changed(self, _index):
        """Keep the statement of the platform being left, show the other."""
        if self._loading:
            return
        self._save_current_custom_statement()
        self._custom_platform = self.custom_str_platform.currentData() or ''
        self.custom_str.setText(self._custom_statements.get(self._custom_platform, ''))

    def _firewall_platform(self) -> str:
        """The packet filter the firewall owning this rule set compiles for."""
        from firewallfabrik.core.objects import Firewall, RuleSet

        if self._model is None:
            return ''
        rule_set_id = getattr(self._model, 'rule_set_id', None)
        if rule_set_id is None:
            return ''
        with self._model._db_manager.session() as session:
            rule_set = session.get(RuleSet, rule_set_id)
            device = getattr(rule_set, 'device', None) if rule_set else None
            if isinstance(device, Firewall):
                return device.platform or ''
        return ''

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
        if hasattr(self, 'custom_str_platform'):
            self.custom_str_platform.currentIndexChanged.connect(
                self._on_custom_platform_changed
            )
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
        if hasattr(self, 'custom_str_platform'):
            self.custom_str_platform.currentIndexChanged.disconnect(
                self._on_custom_platform_changed
            )
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
