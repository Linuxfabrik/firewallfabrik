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

"""The three layers a Branch rule needs in the editor (issue #90).

The rule set a branch jumps into is chosen by dragging it out of the
object tree onto the drop area of the action's Parameters page.  That
needs the tree to hand a rule set out as a drag source, the drop area to
take one and refuse everything else, and the panel to write the reference
back onto the rule.  Two of the three were missing, so the action existed
in the data model and could not be set in the editor at all.

A GUI workflow with no test is a workflow that has never run - File >
Import Library shipped in that state (#150) - so the parts that can be
exercised without a window are exercised here.
"""

import os

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from firewallfabrik.core.objects import NATAction, PolicyAction
from firewallfabrik.gui.object_tree_data import NON_DRAGGABLE_TYPES
from firewallfabrik.gui.policy_context_menu import (
    ACTION_MENU_ENTRIES,
    ACTIONS_WITH_PARAMS,
    NAT_ACTION_MENU_ENTRIES,
    VALID_TYPES_BY_SLOT,
)


@pytest.fixture(scope='module')
def qt_app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize('rule_set_type', ('NAT', 'Policy', 'Routing'))
def test_a_rule_set_can_be_dragged_out_of_the_tree(rule_set_type):
    """It is the drag source the branch drop area waits for (#83)."""
    assert rule_set_type not in NON_DRAGGABLE_TYPES


def test_a_rule_element_still_refuses_a_rule_set():
    """Draggable is not droppable: only the branch area takes one."""
    for slot, valid in VALID_TYPES_BY_SLOT.items():
        assert 'Policy' not in valid, slot
        assert 'NAT' not in valid, slot


def test_the_action_is_offered_in_both_menus():
    assert PolicyAction.Branch in {entry[0] for entry in ACTION_MENU_ENTRIES}
    assert NATAction.Branch in {entry[0] for entry in NAT_ACTION_MENU_ENTRIES}


def test_the_action_has_parameters():
    """Without the Parameters entry there is no drop area to reach."""
    assert PolicyAction.Branch in ACTIONS_WITH_PARAMS


def test_the_drop_area_takes_what_it_is_told_to(qt_app):
    from firewallfabrik.gui.drop_area import FWObjectDropArea

    area = FWObjectDropArea()
    assert area.accepts_type('IPv4'), 'no filter means every type'

    area.set_accepted_types({'Policy'})
    assert area.accepts_type('Policy')
    assert not area.accepts_type('NAT')
    assert not area.accepts_type('IPv4')


def test_the_drop_area_reports_what_was_dropped(qt_app):
    import uuid

    from firewallfabrik.gui.drop_area import FWObjectDropArea

    area = FWObjectDropArea()
    target = uuid.uuid4()
    area.insert_object(target, 'a_000-global_policy', 'Policy')
    assert area.get_object_id() == target
    assert area.get_object_name() == 'a_000-global_policy'
    assert area.get_object_type() == 'Policy'

    area.delete_object()
    assert area.is_empty()
    assert area.get_object_id() is None


def test_the_panel_wires_the_branch_area(qt_app):
    """The widget exists in the .ui file; the panel has to read and write it."""
    # Through the loader, because importing the module directly while it is
    # registering itself is a circular import.
    from firewallfabrik.gui import ui_loader

    panel = ui_loader.CUSTOM_WIDGET_MAP['ActionsDialog']()
    assert hasattr(panel, 'iptBranchDropArea')
    assert hasattr(panel, '_load_branch_target')
    # The area starts out asking for a rule set and nothing else.
    assert panel.iptBranchDropArea.accepts_type('Policy')
    assert not panel.iptBranchDropArea.accepts_type('IPv4')


def test_the_panel_reads_a_nat_rules_options_too(qt_app):
    """It is opened for a NAT rule as well, and asked the wrong subclass.

    ``session.get(PolicyRule, <a NAT rule's id>)`` answers ``None``, so the
    options read as empty and the next save wrote that emptiness back over
    everything the rule carried.
    """
    import pathlib

    source = pathlib.Path('src/firewallfabrik/gui/actions_dialog.py').read_text(
        encoding='utf-8'
    )
    assert 'session.get(Rule, row_data.rule_id)' in source
