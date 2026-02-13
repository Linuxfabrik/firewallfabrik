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

from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import QDockWidget, QTextBrowser, QWidget

# Maps custom widget class names from the .ui file to their Qt base classes.
# As Python implementations are created, replace QWidget with the real class.
CUSTOM_WIDGET_MAP = {
    'ActionsDialog': QWidget,
    'AddressRangeDialog': QWidget,
    'AddressTableDialog': QWidget,
    'AttachedNetworksDialog': QWidget,
    'BlankDialog': QWidget,
    'ClusterDialog': QWidget,
    'ClusterGroupDialog': QWidget,
    'CommentEditorPanel': QWidget,
    'CommentKeywords': QWidget,  # replaced by CommentTags at module bottom
    'CompilerOutputPanel': QTextBrowser,
    'CustomServiceDialog': QWidget,
    'DNSNameDialog': QWidget,
    'DynamicGroupDialog': QWidget,
    'FirewallDialog': QWidget,
    'GroupObjectDialog': QWidget,
    'HostDialog': QWidget,
    'ICMPServiceDialog': QWidget,
    'InterfaceDialog': QWidget,
    'IPServiceDialog': QWidget,
    'IPv4Dialog': QWidget,
    'IPv6Dialog': QWidget,
    'LibraryDialog': QWidget,
    'MetricEditorPanel': QWidget,
    'NATRuleOptionsDialog': QWidget,
    'NetworkDialog': QWidget,
    'NetworkDialogIPv6': QWidget,
    'ObjectEditorDockWidget': QDockWidget,
    'PhysicalAddressDialog': QWidget,
    'RoutingRuleOptionsDialog': QWidget,
    'RuleOptionsDialog': QWidget,
    'RuleSetDialog': QWidget,  # replaced by RuleSetDialog at module bottom
    'TagServiceDialog': QWidget,
    'TCPServiceDialog': QWidget,
    'TimeDialog': QWidget,
    'UDPServiceDialog': QWidget,
    'UserDialog': QWidget,
}


class FWFUiLoader(QUiLoader):
    """Custom UI loader that populates an existing widget instance.

    This mimics the C++ ``Ui::setupUi(this)`` pattern.  When
    ``QUiLoader`` creates the top-level widget (parent is ``None``),
    we return the *base_instance* so that all child widgets, menus,
    toolbars, and dock widgets are added directly to it.

    Unknown custom widget classes listed in ``CUSTOM_WIDGET_MAP`` are
    replaced with their Qt base class so .ui files can be loaded before
    all Python widget classes exist.
    """

    def __init__(self, base_instance):
        super().__init__(base_instance)
        self._base_instance = base_instance

    def createWidget(self, class_name, parent=None, name=''):
        if parent is None and self._base_instance is not None:
            return self._base_instance
        if class_name in CUSTOM_WIDGET_MAP:
            widget = CUSTOM_WIDGET_MAP[class_name](parent)
            widget.setObjectName(name)
            return widget
        return super().createWidget(class_name, parent, name)


# Late imports: dialog modules import FWFUiLoader from this module,
# so we update the map after both modules are fully defined.
def _register_actions_dialog():
    from firewallfabrik.gui.actions_dialog import ActionsPanel

    CUSTOM_WIDGET_MAP['ActionsDialog'] = ActionsPanel


def _register_address_dialogs():
    from firewallfabrik.gui.address_dialogs import (
        AddressRangeDialog,
        IPv4Dialog,
        IPv6Dialog,
        NetworkDialog,
        NetworkDialogIPv6,
        PhysAddressDialog,
    )

    CUSTOM_WIDGET_MAP['IPv4Dialog'] = IPv4Dialog
    CUSTOM_WIDGET_MAP['IPv6Dialog'] = IPv6Dialog
    CUSTOM_WIDGET_MAP['NetworkDialog'] = NetworkDialog
    CUSTOM_WIDGET_MAP['NetworkDialogIPv6'] = NetworkDialogIPv6
    CUSTOM_WIDGET_MAP['AddressRangeDialog'] = AddressRangeDialog
    CUSTOM_WIDGET_MAP['PhysicalAddressDialog'] = PhysAddressDialog


def _register_device_dialogs():
    from firewallfabrik.gui.device_dialogs import (
        FirewallDialog,
        HostDialog,
        InterfaceDialog,
    )

    CUSTOM_WIDGET_MAP['HostDialog'] = HostDialog
    CUSTOM_WIDGET_MAP['FirewallDialog'] = FirewallDialog
    CUSTOM_WIDGET_MAP['InterfaceDialog'] = InterfaceDialog


def _register_service_dialogs():
    from firewallfabrik.gui.service_dialogs import (
        ICMPServiceDialog,
        IPServiceDialog,
        TCPServiceDialog,
        UDPServiceDialog,
    )

    CUSTOM_WIDGET_MAP['TCPServiceDialog'] = TCPServiceDialog
    CUSTOM_WIDGET_MAP['UDPServiceDialog'] = UDPServiceDialog
    CUSTOM_WIDGET_MAP['ICMPServiceDialog'] = ICMPServiceDialog
    CUSTOM_WIDGET_MAP['IPServiceDialog'] = IPServiceDialog


def _register_group_dialog():
    from firewallfabrik.gui.group_dialog import GroupObjectDialog

    CUSTOM_WIDGET_MAP['GroupObjectDialog'] = GroupObjectDialog


def _register_group_type_dialogs():
    from firewallfabrik.gui.address_table_dialog import AddressTableDialog
    from firewallfabrik.gui.dns_name_dialog import DNSNameDialog
    from firewallfabrik.gui.dynamic_group_dialog import DynamicGroupDialog

    CUSTOM_WIDGET_MAP['AddressTableDialog'] = AddressTableDialog
    CUSTOM_WIDGET_MAP['DNSNameDialog'] = DNSNameDialog
    CUSTOM_WIDGET_MAP['DynamicGroupDialog'] = DynamicGroupDialog


def _register_library_dialog():
    from firewallfabrik.gui.library_dialog import LibraryDialog

    CUSTOM_WIDGET_MAP['LibraryDialog'] = LibraryDialog


def _register_time_dialog():
    from firewallfabrik.gui.time_dialog import TimeDialog

    CUSTOM_WIDGET_MAP['TimeDialog'] = TimeDialog


def _register_comment_tags():
    from firewallfabrik.gui.comment_tags import CommentTags

    CUSTOM_WIDGET_MAP['CommentKeywords'] = CommentTags


def _register_comment_editor_panel():
    from firewallfabrik.gui.comment_editor_panel import CommentEditorPanel

    CUSTOM_WIDGET_MAP['CommentEditorPanel'] = CommentEditorPanel


def _register_drop_area():
    from firewallfabrik.gui.drop_area import FWObjectDropArea

    CUSTOM_WIDGET_MAP['FWObjectDropArea'] = FWObjectDropArea


def _register_rule_options_panel():
    from firewallfabrik.gui.rule_options_dialog import RuleOptionsPanel

    CUSTOM_WIDGET_MAP['RuleOptionsDialog'] = RuleOptionsPanel


def _register_service_type_dialogs():
    from firewallfabrik.gui.custom_service_dialog import CustomServiceDialog
    from firewallfabrik.gui.tag_service_dialog import TagServiceDialog
    from firewallfabrik.gui.user_service_dialog import UserServiceDialog

    CUSTOM_WIDGET_MAP['CustomServiceDialog'] = CustomServiceDialog
    CUSTOM_WIDGET_MAP['TagServiceDialog'] = TagServiceDialog
    CUSTOM_WIDGET_MAP['UserDialog'] = UserServiceDialog


def _register_ruleset_dialog():
    from firewallfabrik.gui.ruleset_dialog import RuleSetDialog

    CUSTOM_WIDGET_MAP['RuleSetDialog'] = RuleSetDialog


_register_actions_dialog()
_register_address_dialogs()
_register_comment_editor_panel()
_register_comment_tags()
_register_device_dialogs()
_register_drop_area()
_register_group_dialog()
_register_group_type_dialogs()
_register_library_dialog()
_register_rule_options_panel()
_register_ruleset_dialog()
_register_service_dialogs()
_register_service_type_dialogs()
_register_time_dialog()
