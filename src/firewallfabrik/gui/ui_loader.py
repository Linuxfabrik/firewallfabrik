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
from PySide6.QtWidgets import QDockWidget, QWidget


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
    'CompilerOutputPanel': QWidget,
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
    'RuleSetDialog': QWidget,
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
