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

"""Wizard dialog for creating a new Cluster object.

Ports fwbuilder's ``newClusterDialog`` with its five pages:

1. the name and the member firewalls (``FirewallSelectorWidget``),
2. the cluster interfaces and the member interfaces each stands for
   (``ClusterInterfacesSelectorWidget``, ``ClusterInterfaceWidget``),
3. the failover protocol and the addresses of each cluster interface
   (``InterfacesTabWidget`` in cluster mode),
4. the member whose Policy and NAT rules the cluster takes over, if any,
5. a summary.

The Master column of the first page is left out: see "No Master Member
in a Cluster" in DesignDecisions.md.  The cluster itself is created by
``TreeOperations.create_cluster`` from what ``get_result()`` returns.
"""

import uuid
from dataclasses import dataclass, field
from pathlib import Path

import sqlalchemy
from PySide6.QtCore import QByteArray, QSettings, Qt
from PySide6.QtGui import QIcon, QPalette
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QRadioButton,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from firewallfabrik.core.objects import Firewall
from firewallfabrik.driver._interface_properties import LinuxInterfaceProperties
from firewallfabrik.gui.netmask import (
    EMPTY_ADDRESS_OR_NETMASK,
    NetmaskRejected,
    netmask_for_interface_address,
)
from firewallfabrik.gui.new_host_dialog import NewHostDialog
from firewallfabrik.gui.ui_loader import FWFUiLoader

_UI_DIR = Path(__file__).resolve().parent / 'ui'

_PAGE_FIREWALLS = 0
_PAGE_INTERFACES = 1
_PAGE_ADDRESSES = 2
_PAGE_POLICY = 3
_PAGE_SUMMARY = 4

_SETTINGS_GEOMETRY = 'NewClusterDialog/geometry'
# The failover protocol picked last is offered first next time
# (FWBSettings::getNewClusterFailoverProtocol).
_SETTINGS_PROTOCOL = 'NewClusterDialog/failoverProtocol'

_MEMBER_ROLE = Qt.ItemDataRole.UserRole


@dataclass
class _Iface:
    """What the wizard needs to know about one member interface."""

    id: uuid.UUID
    name: str
    label: str
    eligible: bool
    sub_interfaces: list = field(default_factory=list)


@dataclass
class _Member:
    """A firewall the wizard offers as a member."""

    id: uuid.UUID
    name: str
    library: str
    platform: str
    host_os: str
    interfaces: list = field(default_factory=list)  # top-level _Iface

    def all_interfaces(self):
        for iface in self.interfaces:
            yield iface
            yield from iface.sub_interfaces


class NewClusterDialog(QDialog):
    """Five-page wizard for creating a new Cluster."""

    def __init__(self, db_manager, parent=None, preselected_fw_ids=None):
        super().__init__(parent)

        loader = FWFUiLoader(self)
        loader.load(str(_UI_DIR / 'newclusterdialog_q.ui'))
        self.setWindowIcon(QIcon(':/Icons/Cluster/icon-tree'))

        self._members = self._load_firewalls(db_manager)
        self._use_boxes = {}  # member id -> QCheckBox
        self._selector_tabs = []  # page 2: one widget per cluster interface
        self._policy_group = QButtonGroup(self)
        self._policy_group.addButton(self.noPolicy)
        self._policy_buttons = {}  # QRadioButton -> member id

        preselected = {str(fw_id) for fw_id in preselected_fw_ids or ()}
        self._fill_firewall_selector(preselected)

        self.backButton.clicked.connect(self._on_back)
        self.nextButton.clicked.connect(self._on_next)
        self.finishButton.clicked.connect(self.accept)
        self.obj_name.textChanged.connect(self._update_buttons)
        self.addInterfaceButton.clicked.connect(self._on_add_interface)
        self.removeInterfaceButton.clicked.connect(self._on_remove_interface)

        self._show_page(_PAGE_FIREWALLS)
        self.obj_name.setFocus()
        self._restore_geometry(parent)

    # ------------------------------------------------------------------
    # Geometry persistence
    # ------------------------------------------------------------------

    def _restore_geometry(self, parent):
        geometry = QSettings().value(_SETTINGS_GEOMETRY, type=QByteArray)
        if geometry and self.restoreGeometry(geometry):
            return
        if parent is not None:
            geo = self.geometry()
            geo.moveCenter(parent.geometry().center())
            self.setGeometry(geo)

    def done(self, result):
        QSettings().setValue(_SETTINGS_GEOMETRY, self.saveGeometry())
        super().done(result)

    # ------------------------------------------------------------------
    # Page 1: firewalls
    # ------------------------------------------------------------------

    @staticmethod
    def _load_firewalls(db_manager):
        """Snapshot every firewall with the interfaces the wizard shows."""
        props = LinuxInterfaceProperties()
        members = []
        with db_manager.session() as session:
            firewalls = session.scalars(
                sqlalchemy.select(Firewall)
                .where(Firewall.type == 'Firewall')
                .order_by(Firewall.name)
            ).all()
            for fw in firewalls:
                data = fw.data or {}
                member = _Member(
                    host_os=str(data.get('host_OS', '')),
                    id=fw.id,
                    library=fw.library.name if fw.library else '',
                    name=fw.name,
                    platform=str(data.get('platform', '')),
                )
                for iface in sorted(fw.interfaces, key=lambda i: i.name):
                    if iface.parent_interface_id is not None:
                        continue
                    entry = _Iface(
                        eligible=props.is_eligible_for_cluster(iface),
                        id=iface.id,
                        label=str((iface.data or {}).get('label', '')),
                        name=iface.name,
                    )
                    for sub in sorted(iface.sub_interfaces, key=lambda i: i.name):
                        entry.sub_interfaces.append(
                            _Iface(
                                eligible=props.is_eligible_for_cluster(sub),
                                id=sub.id,
                                label=str((sub.data or {}).get('label', '')),
                                name=sub.name,
                            )
                        )
                    member.interfaces.append(entry)
                members.append(member)
        return members

    def _fill_firewall_selector(self, preselected):
        """One row per firewall, as ``FirewallSelectorWidget::setFirewallList``.

        Two firewalls of one name in different libraries are shown with
        the library in front, so they can be told apart.
        """
        names = [m.name for m in self._members]
        table = self.firewallSelector
        table.setRowCount(len(self._members))
        for row, member in enumerate(self._members):
            text = member.name
            if names.count(member.name) > 1:
                text = f'{member.library} / {member.name}'
            item = QTableWidgetItem(QIcon(':/Icons/Firewall/icon'), text)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            table.setItem(row, 0, item)

            box = QCheckBox()
            box.setChecked(str(member.id) in preselected)
            box.setToolTip(f'Use {member.name} as a member of the cluster')
            box.toggled.connect(self._update_buttons)
            container = QWidget()
            layout = QHBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(box)
            table.setCellWidget(row, 1, container)
            self._use_boxes[member.id] = box
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)

    def _selected_members(self):
        return [m for m in self._members if self._use_boxes[m.id].isChecked()]

    def _firewalls_valid(self):
        """Port of ``FirewallSelectorWidget::isValid``."""
        members = self._selected_members()
        if not members:
            return self._fail(
                'You should select at least one firewall to use with the cluster'
            )
        if len({m.host_os for m in members}) > 1:
            return self._fail(
                'Host operation systems of chosen firewalls are different'
            )
        if len({m.platform for m in members}) > 1:
            return self._fail('Platforms of chosen firewalls are different')
        first_names = {iface.name for iface in members[0].interfaces}
        if not any(
            all(name in {i.name for i in m.interfaces} for m in members)
            for name in first_names
        ):
            return self._fail(
                'Cluster firewalls should have at least one common interface'
            )
        return True

    # ------------------------------------------------------------------
    # Page 2: cluster interfaces and their member interfaces
    # ------------------------------------------------------------------

    def _fill_interface_selector(self):
        """One tab per interface name all members share.

        Ports ``ClusterInterfacesSelectorWidget::setFirewallList``: the
        names are taken from every interface, sub-interfaces included, and
        a tab is kept only if each member has an eligible interface of
        that name.
        """
        while self.interfaceSelector.count():
            widget = self.interfaceSelector.widget(0)
            self.interfaceSelector.removeTab(0)
            widget.deleteLater()
        self._selector_tabs = []

        members = self._selected_members()
        shared = set.intersection(
            *({i.name for i in m.all_interfaces()} for m in members)
        )
        for name in sorted(shared):
            widget = self._add_selector_tab(members)
            if not self._select_member_interfaces(widget, name):
                self._remove_selector_tab(widget)
        self._update_interface_buttons()

    def _add_selector_tab(self, members):
        widget = QWidget()
        FWFUiLoader(widget).load(str(_UI_DIR / 'clusterinterfacewidget_q.ui'))
        widget.trees = {}
        for member in members:
            column = QVBoxLayout()
            column.addWidget(QLabel(member.name))
            tree = QTreeWidget()
            tree.setHeaderHidden(True)
            tree.setToolTip(
                f'Interface of {member.name} this cluster interface stands for.\n'
                'Greyed out interfaces cannot be used in a cluster.'
            )
            root = QTreeWidgetItem(tree, [member.name])
            root.setIcon(0, QIcon(':/Icons/Firewall/icon-tree'))
            root.setFlags(Qt.ItemFlag.ItemIsEnabled)
            for iface in member.interfaces:
                item = self._interface_item(root, iface)
                for sub in iface.sub_interfaces:
                    self._interface_item(item, sub)
            tree.expandAll()
            column.addWidget(tree)
            widget.interfaceBox.addLayout(column)
            widget.trees[member.id] = tree
        widget.name.textChanged.connect(
            lambda text, w=widget: self.interfaceSelector.setTabText(
                self.interfaceSelector.indexOf(w), text
            )
        )
        self.interfaceSelector.addTab(widget, 'New interface')
        self._selector_tabs.append(widget)
        return widget

    def _interface_item(self, parent, iface):
        """A member interface, selectable only if it can be used.

        An interface that cannot be used stays enabled and is only greyed
        out: Qt disables every child of a disabled item, and the VLAN
        sub-interfaces of an interface that cannot be used are exactly
        the ones that can.
        """
        item = QTreeWidgetItem(parent, [iface.name])
        item.setIcon(0, QIcon(':/Icons/Interface/icon-tree'))
        item.setData(0, _MEMBER_ROLE, iface)
        if iface.eligible:
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        else:
            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            item.setForeground(
                0,
                self.palette().color(
                    QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text
                ),
            )
            item.setToolTip(
                0,
                f'{iface.name} cannot be used in a cluster: it is a bridge port,\n'
                'a bond slave or the parent of VLAN sub-interfaces.',
            )
        return item

    @staticmethod
    def _select_member_interfaces(widget, name):
        """Port of ``ClusterInterfaceWidget::setCurrentInterface``."""
        labels = set()
        for tree in widget.trees.values():
            matches = [
                item
                for item in tree.findItems(
                    name,
                    Qt.MatchFlag.MatchExactly
                    | Qt.MatchFlag.MatchCaseSensitive
                    | Qt.MatchFlag.MatchRecursive,
                )
                if item.data(0, _MEMBER_ROLE) is not None
                and item.data(0, _MEMBER_ROLE).eligible
            ]
            if not matches:
                return False
            tree.setCurrentItem(matches[0])
            labels.add(matches[0].data(0, _MEMBER_ROLE).label)
        widget.name.setText(name)
        if len(labels) == 1:
            widget.label.setText(labels.pop())
        return True

    def _remove_selector_tab(self, widget):
        self.interfaceSelector.removeTab(self.interfaceSelector.indexOf(widget))
        self._selector_tabs.remove(widget)
        widget.deleteLater()

    def _on_add_interface(self):
        widget = self._add_selector_tab(self._selected_members())
        self.interfaceSelector.setCurrentWidget(widget)
        widget.name.setFocus()
        self._update_interface_buttons()

    def _on_remove_interface(self):
        widget = self.interfaceSelector.currentWidget()
        if widget is not None:
            self._remove_selector_tab(widget)
        self._update_interface_buttons()

    def _update_interface_buttons(self):
        has_tabs = bool(self._selector_tabs)
        self.removeInterfaceButton.setEnabled(has_tabs)
        self.interfaceSelector.setVisible(has_tabs)
        self.noInterfacesLabel.setVisible(not has_tabs)

    def _chosen_member_interfaces(self, widget):
        """The member interface picked in each tree, or None if one is not."""
        chosen = []
        for tree in widget.trees.values():
            items = tree.selectedItems()
            if not items or items[0].data(0, _MEMBER_ROLE) is None:
                return None
            chosen.append(items[0].data(0, _MEMBER_ROLE))
        return chosen

    def _interfaces_valid(self):
        """Port of ``ClusterInterfacesSelectorWidget::isValid``."""
        used = {}
        names = set()
        for widget in self._selector_tabs:
            self.interfaceSelector.setCurrentWidget(widget)
            name = widget.name.text().strip()
            if not name:
                return self._fail('Interface name can not be blank.')
            if name in names:
                return self._fail(f'The cluster has two interfaces named {name}.')
            names.add(name)
            chosen = self._chosen_member_interfaces(widget)
            if chosen is None:
                return self._fail(
                    'Some of the cluster interfaces do not have any member '
                    'firewall interface selected'
                )
            for member, iface in zip(widget.trees, chosen, strict=True):
                if iface.id in used:
                    fw_name = next(m.name for m in self._members if m.id == member)
                    return self._fail(
                        f'Interface {iface.name} of firewall {fw_name} is used '
                        'in more than one cluster interface.'
                    )
                used[iface.id] = name
        return True

    # ------------------------------------------------------------------
    # Page 3: failover protocol and addresses
    # ------------------------------------------------------------------

    def _fill_interface_editor(self):
        """One editor per cluster interface, in cluster mode.

        Ports ``InterfacesTabWidget::addClusterInterface`` and
        ``InterfaceEditorWidget::setClusterMode``: the name is fixed on the
        previous page, the interface type does not apply, and the failover
        protocol and the explanation are shown.
        """
        while self.interfaceEditor.count():
            widget = self.interfaceEditor.widget(0)
            self.interfaceEditor.removeTab(0)
            widget.deleteLater()

        last_protocol = QSettings().value(_SETTINGS_PROTOCOL, '', type=str)
        for source in self._selector_tabs:
            widget = QWidget()
            FWFUiLoader(widget).load(str(_UI_DIR / 'interfaceeditorwidget_q.ui'))
            widget.ifaceName.setText(source.name.text().strip())
            widget.ifaceName.setEnabled(False)
            widget.ifaceLabel.setText(source.label.text())
            widget.ifaceComment.setPlainText(source.comment.toPlainText())
            for hidden in (widget.typeLabel, widget.ifaceType):
                hidden.setVisible(False)
            for shown in (widget.explanation, widget.protocolLabel, widget.protocol):
                shown.setVisible(True)
            widget.addressTable.horizontalHeader().setStretchLastSection(True)
            widget.addAddressButton.clicked.connect(
                lambda _=False, w=widget: NewHostDialog._add_address_row(w)
            )
            widget.removeAddressButton.clicked.connect(
                lambda _=False, w=widget: NewHostDialog._remove_address_row(w)
            )
            widget.protocol.currentTextChanged.connect(
                lambda text, w=widget: self._on_protocol_changed(w, text)
            )
            index = widget.protocol.findText(last_protocol)
            widget.protocol.setCurrentIndex(max(index, 0))
            self._on_protocol_changed(widget, widget.protocol.currentText())
            self.interfaceEditor.addTab(widget, widget.ifaceName.text())

    @staticmethod
    def _on_protocol_changed(widget, text):
        """Port of ``InterfaceEditorWidget::protocolChanged``.

        None takes part in no failover and so carries no address.
        """
        no_address = text == 'None'
        if no_address:
            widget.addressTable.setRowCount(0)
        for control in (
            widget.addressTable,
            widget.addAddressButton,
            widget.removeAddressButton,
        ):
            control.setEnabled(not no_address)
        QSettings().setValue(_SETTINGS_PROTOCOL, text)

    def _addresses_valid(self):
        for index in range(self.interfaceEditor.count()):
            widget = self.interfaceEditor.widget(index)
            name = widget.ifaceName.text()
            table = widget.addressTable
            for row in range(table.rowCount()):
                self.interfaceEditor.setCurrentIndex(index)
                address, netmask, is_v4 = self._address_row(table, row)
                where = f'Interface "{name}", row {row + 1}'
                if not address or not netmask:
                    return self._fail(f'{where}: {EMPTY_ADDRESS_OR_NETMASK}.')
                if not NewHostDialog._is_valid_address(address, is_v4):
                    family = 'IPv4' if is_v4 else 'IPv6'
                    return self._fail(
                        f"{where}: '{address}' is not a valid {family} address."
                    )
                try:
                    netmask_for_interface_address(netmask, is_v4=is_v4)
                except NetmaskRejected as rejected:
                    return self._fail(f'{where}: {rejected.message}.')
        return True

    @staticmethod
    def _address_row(table, row):
        address_item = table.item(row, 0)
        netmask_item = table.item(row, 1)
        combo = table.cellWidget(row, 2)
        return (
            address_item.text().strip() if address_item else '',
            netmask_item.text().strip() if netmask_item else '',
            combo.currentIndex() == 0 if combo else True,
        )

    def _interface_data(self):
        """The cluster interfaces as ``create_cluster`` takes them."""
        result = []
        for index, source in enumerate(self._selector_tabs):
            editor = self.interfaceEditor.widget(index)
            addresses = []
            for row in range(editor.addressTable.rowCount()):
                address, netmask, is_v4 = self._address_row(editor.addressTable, row)
                addresses.append(
                    {
                        'address': address,
                        'ipv4': is_v4,
                        'netmask': NewHostDialog._normalized_netmask(netmask, is_v4),
                    }
                )
            result.append(
                {
                    'addresses': addresses,
                    'comment': editor.ifaceComment.toPlainText().strip(),
                    'label': editor.ifaceLabel.text().strip(),
                    'members': [i.id for i in self._chosen_member_interfaces(source)],
                    'name': editor.ifaceName.text(),
                    'protocol': editor.protocol.currentText().lower(),
                }
            )
        return result

    # ------------------------------------------------------------------
    # Page 4: rules
    # ------------------------------------------------------------------

    def _fill_policy_choice(self):
        for button in self._policy_buttons:
            self._policy_group.removeButton(button)
            button.deleteLater()
        self._policy_buttons = {}
        for member in self._selected_members():
            button = QRadioButton(member.name)
            button.setToolTip(
                f'The cluster takes over the rules of {member.name}; every\n'
                'member is backed up and left with empty rule sets.'
            )
            self.policySourceLayout.addWidget(button)
            self._policy_group.addButton(button)
            self._policy_buttons[button] = member.id
        self.noPolicy.setChecked(True)

    def _policy_source(self):
        return self._policy_buttons.get(self._policy_group.checkedButton())

    # ------------------------------------------------------------------
    # Page 5: summary
    # ------------------------------------------------------------------

    def _fill_summary(self):
        self.clusterName.setText(f'Name: {self.obj_name.text().strip()}')
        self.firewallsList.setText('\n'.join(m.name for m in self._selected_members()))
        lines = []
        interfaces = self._interface_data() if self._selector_tabs else []
        for index, iface in enumerate(interfaces):
            protocol = self.interfaceEditor.widget(index).protocol.currentText()
            text = f'{iface["name"]} ({protocol})'
            addresses = [f'{a["address"]}/{a["netmask"]}' for a in iface['addresses']]
            if addresses:
                word = 'address' if len(addresses) == 1 else 'addresses'
                text += f' with {word}: ' + ', '.join(addresses)
            lines.append(text)
        self.interfacesList.setText('\n'.join(lines) or 'none')
        source = self._policy_source()
        name = next((m.name for m in self._members if m.id == source), '')
        self.policyLabel.setText(
            f'Policy and NAT rules will be copied from firewall: {name}'
        )
        self.policyLabel.setVisible(source is not None)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _fail(self, message):
        QMessageBox.critical(self, self.windowTitle(), message)
        return False

    def _show_page(self, page, blank=True):
        """Port of ``newClusterDialog::showPage``.

        *blank* rebuilds the page from the previous ones, which happens on
        the way forward; going back keeps what was entered.
        """
        if blank:
            if page == _PAGE_INTERFACES:
                self._fill_interface_selector()
            elif page == _PAGE_ADDRESSES:
                self._fill_interface_editor()
            elif page == _PAGE_POLICY:
                self._fill_policy_choice()
        if page == _PAGE_SUMMARY:
            self._fill_summary()
        self.stackedWidget.setCurrentIndex(page)
        self.titleLabel.setText(self.stackedWidget.currentWidget().windowTitle())
        self._update_buttons()

    def _update_buttons(self):
        page = self.stackedWidget.currentIndex()
        self.backButton.setEnabled(page != _PAGE_FIREWALLS)
        self.nextButton.setEnabled(
            page != _PAGE_SUMMARY
            and (page != _PAGE_FIREWALLS or bool(self.obj_name.text().strip()))
        )
        self.finishButton.setEnabled(page == _PAGE_SUMMARY)
        (self.finishButton if page == _PAGE_SUMMARY else self.nextButton).setDefault(
            True
        )

    def _on_next(self):
        page = self.stackedWidget.currentIndex()
        if page == _PAGE_FIREWALLS and not self._firewalls_valid():
            return
        if page == _PAGE_INTERFACES and not self._interfaces_valid():
            return
        if page == _PAGE_ADDRESSES and not self._addresses_valid():
            return
        following = page + 1
        # A cluster without interfaces has no addresses to set.
        if following == _PAGE_ADDRESSES and not self._selector_tabs:
            following = _PAGE_POLICY
        self._show_page(following)

    def _on_back(self):
        page = self.stackedWidget.currentIndex()
        previous = page - 1
        if previous == _PAGE_ADDRESSES and not self._selector_tabs:
            previous = _PAGE_INTERFACES
        self._show_page(previous, blank=False)

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    def get_result(self):
        """Return the cluster as ``TreeOperations.create_cluster`` takes it.

        The platform and host OS are those of the first member, which the
        first page has checked all members share.
        """
        members = self._selected_members()
        return {
            'copy_rules_from': self._policy_source(),
            'host_OS': members[0].host_os,
            'interfaces': self._interface_data() if self._selector_tabs else [],
            'members': [m.id for m in members],
            'name': self.obj_name.text().strip(),
            'platform': members[0].platform,
        }
