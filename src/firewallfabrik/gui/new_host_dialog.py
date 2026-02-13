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

"""Wizard dialog for creating a new Host object with interfaces.

Ports fwbuilder's ``newHostDialog`` — simplified to two pages (name and
manual interface configuration; SNMP discovery and templates are dropped).
"""

import ipaddress
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QMessageBox,
    QPushButton,
    QWidget,
)

from firewallfabrik.gui.ui_loader import FWFUiLoader

_PAGE_NAME = 0
_PAGE_INTERFACES = 1

_TYPE_STATIC = 0
_TYPE_DYNAMIC = 1
_TYPE_UNNUMBERED = 2


class NewHostDialog(QDialog):
    """Two-page wizard for creating a new Host with interfaces.

    Page 1: Enter host name.
    Page 2: Configure network interfaces (name, label, type, addresses).

    Mirrors fwbuilder's ``newHostDialog`` — the SNMP discovery and
    template pages are dropped.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        ui_path = Path(__file__).resolve().parent / 'ui' / 'newhostdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self.setWindowIcon(QIcon(':/Icons/Host/icon-tree'))

        self._iface_ui_path = (
            Path(__file__).resolve().parent / 'ui' / 'interfaceeditorwidget_q.ui'
        )

        # Tab widgets and their data.
        self._iface_widgets = []  # list of QWidget (one per tab)

        # Initial button states.
        self.backButton.setEnabled(False)
        self.nextButton.setEnabled(False)
        self.finishButton.setEnabled(False)

        # Connections.
        self.backButton.clicked.connect(self._on_back)
        self.nextButton.clicked.connect(self._on_next)
        self.finishButton.clicked.connect(self._on_finish)
        self.cancelButton.clicked.connect(self.reject)
        self.obj_name.textChanged.connect(self._validate)

        # Corner buttons for adding/removing interface tabs.
        self._add_btn = QPushButton('+')
        self._add_btn.setToolTip('Add a new interface')
        self._add_btn.setFixedSize(24, 24)
        self._add_btn.clicked.connect(self._add_interface_tab)
        self.interfaceEditor.setCornerWidget(self._add_btn)

        self._remove_btn = QPushButton('\u2212')  # minus sign
        self._remove_btn.setToolTip('Remove the current interface')
        self._remove_btn.setFixedSize(24, 24)
        self._remove_btn.clicked.connect(self._remove_current_tab)

        self.obj_name.setText('New Host')
        self.obj_name.selectAll()

        # Start with one blank interface tab.
        self._add_interface_tab()

        self._show_page(_PAGE_NAME)

        self.adjustSize()

        # Center on parent window.
        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    # ------------------------------------------------------------------
    # Interface tab management
    # ------------------------------------------------------------------

    def _add_interface_tab(self):
        """Add a new blank interface tab."""
        widget = QWidget()
        loader = FWFUiLoader(widget)
        loader.load(str(self._iface_ui_path))

        # Connect name field to update tab title dynamically.
        widget.ifaceName.textEdited.connect(
            lambda text, w=widget: self._on_iface_name_edited(w, text)
        )

        # Connect type combo to enable/disable address controls.
        widget.ifaceType.currentIndexChanged.connect(
            lambda idx, w=widget: self._on_type_changed(w, idx)
        )

        # Connect address buttons.
        widget.addAddressButton.clicked.connect(
            lambda checked=False, w=widget: self._add_address_row(w)
        )
        widget.removeAddressButton.clicked.connect(
            lambda checked=False, w=widget: self._remove_address_row(w)
        )

        # Resize the address table columns to fill available space.
        header = widget.addressTable.horizontalHeader()
        header.setStretchLastSection(True)

        idx = self.interfaceEditor.count()
        tab_name = f'Interface {idx}'
        self.interfaceEditor.addTab(widget, tab_name)
        self.interfaceEditor.setCurrentWidget(widget)
        self._iface_widgets.append(widget)
        self._update_remove_button()
        widget.ifaceName.setFocus()

    def _remove_current_tab(self):
        """Remove the currently selected interface tab."""
        idx = self.interfaceEditor.currentIndex()
        if idx < 0 or self.interfaceEditor.count() <= 0:
            return
        widget = self.interfaceEditor.widget(idx)
        self.interfaceEditor.removeTab(idx)
        if widget in self._iface_widgets:
            self._iface_widgets.remove(widget)
        widget.deleteLater()
        self._update_remove_button()

    def _update_remove_button(self):
        """Show the remove button only when there are tabs."""
        from PySide6.QtCore import Qt

        if self.interfaceEditor.count() > 0:
            self.interfaceEditor.setCornerWidget(
                self._remove_btn, Qt.Corner.TopRightCorner
            )
            self._remove_btn.show()
        else:
            self._remove_btn.hide()

    def _on_iface_name_edited(self, widget, text):
        """Update the tab title when the interface name changes."""
        idx = self.interfaceEditor.indexOf(widget)
        if idx >= 0:
            self.interfaceEditor.setTabText(idx, text or f'Interface {idx}')

    @staticmethod
    def _on_type_changed(widget, idx):
        """Enable/disable address controls based on interface type."""
        is_static = idx == _TYPE_STATIC
        widget.addressTable.setEnabled(is_static)
        widget.addAddressButton.setEnabled(is_static)
        widget.removeAddressButton.setEnabled(is_static)
        if not is_static:
            widget.addressTable.setRowCount(0)

    @staticmethod
    def _add_address_row(widget):
        """Add a new address row to the interface's address table."""
        table = widget.addressTable
        row = table.rowCount()
        table.insertRow(row)

        # Protocol combo in column 2.
        combo = QComboBox()
        combo.addItems(['IPv4', 'IPv6'])
        combo.setToolTip('Address family: IPv4 or IPv6')
        table.setCellWidget(row, 2, combo)

    @staticmethod
    def _remove_address_row(widget):
        """Remove the selected address row from the interface's table."""
        table = widget.addressTable
        row = table.currentRow()
        if row >= 0:
            table.removeRow(row)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self):
        """Validate wizard state and update button enabled states."""
        page = self.stackedWidget.currentIndex()
        if page == _PAGE_NAME:
            name = self.obj_name.text().strip()
            self.nextButton.setEnabled(bool(name))
        elif page == _PAGE_INTERFACES:
            self.finishButton.setEnabled(True)

    def _validate_interfaces(self):
        """Validate all interface tabs.  Return True if valid."""
        errors = []
        for i in range(self.interfaceEditor.count()):
            widget = self.interfaceEditor.widget(i)
            name = widget.ifaceName.text().strip()
            if not name:
                errors.append(f'Tab {i + 1}: Interface name is required.')
                self.interfaceEditor.setCurrentIndex(i)
                widget.ifaceName.setFocus()
                break

            iface_type = widget.ifaceType.currentIndex()
            if iface_type == _TYPE_STATIC:
                table = widget.addressTable
                for row in range(table.rowCount()):
                    addr_item = table.item(row, 0)
                    mask_item = table.item(row, 1)
                    addr = addr_item.text().strip() if addr_item else ''
                    mask = mask_item.text().strip() if mask_item else ''
                    combo = table.cellWidget(row, 2)
                    is_v4 = combo.currentIndex() == 0 if combo else True

                    if not addr:
                        errors.append(
                            f'Tab "{name}", row {row + 1}: IP address is required.'
                        )
                        self.interfaceEditor.setCurrentIndex(i)
                        break
                    if not self._is_valid_address(addr, is_v4):
                        errors.append(
                            f'Tab "{name}", row {row + 1}: '
                            f"'{addr}' is not a valid "
                            f'{"IPv4" if is_v4 else "IPv6"} address.'
                        )
                        self.interfaceEditor.setCurrentIndex(i)
                        break
                    if mask and not self._is_valid_netmask(mask, is_v4):
                        errors.append(
                            f'Tab "{name}", row {row + 1}: '
                            f"'{mask}' is not a valid netmask."
                        )
                        self.interfaceEditor.setCurrentIndex(i)
                        break

        self.ifaceValidationLabel.setText('\n'.join(errors))
        return len(errors) == 0

    @staticmethod
    def _is_valid_address(addr, is_v4):
        """Return True if *addr* is a valid IP address."""
        try:
            parsed = ipaddress.ip_address(addr)
            if is_v4:
                return isinstance(parsed, ipaddress.IPv4Address)
            return isinstance(parsed, ipaddress.IPv6Address)
        except ValueError:
            return False

    @staticmethod
    def _is_valid_netmask(mask, is_v4):
        """Return True if *mask* is a valid netmask (CIDR or dotted)."""
        try:
            prefix = int(mask)
            max_prefix = 32 if is_v4 else 128
            return 0 <= prefix <= max_prefix
        except ValueError:
            pass
        # Try dotted notation (IPv4 only).
        if is_v4:
            try:
                ipaddress.IPv4Address(mask)
                return True
            except ValueError:
                pass
        return False

    # ------------------------------------------------------------------
    # Page navigation
    # ------------------------------------------------------------------

    def _show_page(self, page):
        """Switch to the given wizard page and update button states."""
        self.stackedWidget.setCurrentIndex(page)

        if page == _PAGE_NAME:
            self.titleLabel.setText('Name the new host object')
            self.backButton.setEnabled(False)
            self.finishButton.setEnabled(False)
            self._validate()
            self.obj_name.setFocus()
        elif page == _PAGE_INTERFACES:
            self.titleLabel.setText('Configure interfaces')
            self.backButton.setEnabled(True)
            self.nextButton.setEnabled(False)
            self.finishButton.setEnabled(True)
            self.finishButton.setDefault(True)

    def _on_back(self):
        """Navigate to the previous page."""
        current = self.stackedWidget.currentIndex()
        if current > _PAGE_NAME:
            self._show_page(current - 1)

    def _on_next(self):
        """Navigate to the next page."""
        current = self.stackedWidget.currentIndex()
        if current == _PAGE_NAME:
            name = self.obj_name.text().strip()
            if not name:
                QMessageBox.warning(
                    self,
                    self.windowTitle(),
                    'Please enter a name for the new host.',
                )
                self.obj_name.setFocus()
                return
            self._show_page(_PAGE_INTERFACES)

    def _on_finish(self):
        """Validate and accept the dialog."""
        if not self._validate_interfaces():
            return
        self.accept()

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    def get_result(self):
        """Return ``(name, interfaces)`` for host creation.

        *interfaces* is a list of dicts, each with keys:

        - ``name`` (str): interface name
        - ``label`` (str): optional label
        - ``comment`` (str): optional comment
        - ``type`` (int): 0 = static, 1 = dynamic, 2 = unnumbered
        - ``addresses`` (list[dict]): each with ``address``, ``netmask``,
          ``ipv4`` (bool)
        """
        name = self.obj_name.text().strip()
        interfaces = []
        for i in range(self.interfaceEditor.count()):
            widget = self.interfaceEditor.widget(i)
            iface_name = widget.ifaceName.text().strip()
            if not iface_name:
                continue
            iface = {
                'addresses': [],
                'comment': widget.ifaceComment.toPlainText().strip(),
                'label': widget.ifaceLabel.text().strip(),
                'name': iface_name,
                'type': widget.ifaceType.currentIndex(),
            }

            if iface['type'] == _TYPE_STATIC:
                table = widget.addressTable
                for row in range(table.rowCount()):
                    addr_item = table.item(row, 0)
                    mask_item = table.item(row, 1)
                    combo = table.cellWidget(row, 2)
                    addr = addr_item.text().strip() if addr_item else ''
                    mask = mask_item.text().strip() if mask_item else ''
                    is_v4 = combo.currentIndex() == 0 if combo else True
                    if addr:
                        iface['addresses'].append(
                            {
                                'address': addr,
                                'ipv4': is_v4,
                                'netmask': mask,
                            }
                        )

            interfaces.append(iface)
        return name, interfaces
