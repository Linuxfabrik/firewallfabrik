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

"""Wizard dialog for creating a new Cluster object."""

from pathlib import Path

import sqlalchemy
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QRadioButton,
    QTableWidgetItem,
    QWidget,
)

from firewallfabrik.core.objects import Host
from firewallfabrik.gui.platform_settings import HOST_OS
from firewallfabrik.gui.ui_loader import FWFUiLoader

_PAGE_FIREWALLS = 0
_PAGE_SUMMARY = 1


class NewClusterDialog(QDialog):
    """Two-page wizard for creating a new Cluster.

    Page 1: Enter cluster name and select member firewalls (with master
    designation).  Page 2: Review a summary before finishing.

    Mirrors fwbuilder's ``newClusterDialog`` — simplified to two pages
    (interface/failover/policy pages deferred).
    """

    def __init__(self, db_manager, parent=None, preselected_fw_ids=None):
        super().__init__(parent)

        ui_path = Path(__file__).resolve().parent / 'ui' / 'newclusterdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self.setWindowIcon(QIcon(':/Icons/Cluster/icon-tree'))

        self._db_manager = db_manager
        self._preselected_fw_ids = set(preselected_fw_ids or [])

        # Firewall rows: list of (fw_id, fw_name, fw_data) tuples.
        self._firewalls = []
        # Widgets per row: list of (QCheckBox, QRadioButton) tuples.
        self._row_widgets = []

        self._master_group = QButtonGroup(self)
        self._master_group.setExclusive(True)

        # Initial button states.
        self.backButton.setEnabled(False)
        self.nextButton.setEnabled(False)
        self.finishButton.setEnabled(False)

        # Connections.
        self.backButton.clicked.connect(self._on_back)
        self.nextButton.clicked.connect(self._on_next)
        self.finishButton.clicked.connect(self.accept)
        self.cancelButton.clicked.connect(self.reject)
        self.obj_name.textChanged.connect(self._validate)

        self.obj_name.setText('New Cluster')
        self.obj_name.selectAll()

        self._populate_firewall_table()
        self._validate()
        self._show_page(_PAGE_FIREWALLS)

        self.adjustSize()

        # Center on parent window.
        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    # ------------------------------------------------------------------
    # Firewall table
    # ------------------------------------------------------------------

    def _populate_firewall_table(self):
        """Query all Firewall objects and populate the table."""
        if self._db_manager is None:
            return

        session = self._db_manager.create_session()
        try:
            firewalls = session.scalars(
                sqlalchemy.select(Host)
                .where(Host.type == 'Firewall')
                .order_by(Host.name),
            ).all()
            self._firewalls = [
                (
                    str(fw.id),
                    fw.name,
                    {
                        'host_OS': fw.host_os_val or '',
                        'platform': fw.host_platform or '',
                        'version': fw.host_version or '',
                    },
                )
                for fw in firewalls
            ]
        finally:
            session.close()

        table = self.firewallTable
        table.setSortingEnabled(False)
        table.setRowCount(len(self._firewalls))
        self._row_widgets = []

        for row, (fw_id, fw_name, _fw_data) in enumerate(self._firewalls):
            # Column 0: Firewall name.
            name_item = QTableWidgetItem(fw_name)
            name_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable,
            )
            name_item.setIcon(QIcon(':/Icons/Firewall/icon-tree'))
            table.setItem(row, 0, name_item)

            # Column 1: "Use" checkbox.
            use_cb = QCheckBox()
            use_cb.setToolTip(f'Include {fw_name} in the cluster')
            use_container = QWidget()
            layout = _centered_layout(use_container)
            layout.addWidget(use_cb)
            table.setCellWidget(row, 1, use_container)

            # Column 2: "Master" radio button.
            master_rb = QRadioButton()
            master_rb.setToolTip(f'Designate {fw_name} as master')
            master_rb.setEnabled(False)
            self._master_group.addButton(master_rb, row)
            master_container = QWidget()
            layout = _centered_layout(master_container)
            layout.addWidget(master_rb)
            table.setCellWidget(row, 2, master_container)

            # Connect checkbox to enable/disable the radio button.
            use_cb.toggled.connect(
                lambda checked, rb=master_rb: self._on_use_toggled(checked, rb),
            )

            self._row_widgets.append((use_cb, master_rb))

            # Pre-select if in the preselected list.
            if fw_id in self._preselected_fw_ids:
                use_cb.setChecked(True)

        # Auto-select master for the first checked firewall if preselected.
        if self._preselected_fw_ids:
            self._auto_select_master()

        table.setSortingEnabled(True)
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)

    def _on_use_toggled(self, checked, radio_button):
        """Enable/disable the master radio button when "Use" is toggled."""
        radio_button.setEnabled(checked)
        if not checked:
            radio_button.setChecked(False)
            # If no master is selected, auto-select one.
            self._auto_select_master()
        self._validate()

    def _auto_select_master(self):
        """Auto-select the first checked firewall as master if none is selected."""
        if self._master_group.checkedId() >= 0:
            # A master is already selected; check it's still checked in "Use".
            master_row = self._master_group.checkedId()
            if master_row < len(self._row_widgets):
                use_cb, _ = self._row_widgets[master_row]
                if use_cb.isChecked():
                    return
        # Find the first checked firewall and make it master.
        for use_cb, master_rb in self._row_widgets:
            if use_cb.isChecked():
                master_rb.setChecked(True)
                return

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self):
        """Validate wizard state and update button enabled states."""
        name = self.obj_name.text().strip()
        errors = []

        if not name:
            errors.append('Enter a cluster name.')

        selected_count = sum(1 for use_cb, _ in self._row_widgets if use_cb.isChecked())
        if selected_count < 2:
            errors.append('Select at least two member firewalls.')

        has_master = self._master_group.checkedId() >= 0
        if selected_count >= 2 and not has_master:
            errors.append('Designate one firewall as master.')
        elif has_master:
            master_row = self._master_group.checkedId()
            if master_row < len(self._row_widgets):
                use_cb, _ = self._row_widgets[master_row]
                if not use_cb.isChecked():
                    errors.append('The master firewall must be selected for use.')

        self.validationLabel.setText('\n'.join(errors))
        is_valid = len(errors) == 0
        self.nextButton.setEnabled(is_valid)

    # ------------------------------------------------------------------
    # Page navigation
    # ------------------------------------------------------------------

    def _show_page(self, page):
        """Switch to the given wizard page and update button states."""
        self.stackedWidget.setCurrentIndex(page)

        if page == _PAGE_FIREWALLS:
            self.titleLabel.setText('Select member firewalls')
            self.backButton.setEnabled(False)
            self._validate()  # Updates nextButton.
            self.finishButton.setEnabled(False)
        elif page == _PAGE_SUMMARY:
            self.titleLabel.setText('Review cluster configuration')
            self.backButton.setEnabled(True)
            self.nextButton.setEnabled(False)
            self.finishButton.setEnabled(True)
            self.finishButton.setDefault(True)
            self._populate_summary()

    def _on_back(self):
        """Navigate to the previous page."""
        current = self.stackedWidget.currentIndex()
        if current > _PAGE_FIREWALLS:
            self._show_page(current - 1)

    def _on_next(self):
        """Navigate to the next page."""
        current = self.stackedWidget.currentIndex()
        if current < _PAGE_SUMMARY:
            self._show_page(current + 1)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _populate_summary(self):
        """Fill in the summary page labels."""
        name = self.obj_name.text().strip()
        self.clusterName.setText(f'Name: {name}')

        selected_names = []
        master_name = ''
        master_data = {}
        master_row = self._master_group.checkedId()

        for row, (use_cb, _master_rb) in enumerate(self._row_widgets):
            if use_cb.isChecked():
                _fw_id, fw_name, fw_data = self._firewalls[row]
                selected_names.append(fw_name)
                if row == master_row:
                    master_name = fw_name
                    master_data = fw_data

        self.firewallsList.setText('\n'.join(sorted(selected_names)))
        self.masterLabel.setText(f'Master firewall: {master_name}')

        platform = master_data.get('platform', '')
        host_os = master_data.get('host_OS', '')
        host_os_display = HOST_OS.get(host_os, host_os)

        self.platformLabel.setText(f'Platform: {platform}')
        self.hostOSLabel.setText(f'Host OS: {host_os_display}')

    # ------------------------------------------------------------------
    # Result
    # ------------------------------------------------------------------

    def get_result(self):
        """Return ``(name, extra_data)`` for object creation.

        *extra_data* contains ``platform``, ``host_OS``, ``version``,
        ``member_fw_ids``, and ``master_fw_id`` derived from the
        selected master firewall (matching fwbuilder behaviour).
        """
        name = self.obj_name.text().strip()
        master_row = self._master_group.checkedId()

        member_ids = []
        master_id = None
        master_data = {}

        for row, (use_cb, _master_rb) in enumerate(self._row_widgets):
            if use_cb.isChecked():
                fw_id = self._firewalls[row][0]
                member_ids.append(fw_id)
                if row == master_row:
                    master_id = fw_id
                    master_data = self._firewalls[row][2]

        return name, {
            'host_OS': master_data.get('host_OS', ''),
            'master_fw_id': master_id,
            'member_fw_ids': sorted(member_ids),
            'platform': master_data.get('platform', ''),
            'version': master_data.get('version', ''),
        }


def _centered_layout(parent):
    """Create a centered QHBoxLayout with zero margins for cell widgets."""
    from PySide6.QtWidgets import QHBoxLayout

    layout = QHBoxLayout(parent)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.setContentsMargins(0, 0, 0, 0)
    return layout
