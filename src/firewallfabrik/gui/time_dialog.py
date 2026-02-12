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

"""Editor panel dialog for time/interval objects."""

from PySide6.QtCore import QDate, QTime

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog

# Map day-of-week index (0=Mon) to the checkbox objectName in timedialog_q.ui.
_DOW_CHECKBOXES = {
    0: 'cbStart1_2',
    1: 'cbStart2_2',
    2: 'cbStart3_2',
    3: 'cbStart4_2',
    4: 'cbStart5_2',
    5: 'cbStart6_2',
    6: 'cbStart7_2',
}


class TimeDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('timedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}

        start_date = data.get('from_date', '')
        start_time = data.get('from_time', '')
        end_date = data.get('to_date', '')
        end_time = data.get('to_time', '')

        self.useStartDate.setChecked(bool(start_date))
        if start_date:
            self.startDate.setDate(QDate.fromString(start_date, 'yyyy-MM-dd'))
        if start_time:
            self.startTime.setTime(QTime.fromString(start_time, 'HH:mm'))

        self.useEndDate.setChecked(bool(end_date))
        if end_date:
            self.endDate.setDate(QDate.fromString(end_date, 'yyyy-MM-dd'))
        if end_time:
            self.endTime.setTime(QTime.fromString(end_time, 'HH:mm'))

        days_str = data.get('days_of_week', '')
        active_days = set(days_str.split(',')) if days_str else set()
        for idx, cb_name in _DOW_CHECKBOXES.items():
            cb = getattr(self, cb_name, None)
            if cb:
                cb.setChecked(str(idx) in active_days)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = dict(self._obj.data or {})

        if self.useStartDate.isChecked():
            data['from_date'] = self.startDate.date().toString('yyyy-MM-dd')
            data['from_time'] = self.startTime.time().toString('HH:mm')
        else:
            data.pop('from_date', None)
            data.pop('from_time', None)

        if self.useEndDate.isChecked():
            data['to_date'] = self.endDate.date().toString('yyyy-MM-dd')
            data['to_time'] = self.endTime.time().toString('HH:mm')
        else:
            data.pop('to_date', None)
            data.pop('to_time', None)

        active_days = []
        for idx, cb_name in _DOW_CHECKBOXES.items():
            cb = getattr(self, cb_name, None)
            if cb and cb.isChecked():
                active_days.append(str(idx))
        data['days_of_week'] = ','.join(active_days) if active_days else ''
        self._obj.data = data
