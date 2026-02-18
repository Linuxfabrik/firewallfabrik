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

from PySide6.QtCore import QTime

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog

# Map day-of-week index (0=Sun, fwbuilder convention) to the checkbox
# objectName in timedialog_q.ui.
_DOW_CHECKBOXES = {
    0: 'cbStart7_2',  # Sun
    1: 'cbStart1_2',  # Mon
    2: 'cbStart2_2',  # Tue
    3: 'cbStart3_2',  # Wed
    4: 'cbStart4_2',  # Thu
    5: 'cbStart5_2',  # Fri
    6: 'cbStart6_2',  # Sat
}


class TimeDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('timedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}

        # Support both new format (from_time/to_time) and legacy format
        # (from_hour/from_minute/to_hour/to_minute) from .fwb imports.
        start_time = data.get('from_time', '')
        if not start_time:
            h = data.get('from_hour', '')
            m = data.get('from_minute', '')
            if h not in ('', '-1') and m not in ('', '-1'):
                start_time = f'{int(h):02d}:{int(m):02d}'

        end_time = data.get('to_time', '')
        if not end_time:
            h = data.get('to_hour', '')
            m = data.get('to_minute', '')
            if h not in ('', '-1') and m not in ('', '-1'):
                end_time = f'{int(h):02d}:{int(m):02d}'

        if start_time:
            self.startTime.setTime(QTime.fromString(start_time, 'HH:mm'))
        self.endTime.setTime(
            QTime.fromString(end_time, 'HH:mm') if end_time else QTime(23, 59)
        )

        days_str = data.get('days_of_week', '')
        active_days = set(days_str.split(',')) if days_str else set()
        for idx, cb_name in _DOW_CHECKBOXES.items():
            cb = getattr(self, cb_name, None)
            if cb:
                cb.setChecked(str(idx) in active_days)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = dict(self._obj.data or {})

        data['from_time'] = self.startTime.time().toString('HH:mm')
        data['to_time'] = self.endTime.time().toString('HH:mm')

        # Clean up legacy keys if present
        for key in (
            'from_date',
            'from_hour',
            'from_minute',
            'to_date',
            'to_hour',
            'to_minute',
        ):
            data.pop(key, None)

        active_days = []
        for idx, cb_name in _DOW_CHECKBOXES.items():
            cb = getattr(self, cb_name, None)
            if cb and cb.isChecked():
                active_days.append(str(idx))
        data['days_of_week'] = ','.join(active_days) if active_days else ''
        self._obj.data = data
