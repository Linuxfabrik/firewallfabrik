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

"""The Time editor shows the weekdays and dates the compilers apply.

Older Firewall Builder files carry a first/last weekday pair instead of
the day list, and ``Interval::getDaysOfWeek`` falls back to it whenever
the list is empty.  The calendar window is stored as from_/to_ day, month
and year, -1 when unused (``TimeDialog::applyChanges``).
"""

import os

import pytest

# The GUI is an optional extra and the test runner installs the package
# without it, so this has to say so before the first Qt import rather than
# fail to collect.
pytest.importorskip('PySide6', reason='the GUI extra is not installed')

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

# The loader registers the dialog modules at import time, so it has to be
# imported first: reaching for the dialog module directly is a circular
# import through `device_dialogs`.
from PySide6.QtCore import QDate

import firewallfabrik.gui.ui_loader  # noqa: F401
from firewallfabrik.compiler._interval_helpers import (
    parse_interval_data,
    parse_interval_dates,
)
from firewallfabrik.core.objects import Interval
from firewallfabrik.gui.time_dialog import _DOW_CHECKBOXES, TimeDialog


@pytest.fixture(scope='module', autouse=True)
def _application():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _ticked(dlg):
    return {
        idx for idx, name in _DOW_CHECKBOXES.items() if getattr(dlg, name).isChecked()
    }


def test_a_weekday_pair_is_shown_and_kept():
    # Monday to Friday.
    interval = Interval(name='workdays', data={'from_weekday': 1, 'to_weekday': 5})
    dlg = TimeDialog()
    dlg.load_object(interval)
    assert _ticked(dlg) == {1, 2, 3, 4, 5}

    dlg.apply_all()
    assert 'from_weekday' not in interval.data
    assert parse_interval_data(interval.data)[4] == [1, 2, 3, 4, 5]


def test_the_day_list_wins_over_the_pair():
    interval = Interval(
        name='weekend',
        data={'days_of_week': '0,6', 'from_weekday': 1, 'to_weekday': 5},
    )
    dlg = TimeDialog()
    dlg.load_object(interval)
    assert _ticked(dlg) == {0, 6}


def test_a_stored_date_is_shown():
    interval = Interval(
        name='window',
        data={'from_day': 1, 'from_month': 10, 'from_year': 2026, 'to_day': -1},
    )
    dlg = TimeDialog()
    dlg.load_object(interval)
    assert dlg.useStartDate.isChecked()
    assert dlg.startDate.isEnabled()
    assert dlg.startDate.date().toString('yyyy-MM-dd') == '2026-10-01'
    assert not dlg.useEndDate.isChecked()
    assert not dlg.endDate.isEnabled()


def test_an_untouched_editor_keeps_the_stored_date_keys():
    data = {'from_day': '31', 'from_month': '2', 'from_year': '2026', 'to_day': '-1'}
    interval = Interval(name='window', data=dict(data))
    dlg = TimeDialog()
    dlg.load_object(interval)
    dlg.apply_all()
    for key, value in data.items():
        assert interval.data[key] == value


def test_setting_and_clearing_a_date():
    interval = Interval(name='window', data={})
    dlg = TimeDialog()
    dlg.load_object(interval)
    dlg.useEndDate.setChecked(True)
    assert dlg.endDate.isEnabled()
    dlg.endDate.setDate(QDate(2026, 12, 31))
    dlg.apply_all()
    assert parse_interval_dates(interval.data)[1][:3] == (2026, 12, 31)

    dlg.load_object(interval)
    dlg.useEndDate.setChecked(False)
    dlg.apply_all()
    assert parse_interval_dates(interval.data) == (None, None)
