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

"""The Time editor shows the weekdays the compilers apply.

Older Firewall Builder files carry a first/last weekday pair instead of
the day list, and ``Interval::getDaysOfWeek`` falls back to it whenever
the list is empty.
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
import firewallfabrik.gui.ui_loader  # noqa: F401
from firewallfabrik.compiler._interval_helpers import parse_interval_data
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
