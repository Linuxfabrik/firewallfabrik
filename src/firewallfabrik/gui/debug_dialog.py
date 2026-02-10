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

import getpass
import os
import platform
import sys
from pathlib import Path

import PySide6
from PySide6.QtCore import QLibraryInfo, QLocale, qVersion
from PySide6.QtGui import QPixmapCache
from PySide6.QtWidgets import QDialog

from firewallfabrik import __version__
from firewallfabrik.gui.ui_loader import FWFUiLoader


class DebugDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)

        ui_path = Path(__file__).resolve().parent / 'ui' / 'debugdialog_q.ui'
        loader = FWFUiLoader(self)
        loader.load(str(ui_path))

        self.setWindowTitle('Debugging Info')

        self._populate()
        self.resize(700, 400)

        if parent is not None:
            parent_center = parent.geometry().center()
            self.move(
                parent_center.x() - self.width() // 2,
                parent_center.y() - self.height() // 2,
            )

    def _populate(self):
        t = self.debugText
        ui_dir = Path(__file__).resolve().parent / 'ui'

        t.append(f'Path to executable:\n  {sys.executable}')
        t.append('')
        t.append(f'Path to resources:\n  {ui_dir}')
        t.append('')
        t.append(f'Path to locale:\n  {QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)}')
        t.append('')

        try:
            user_name = getpass.getuser()
        except Exception:
            user_name = 'N/A'
        t.append(f'User name: {user_name}')
        t.append('')

        t.append(f'Current locale: {QLocale.system().name()}')
        t.append('')
        t.append('Versions:')
        t.append(f'  FirewallFabrik {__version__}')
        t.append(f'  Python {platform.python_version()}')
        t.append(f'  Built with PySide6 {PySide6.__version__}')
        t.append(f'  Using Qt {qVersion()}')
        t.append('')
        t.append('Platform:')
        t.append(f'  OS: {platform.platform()}')
        t.append(f'  Architecture: {platform.machine()}')
        t.append('')
        t.append(f'QPixmapCache limit: {QPixmapCache.cacheLimit()} kb')
