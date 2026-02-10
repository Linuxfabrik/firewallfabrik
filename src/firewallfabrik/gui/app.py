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

import sys

from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator
from PySide6.QtWidgets import QApplication

from firewallfabrik import __version__
from firewallfabrik.gui.main_window import FWWindow


def main():
    print(f'FirewallFabrik {__version__}')

    app = QApplication(sys.argv)
    app.setOrganizationName('Linuxfabrik')
    app.setApplicationName('FirewallFabrik')

    # Load Qt's own translations for the current locale
    locale = QLocale.system().name()
    qt_translator = QTranslator()
    qt_translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if qt_translator.load(f'qt_{locale}', qt_translations_path):
        app.installTranslator(qt_translator)

    mw = FWWindow()
    mw.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
