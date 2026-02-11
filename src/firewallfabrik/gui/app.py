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

import argparse
import os
import pathlib
import sys

try:
    from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator
    from PySide6.QtWidgets import QApplication
except ImportError:
    print(
        'Python module "PySide6" is not installed; this module is required to run FirewallFabrik in GUI mode.',
        file=sys.stderr,
    )
    sys.exit(1)

from firewallfabrik import __version__
from firewallfabrik.gui.main_window import FWWindow


def main():
    parser = argparse.ArgumentParser(
        prog='fwf',
        description='FirewallFabrik — firewall configuration manager',
    )
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=f'FirewallFabrik {__version__}',
    )
    parser.add_argument(
        '-f',
        '--file',
        metavar='FILE',
        help='database file to load on startup',
    )
    parser.add_argument(
        'file_positional',
        nargs='?',
        metavar='FILE',
        help='database file to load on startup',
    )

    # Use parse_known_args so Qt-specific flags (e.g. -platform) pass through.
    args, remaining = parser.parse_known_args()
    filename = args.file or args.file_positional

    # Set desktop file name before QApplication construction so the Wayland
    # platform plugin picks it up during init and doesn't try to register twice.
    os.environ.setdefault('XDG_ACTIVATION_TOKEN', '')
    QApplication.setDesktopFileName('ch.linuxfabrik.firewallfabrik')

    app = QApplication(remaining)
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

    if filename:
        mw._load_file(pathlib.Path(filename).resolve())

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
