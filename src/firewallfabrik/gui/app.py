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

"""Application entry point for the FirewallFabrik GUI."""

import argparse
import os
import pathlib
import signal
import sys

try:
    from PySide6.QtCore import QLibraryInfo, QLocale, QTimer, QTranslator
    from PySide6.QtWidgets import QApplication, QProxyStyle, QStyle, QStyleFactory
except ImportError:
    print(
        'Python module "PySide6" is not installed; this module is required to run FirewallFabrik in GUI mode.',
        file=sys.stderr,
    )
    sys.exit(1)

from firewallfabrik import __version__
from firewallfabrik.gui.main_window import FWWindow
from firewallfabrik.gui.window_registry import WindowRegistry


class _FWFStyle(QProxyStyle):
    """Proxy style wrapping Fusion with tweaked pixel metrics."""

    def __init__(self):
        super().__init__(QStyleFactory.create('Fusion'))

    def pixelMetric(self, metric, option=None, widget=None):
        if metric == QStyle.PixelMetric.PM_SmallIconSize:
            return 14
        return super().pixelMetric(metric, option, widget)


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

    # Prefer Wayland platform plugins when a Wayland session is available
    # and the user has not chosen a plugin explicitly.  The semicolon-
    # separated list makes Qt try each plugin in order, covering setups
    # where only a specific variant (e.g. wayland-egl) is installed.
    if 'QT_QPA_PLATFORM' not in os.environ and os.environ.get('WAYLAND_DISPLAY'):
        os.environ['QT_QPA_PLATFORM'] = 'wayland;wayland-egl;wayland-brcm'

    # Suppress harmless Wayland text-input warnings (Qt 6 / zwp_text_input_v3
    # emits noisy "Got leave event for surface 0x0" messages on focus changes).
    rules = os.environ.get('QT_LOGGING_RULES', '')
    if rules:
        rules += ';'
    os.environ['QT_LOGGING_RULES'] = rules + 'qt.qpa.wayland.textinput=false'

    # Use parse_known_args so Qt-specific flags (e.g. -platform) pass through.
    args, remaining = parser.parse_known_args()
    filename = args.file or args.file_positional

    # Set desktop file name before QApplication construction so the Wayland
    # platform plugin picks it up during init and doesn't try to register twice.
    QApplication.setDesktopFileName('ch.linuxfabrik.firewallfabrik')

    app = QApplication(remaining)
    app.setStyle(_FWFStyle())
    app.setOrganizationName('Linuxfabrik')
    app.setApplicationName('FirewallFabrik')

    # Load global stylesheet
    _style_path = pathlib.Path(__file__).resolve().parent / 'ui' / 'style.qss'
    if _style_path.is_file():
        app.setStyleSheet(_style_path.read_text())

    # Load Qt's own translations for the current locale
    locale = QLocale.system().name()
    qt_translator = QTranslator()
    qt_translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if qt_translator.load(f'qt_{locale}', qt_translations_path):
        app.installTranslator(qt_translator)

    # Allow clean shutdown on Ctrl+C from the terminal.  Qt's event loop
    # blocks Python's signal handling; a periodic no-op timer gives Python a
    # chance to run the handler between Qt events.
    signal.signal(signal.SIGINT, lambda *_args: app.quit())
    _sigint_timer = QTimer()
    _sigint_timer.start(200)
    _sigint_timer.timeout.connect(lambda: None)

    # Initialise the shared window registry before creating the first window.
    WindowRegistry.instance()

    mw = FWWindow()
    mw.show()

    if filename:
        mw._load_file(pathlib.Path(filename).resolve())

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
