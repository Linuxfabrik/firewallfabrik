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

# Build step: compile Qt resources via pyside6-rcc. All arguments are static,
# no user input is forwarded to the subprocess. pyside6-rcc is resolved from
# PATH at build time in the developer / CI environment only.
import subprocess  # nosec B404

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        # Static args only, pyside6-rcc found via PATH at build time.
        subprocess.run(  # nosec B603 B607
            [
                'pyside6-rcc',
                '--binary',
                'src/firewallfabrik/gui/ui/MainRes.qrc',
                '-o',
                'src/firewallfabrik/gui/ui/MainRes.rcc',
            ],
            check=True,
        )
        super().run()


setup(cmdclass={'build_py': BuildPy})
