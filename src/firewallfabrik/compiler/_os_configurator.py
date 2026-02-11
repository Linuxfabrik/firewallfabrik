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

"""OSConfigurator base class.

Generates OS-specific configuration script sections:
interface configuration, kernel parameters, module loading, etc.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core.objects import Firewall

if TYPE_CHECKING:
    import sqlalchemy.orm


class OSConfigurator(BaseCompiler):
    """Generates OS-specific configuration script sections.

    Platform-specific subclasses produce interface configuration,
    kernel parameter settings, module loading, etc.
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6: bool = False,
    ) -> None:
        super().__init__()
        self.session: sqlalchemy.orm.Session = session
        self.fw: Firewall = fw
        self.ipv6: bool = ipv6
        self.output: io.StringIO = io.StringIO()

    def prolog(self) -> str:
        return ''

    def epilog(self) -> str:
        return ''

    def print_shell_functions(self) -> str:
        return ''

    def generate_interfaces(self) -> str:
        return ''

    def generate_virtual_addresses(self) -> str:
        return ''

    def print_path_for_all_tools(self, os_name: str) -> str:
        return ''
