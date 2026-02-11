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

"""Preprocessor base class.

Transforms the object graph before compilation.
Platform-specific subclasses add/modify interfaces, addresses, etc.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from firewallfabrik.compiler._base import BaseCompiler
from firewallfabrik.core.objects import Firewall

if TYPE_CHECKING:
    import sqlalchemy.orm


class Preprocessor(BaseCompiler):
    """Preprocessor transforms objects before compilation.

    Platform-specific subclasses add/modify interfaces, addresses, etc.
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

    def compile(self) -> None:
        """Run the preprocessor."""
        self.run()

    def run(self) -> None:
        """Override in subclasses to implement preprocessing."""
        pass
