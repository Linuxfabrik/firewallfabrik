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

"""Linux preprocessor.

``Preprocessor_ipt::convertObject`` has one job: hand every compile-time
MultiAddress object a rule names to ``loadFromSource``, with an
``AttachedNetworks`` branch in front of it.  Both halves live in
``Compiler._resolve_multi_address``, which the ``ResolveMultiAddress``
processor calls once per object and caches - the same place a DNS name
and an address table are resolved, and early enough for
``EmptyGroupsInRE`` to see what came back.

What is left here is the hook itself.  Both drivers construct it per
address family before the rule processors run, so a step that has to
happen before any rule is read has somewhere to go.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from firewallfabrik.compiler._preprocessor import Preprocessor
from firewallfabrik.core.objects import Firewall

if TYPE_CHECKING:
    import sqlalchemy.orm


class PreprocessorLinux(Preprocessor):
    """The Linux preprocessor hook.

    It carries no work of its own: what
    ``Preprocessor_ipt::convertObject`` does is done per object in
    ``Compiler._resolve_multi_address``.  An earlier version of this class
    walked the firewall's interfaces looking for an ``AttachedNetworks``
    among their *addresses*, where such an object never is - it is a
    group - and printed the networks it worked out without giving them to
    anybody.
    """

    def __init__(
        self,
        session: sqlalchemy.orm.Session,
        fw: Firewall,
        ipv6: bool = False,
    ) -> None:
        super().__init__(session, fw, ipv6)
