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

"""Editor panel dialog for AttachedNetworks objects."""

from firewallfabrik.core.objects import attached_network_mask
from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class AttachedNetworksDialog(BaseObjectDialog):
    """Editor for AttachedNetworks objects (name + the subnets it stands for).

    The list of subnets is not editable: it is what the compiler works out
    from the addresses of the parent interface on every run.  Showing it
    is the whole point of the panel, because otherwise nothing in the
    editor says what a rule naming this object matches - and it is the
    same answer, from ``AttachedNetworks.subnets``, that the compiler
    reads.
    """

    def __init__(self, parent=None):
        super().__init__('attachednetworksdialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.addresses.clear()
        for net in self._obj.subnets():
            self.addresses.addItem(
                f'{net.network_address}/{attached_network_mask(net)}'
            )

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
