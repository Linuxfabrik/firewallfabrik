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

"""Editor panel dialog for TagService objects."""

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class TagServiceDialog(BaseObjectDialog):
    """Editor for TagService objects (name + tag code)."""

    def __init__(self, parent=None):
        super().__init__('tagservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.tagcode.setText(self._obj.tag_code or '')

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.tag_code = self.tagcode.text()
