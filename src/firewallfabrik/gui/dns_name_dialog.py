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

"""Editor panel dialog for DNSName objects."""

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class DNSNameDialog(BaseObjectDialog):
    """Editor for DNSName objects (name + DNS record + resolve mode)."""

    def __init__(self, parent=None):
        super().__init__('dnsnamedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.dnsrec.setText(data.get('source_name', ''))
        run_time = data.get('run_time', True)
        if run_time:
            self.r_runtime.setChecked(True)
        else:
            self.r_compiletime.setChecked(True)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = dict(self._obj.data or {})
        data['source_name'] = self.dnsrec.text().strip()
        data['run_time'] = self.r_runtime.isChecked()
        self._obj.data = data
