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

"""Editor panel dialog for AddressTable objects."""

from PySide6.QtCore import QSettings

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class AddressTableDialog(BaseObjectDialog):
    """Editor for AddressTable objects (name + filename + resolve mode)."""

    def __init__(self, parent=None):
        super().__init__('addresstabledialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.filename.setText(data.get('source_name', ''))

        # Resolve mode: honour the preference for new objects (no
        # run_time key yet), otherwise use the stored value.
        if 'run_time' in data:
            run_time = data['run_time']
        else:
            settings = QSettings()
            use_compile = settings.value(
                'Objects/AddressTable/useCompileTimeForNewObjects', True, type=bool
            )
            run_time = not use_compile
        if run_time:
            self.r_runtime.setChecked(True)
        else:
            self.r_compiletime.setChecked(True)

    def _apply_changes(self):
        new_name = self.obj_name.text()
        if self._obj.name != new_name:
            self._obj.name = new_name
        old_data = self._obj.data or {}
        data = dict(old_data)
        data['source_name'] = self.filename.text().strip()
        data['run_time'] = self.r_runtime.isChecked()
        if data != old_data:
            self._obj.data = data
