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

"""Editor panel dialog for RuleSet objects (Policy, NAT, Routing)."""

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog


class RuleSetDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('rulesetdialog_q.ui', parent)

    def _populate(self):
        rs = self._obj
        self.obj_name.setText(rs.name or '')

        # ipv4_6_rule_set: 0=IPv4, 1=IPv6, 2=dual
        if rs.ipv4 and rs.ipv6:
            idx = 2
        elif rs.ipv6:
            idx = 1
        else:
            idx = 0
        self.ipv4_6_rule_set.setCurrentIndex(idx)

        self.top_rule_set.setChecked(rs.top)

        # Show/hide platform-specific widgets.
        device = rs.device
        platform = device.platform if device else ''
        rs_type = rs.type

        if platform == 'iptables' and rs_type == 'Policy':
            self.iptables_only.show()
            opts = rs.options or {}
            mangle_only = opts.get('mangle_only_rule_set', False)
            self.ipt_mangle_table.setChecked(bool(mangle_only))
            self.ipt_filter_table.setChecked(not bool(mangle_only))
        else:
            self.iptables_only.hide()

    def _apply_changes(self):
        rs = self._obj
        rs.name = self.obj_name.text()

        idx = self.ipv4_6_rule_set.currentIndex()
        if idx == 2:
            rs.ipv4 = True
            rs.ipv6 = True
        elif idx == 1:
            rs.ipv4 = False
            rs.ipv6 = True
        else:
            rs.ipv4 = True
            rs.ipv6 = False

        rs.top = self.top_rule_set.isChecked()

        device = rs.device
        platform = device.platform if device else ''
        if platform == 'iptables' and rs.type == 'Policy':
            opts = dict(rs.options or {})
            opts['mangle_only_rule_set'] = self.ipt_mangle_table.isChecked()
            rs.options = opts
