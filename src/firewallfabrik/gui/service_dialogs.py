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

"""Editor panel dialogs for service objects."""

from PySide6.QtCore import Slot

from firewallfabrik.gui.base_object_dialog import BaseObjectDialog

_TCP_FLAGS = ('urg', 'ack', 'psh', 'rst', 'syn', 'fin')


class TCPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('tcpservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.ss.setValue(self._obj.src_range_start or 0)
        self.se.setValue(self._obj.src_range_end or 0)
        self.ds.setValue(self._obj.dst_range_start or 0)
        self.de.setValue(self._obj.dst_range_end or 0)
        data = self._obj.data or {}
        self.established.setChecked(data.get('established') == 'True')
        flags = self._obj.tcp_flags or {}
        masks = self._obj.tcp_flags_masks or {}
        for flag in _TCP_FLAGS:
            mask_cb = getattr(self, f'{flag}_m', None)
            set_cb = getattr(self, f'{flag}_s', None)
            if mask_cb:
                mask_cb.setChecked(bool(masks.get(flag)))
            if set_cb:
                set_cb.setChecked(bool(flags.get(flag)))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.src_range_start = self.ss.value()
        self._obj.src_range_end = self.se.value()
        self._obj.dst_range_start = self.ds.value()
        self._obj.dst_range_end = self.de.value()
        data = dict(self._obj.data or {})
        data['established'] = str(self.established.isChecked())
        self._obj.data = data
        flags = {}
        masks = {}
        for flag in _TCP_FLAGS:
            mask_cb = getattr(self, f'{flag}_m', None)
            set_cb = getattr(self, f'{flag}_s', None)
            if mask_cb:
                masks[flag] = mask_cb.isChecked()
            if set_cb:
                flags[flag] = set_cb.isChecked()
        self._obj.tcp_flags = flags
        self._obj.tcp_flags_masks = masks

    @Slot()
    def toggleEstablished(self):
        # TODO
        pass


class UDPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('udpservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.ss.setValue(self._obj.src_range_start or 0)
        self.se.setValue(self._obj.src_range_end or 0)
        self.ds.setValue(self._obj.dst_range_start or 0)
        self.de.setValue(self._obj.dst_range_end or 0)

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.src_range_start = self.ss.value()
        self._obj.src_range_end = self.se.value()
        self._obj.dst_range_start = self.ds.value()
        self._obj.dst_range_end = self.de.value()


class ICMPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('icmpservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.icmpType.setValue(int(data.get('type', -1)))
        self.icmpCode.setValue(int(data.get('code', -1)))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = dict(self._obj.data or {})
        data['type'] = str(self.icmpType.value())
        data['code'] = str(self.icmpCode.value())
        self._obj.data = data


class IPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('ipservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        data = self._obj.data or {}
        self.protocolNum.setValue(int(data.get('protocol_num', 0)))
        dscp = data.get('dscp')
        if dscp:
            self.use_dscp.setChecked(True)
            self.code.setText(dscp)
        else:
            tos = data.get('tos')
            if tos:
                self.use_tos.setChecked(True)
                self.code.setText(tos)
        self.any_opt.setChecked(data.get('any_opt') == 'True')
        self.lsrr.setChecked(data.get('lsrr') == 'True')
        self.ssrr.setChecked(data.get('ssrr') == 'True')
        self.rr.setChecked(data.get('rr') == 'True')
        self.timestamp.setChecked(data.get('timestamp') == 'True')
        self.router_alert.setChecked(data.get('router_alert') == 'True')
        self.all_fragments.setChecked(data.get('fragm') == 'True')
        self.short_fragments.setChecked(data.get('short_fragm') == 'True')

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        data = dict(self._obj.data or {})
        data['protocol_num'] = str(self.protocolNum.value())
        if self.use_dscp.isChecked():
            data['dscp'] = self.code.text()
            data.pop('tos', None)
        else:
            data['tos'] = self.code.text()
            data.pop('dscp', None)
        data['any_opt'] = str(self.any_opt.isChecked())
        data['lsrr'] = str(self.lsrr.isChecked())
        data['ssrr'] = str(self.ssrr.isChecked())
        data['rr'] = str(self.rr.isChecked())
        data['timestamp'] = str(self.timestamp.isChecked())
        data['router_alert'] = str(self.router_alert.isChecked())
        data['fragm'] = str(self.all_fragments.isChecked())
        data['short_fragm'] = str(self.short_fragments.isChecked())
        self._obj.data = data

    @Slot()
    def anyOptionsStateChanged(self):
        # TODO
        pass
