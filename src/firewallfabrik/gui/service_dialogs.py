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
_TCP_FLAG_LABELS = (
    'flags_lbl_1',
    'flags_lbl_2',
    'flags_lbl_3',
    'flags_lbl_a',
    'flags_lbl_f',
    'flags_lbl_p',
    'flags_lbl_r',
    'flags_lbl_s',
    'flags_lbl_u',
)


class TCPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('tcpservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.ss.setValue(self._obj.src_range_start or 0)
        self.se.setValue(self._obj.src_range_end or 0)
        self.ds.setValue(self._obj.dst_range_start or 0)
        self.de.setValue(self._obj.dst_range_end or 0)
        self.established.setChecked(bool(self._obj.tcp_established))
        for flag in _TCP_FLAGS:
            mask_cb = getattr(self, f'{flag}_m', None)
            set_cb = getattr(self, f'{flag}_s', None)
            if mask_cb:
                mask_cb.setChecked(bool(getattr(self._obj, f'tcp_mask_{flag}', None)))
            if set_cb:
                set_cb.setChecked(bool(getattr(self._obj, f'tcp_flag_{flag}', None)))
        self.toggleEstablished()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        # Port range start must be <= end (fwbuilder bug #1695481).
        if self.ss.value() > self.se.value():
            self.se.setValue(self.ss.value())
        if self.ds.value() > self.de.value():
            self.de.setValue(self.ds.value())
        self._obj.src_range_start = self.ss.value()
        self._obj.src_range_end = self.se.value()
        self._obj.dst_range_start = self.ds.value()
        self._obj.dst_range_end = self.de.value()
        self._obj.tcp_established = self.established.isChecked()
        for flag in _TCP_FLAGS:
            mask_cb = getattr(self, f'{flag}_m', None)
            set_cb = getattr(self, f'{flag}_s', None)
            if mask_cb:
                setattr(self._obj, f'tcp_mask_{flag}', mask_cb.isChecked())
            if set_cb:
                setattr(self._obj, f'tcp_flag_{flag}', set_cb.isChecked())

    @Slot()
    def toggleEstablished(self):
        """Disable TCP flag controls when 'established' is checked."""
        using_est = self.established.isChecked()
        for flag in _TCP_FLAGS:
            for suffix in ('_m', '_s'):
                widget = getattr(self, f'{flag}{suffix}', None)
                if widget:
                    widget.setEnabled(not using_est)
        for lbl_name in _TCP_FLAG_LABELS:
            lbl = getattr(self, lbl_name, None)
            if lbl:
                lbl.setEnabled(not using_est)


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
        # Port range start must be <= end (fwbuilder bug #1695481).
        if self.ss.value() > self.se.value():
            self.se.setValue(self.ss.value())
        if self.ds.value() > self.de.value():
            self.de.setValue(self.ds.value())
        self._obj.src_range_start = self.ss.value()
        self._obj.src_range_end = self.se.value()
        self._obj.dst_range_start = self.ds.value()
        self._obj.dst_range_end = self.de.value()


class ICMPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('icmpservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.icmpType.setValue(
            self._obj.icmp_type if self._obj.icmp_type is not None else -1
        )
        self.icmpCode.setValue(
            self._obj.icmp_code if self._obj.icmp_code is not None else -1
        )

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.icmp_type = self.icmpType.value()
        self._obj.icmp_code = self.icmpCode.value()


_IP_OPTION_CHECKBOXES = ('lsrr', 'router_alert', 'rr', 'ssrr', 'timestamp')


class IPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('ipservicedialog_q.ui', parent)

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        self.protocolNum.setValue(self._obj.protocol_num or 0)
        dscp = self._obj.ip_dscp or ''
        if dscp:
            self.use_dscp.setChecked(True)
            self.code.setText(dscp)
        else:
            tos = self._obj.ip_tos or ''
            if tos:
                self.use_tos.setChecked(True)
                self.code.setText(tos)
        self.any_opt.setChecked(bool(self._obj.ip_opt_any_opt))
        self.lsrr.setChecked(bool(self._obj.ip_opt_lsrr))
        self.ssrr.setChecked(bool(self._obj.ip_opt_ssrr))
        self.rr.setChecked(bool(self._obj.ip_opt_rr))
        self.timestamp.setChecked(bool(self._obj.ip_opt_ts))
        self.router_alert.setChecked(bool(self._obj.ip_opt_rtralt))
        self.all_fragments.setChecked(bool(self._obj.ip_opt_fragm))
        self.short_fragments.setChecked(bool(self._obj.ip_opt_short_fragm))
        self.anyOptionsStateChanged()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.protocol_num = self.protocolNum.value()
        if self.use_dscp.isChecked():
            self._obj.ip_dscp = self.code.text()
            self._obj.ip_tos = None
        else:
            self._obj.ip_tos = self.code.text()
            self._obj.ip_dscp = None
        self._obj.ip_opt_any_opt = self.any_opt.isChecked()
        self._obj.ip_opt_lsrr = self.lsrr.isChecked()
        self._obj.ip_opt_ssrr = self.ssrr.isChecked()
        self._obj.ip_opt_rr = self.rr.isChecked()
        self._obj.ip_opt_ts = self.timestamp.isChecked()
        self._obj.ip_opt_rtralt = self.router_alert.isChecked()
        self._obj.ip_opt_fragm = self.all_fragments.isChecked()
        self._obj.ip_opt_short_fragm = self.short_fragments.isChecked()

    @Slot()
    def anyOptionsStateChanged(self):
        """Uncheck and disable individual IP options when 'any option' is checked."""
        any_checked = self.any_opt.isChecked()
        for cb_name in _IP_OPTION_CHECKBOXES:
            cb = getattr(self, cb_name, None)
            if cb:
                if any_checked:
                    cb.setChecked(False)
                cb.setEnabled(not any_checked)
