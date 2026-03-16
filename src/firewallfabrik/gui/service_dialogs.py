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


def _is_true(val):
    """Return True for bool True or string 'True'/'true'."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() == 'true'
    return bool(val)


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
        data = dict(self._obj.data or {})
        data['established'] = self.established.isChecked()
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
        codes = self._obj.codes or {}
        self.icmpType.setValue(int(codes.get('type', -1)))
        self.icmpCode.setValue(int(codes.get('code', -1)))

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.codes = {
            'type': self.icmpType.value(),
            'code': self.icmpCode.value(),
        }


_IP_OPTION_CHECKBOXES = ('lsrr', 'router_alert', 'rr', 'ssrr', 'timestamp')


class IPServiceDialog(BaseObjectDialog):
    def __init__(self, parent=None):
        super().__init__('ipservicedialog_q.ui', parent)
        self._update_code_field()

    def _set_read_only(self, read_only):
        super()._set_read_only(read_only)
        if not read_only:
            # Re-apply conditional enablement after the base class
            # blanket-enables all widgets.
            self._update_code_field()

    def _populate(self):
        self.obj_name.setText(self._obj.name or '')
        protocols = self._obj.named_protocols or {}
        self.protocolNum.setValue(int(protocols.get('protocol_num', 0)))
        data = self._obj.data or {}
        dscp = data.get('dscp')
        tos = data.get('tos')
        if dscp:
            self.use_dscp.setChecked(True)
            self.code.setText(dscp)
        elif tos:
            self.use_tos.setChecked(True)
            self.code.setText(tos)
        else:
            # Neither set — both radios unchecked, code field disabled
            self.use_dscp.setChecked(False)
            self.use_tos.setChecked(False)
        self._update_code_field()
        self.any_opt.setChecked(_is_true(data.get('any_opt')))
        self.lsrr.setChecked(_is_true(data.get('lsrr')))
        self.ssrr.setChecked(_is_true(data.get('ssrr')))
        self.rr.setChecked(_is_true(data.get('rr')))
        self.timestamp.setChecked(_is_true(data.get('ts')))
        self.router_alert.setChecked(_is_true(data.get('rtralt')))
        self.all_fragments.setChecked(_is_true(data.get('fragm')))
        self.short_fragments.setChecked(_is_true(data.get('short_fragm')))
        self.anyOptionsStateChanged()

    def _apply_changes(self):
        self._obj.name = self.obj_name.text()
        self._obj.named_protocols = {
            'protocol_num': str(self.protocolNum.value()),
        }
        data = dict(self._obj.data or {})
        if self.use_dscp.isChecked():
            data['dscp'] = self.code.text()
            data.pop('tos', None)
        elif self.use_tos.isChecked():
            data['tos'] = self.code.text()
            data.pop('dscp', None)
        else:
            # Neither selected — clear both
            data.pop('dscp', None)
            data.pop('tos', None)
        data['any_opt'] = self.any_opt.isChecked()
        data['lsrr'] = self.lsrr.isChecked()
        data['ssrr'] = self.ssrr.isChecked()
        data['rr'] = self.rr.isChecked()
        data['ts'] = self.timestamp.isChecked()
        data['rtralt'] = self.router_alert.isChecked()
        data['fragm'] = self.all_fragments.isChecked()
        data['short_fragm'] = self.short_fragments.isChecked()
        self._obj.data = data

    def _update_code_field(self):
        """Enable the code field only when a DiffServ radio is selected."""
        enabled = self.use_dscp.isChecked() or self.use_tos.isChecked()
        self.code.setEnabled(enabled)
        if not enabled:
            self.code.clear()

    @Slot()
    def diffServToggled(self):
        """Ensure mutual exclusivity and enable/disable the code field."""
        sender = self.sender()
        if sender and sender.isChecked():
            # Uncheck the other radio
            if sender is self.use_dscp:
                self.use_tos.setChecked(False)
            else:
                self.use_dscp.setChecked(False)
        self._update_code_field()

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
